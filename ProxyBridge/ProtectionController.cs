namespace ProxyBridge;

internal sealed record ProtectionOperations(
    Func<uint> Count, Func<bool> Running, Action<Settings, ulong, bool> Configure,
    Func<Settings, ulong, bool, bool> Matches, Func<Task> Stop, Action Remove, Action Deactivate);

internal sealed record ProtectionOutcome(bool PolicyVerified, bool EngineStopped, bool Released, IReadOnlyList<Exception> Errors)
{
    public bool Succeeded => Errors.Count == 0 && EngineStopped && (PolicyVerified || Released);
}

// Owns user intent separately from observations. An absent or damaged policy must
// never be interpreted as permission to stop maintaining the requested protection.
internal sealed class ProtectionController(Settings settings, ProtectionOperations operations)
{
    public bool ConnectWanted { get; private set; }
    public bool ProtectionRequired { get; private set; }
    public ulong ActiveLuid { get; private set; }
    public bool SettingsUsable { get; private set; } = true;
    public bool EngineStopConfirmed { get; private set; } = true;
    public bool StoppedDnsAllowed { get; private set; }

    public void ObserveStartup(uint count, bool settingsUsable)
    {
        ProtectionRequired |= count != 0;
        SettingsUsable = settingsUsable;
    }
    public void UseSettings(Settings value)
    {
        value.Validate(); settings = value; SettingsUsable = true;
    }
    public void RequestConnect() { ConnectWanted = true; ProtectionRequired = true; }
    public void RequestBlock() { ConnectWanted = false; ProtectionRequired = true; }
    public void ConfigureActive(ulong luid)
    {
        if (!SettingsUsable) throw new InvalidOperationException("Сначала проверьте и сохраните настройки защиты.");
        operations.Configure(settings, luid, false);
        StoppedDnsAllowed = false;
        if (!operations.Matches(settings, luid, false)) throw new InvalidOperationException("Установленная политика защиты не соответствует ожидаемой.");
        ActiveLuid = luid;
        if (luid != 0) EngineStopConfirmed = false;
    }
    public bool IsExpectedPolicy() => SettingsUsable
        && StoppedDnsAllowed == (!ConnectWanted && ProtectionRequired && ActiveLuid == 0 && settings.ExcludedApplications.Length > 0)
        && operations.Matches(settings, ActiveLuid, StoppedDnsAllowed);
    public bool IsConnectedCandidate() => ConnectWanted && ProtectionRequired && ActiveLuid != 0 && operations.Running() && IsExpectedPolicy();

    static Exception Failure(string stage, Exception error) => new InvalidOperationException(stage + ": " + error.Message, error);
    public async Task<ProtectionOutcome> RearmAsync(Exception? cause = null)
    {
        ProtectionRequired = true;
        var errors = new List<Exception>();
        if (cause != null) errors.Add(cause);
        bool verified = false, stopped = false;
        try { operations.Deactivate(); }
        catch (Exception ex) { errors.Add(Failure("Снятие активных разрешений", ex)); }
        if (!SettingsUsable) errors.Add(new InvalidOperationException("Настройки защиты не подтверждены; автоматическая замена фильтров отменена."));
        else {
            try { operations.Configure(settings, 0, false); StoppedDnsAllowed = false; }
            catch (Exception ex) { errors.Add(Failure("Установка блокировки", ex)); }
        }
        // Stop must run even if Configure failed. Keep both failures and the
        // original connection error; a cleanup exception must not hide its cause.
        try { await operations.Stop(); stopped = true; }
        catch (Exception ex) { errors.Add(Failure("Остановка движка", ex)); }
        EngineStopConfirmed = stopped;
        bool allowStoppedDns = false;
        // A stopped-only DNS exception must never be installed before Stop has
        // succeeded, during connection preparation, or after a cleanup failure.
        if (stopped && errors.Count == (cause == null ? 0 : 1) && SettingsUsable && !ConnectWanted && settings.ExcludedApplications.Length > 0) {
            try { operations.Configure(settings, 0, true); allowStoppedDns = true; }
            catch (Exception ex) { errors.Add(Failure("Разрешение DNS для исключений после остановки", ex)); }
        }
        if (SettingsUsable) {
            try {
                verified = operations.Matches(settings, 0, allowStoppedDns);
                if (!verified) errors.Add(new InvalidOperationException("Полная политика блокировки не подтверждена."));
            } catch (Exception ex) { errors.Add(Failure("Проверка блокировки", ex)); }
        }
        if (verified) { ActiveLuid = 0; StoppedDnsAllowed = allowStoppedDns; }
        return new(verified, stopped, false, errors);
    }
    public async Task<ProtectionOutcome> ReleaseAsync()
    {
        ConnectWanted = false;
        var errors = new List<Exception>();
        bool stopped = false, deactivated = false;
        try { operations.Deactivate(); deactivated = true; }
        catch (Exception ex) { errors.Add(Failure("Снятие активных разрешений перед отключением", ex)); }
        try { await operations.Stop(); stopped = true; }
        catch (Exception ex) { errors.Add(Failure("Остановка перед снятием защиты", ex)); }
        EngineStopConfirmed = stopped;
        if (stopped && deactivated) {
            try {
                operations.Remove();
                if (operations.Count() != 0) throw new InvalidOperationException("Фильтры приложения остались после снятия защиты.");
                ProtectionRequired = false; ActiveLuid = 0; StoppedDnsAllowed = false;
                return new(false, true, true, errors);
            } catch (Exception ex) { errors.Add(Failure("Снятие защиты", ex)); }
        }
        if (ProtectionRequired) {
            var recovery = await RearmAsync();
            errors.AddRange(recovery.Errors);
            return new(recovery.PolicyVerified, recovery.EngineStopped, false, errors);
        }
        return new(false, stopped, false, errors);
    }
    public async Task<ProtectionOutcome> PrepareExitAsync()
    {
        ConnectWanted = false;
        Exception? observationError = null;
        try { ProtectionRequired |= operations.Count() != 0; }
        catch (Exception ex) {
            // An unknown policy is not evidence that it is safe to discard intent.
            ProtectionRequired = true; observationError = Failure("Проверка защиты перед выходом", ex);
        }
        if (ProtectionRequired) return await RearmAsync(observationError);
        var errors = new List<Exception>();
        bool stopped = false;
        try { operations.Deactivate(); }
        catch (Exception ex) { errors.Add(Failure("Снятие активных разрешений перед выходом", ex)); }
        try { await operations.Stop(); stopped = true; }
        catch (Exception ex) { errors.Add(Failure("Остановка перед выходом", ex)); }
        EngineStopConfirmed = stopped;
        return new(false, stopped, true, errors);
    }
}
