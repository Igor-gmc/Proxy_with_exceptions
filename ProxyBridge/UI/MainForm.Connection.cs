using System.Diagnostics;

namespace ProxyBridge;

internal sealed partial class MainForm
{
    CancellationTokenSource? speedCancellation;
    readonly Engine engine = new();
    readonly ProtectionController protection;
    DiagnosticContext? diagnosticContext;
    Exception? pendingConnectionFailure;

    void WireEngineEvents()
    {
        engine.ObservedLog += OnEngineLog;
        if (!observeOnly)
        {
            engine.Exited += OnEngineExited;
        }
    }

    void OnEngineLog(EngineLogObservation observation)
    {
        // Keep stdout draining independent of disk I/O and UI dispatch.
        AppLog.WriteAt(observation.EventTime, observation.MonoTicks, "sing-box: " + observation.Message);
        try
        {
            if (!IsDisposed && IsHandleCreated)
            {
                BeginInvoke(() =>
                {
                    if (!IsDisposed)
                    {
                        AppendAt(observation.EventTime, observation.MonoTicks, observation.Message, false);
                    }
                });
            }
        }
        catch (InvalidOperationException)
        {
            // The window may close between the check and BeginInvoke.
        }
    }

    void OnEngineExited(long generation)
    {
        AppLog.Write($"Движок завершился: поколение {generation}.");
        try
        {
            if (!IsDisposed && IsHandleCreated)
            {
                BeginInvoke(async () => await HandleEngineExit(generation));
            }
        }
        catch (InvalidOperationException)
        {
            // Disposal already owns fail-closed cleanup when dispatch is gone.
        }
    }

    async Task HandleEngineExit(long generation)
    {
        if (IsDisposed || generation != engine.Generation || engine.Running || !protection.ConnectWanted)
        {
            AppLog.Write($"ENGINE exit-notification ignored eventGeneration={generation} currentGeneration={engine.Generation}");
            return;
        }

        SetVisualState(ProxyVisualState.Failed);
        var errors = new List<Exception> { new IOException("Движок туннеля неожиданно завершился.") };
        try
        {
            Guard.Deactivate();
        }
        catch (Exception ex) { errors.Add(ex); }
        pendingConnectionFailure = new AggregateException("Аварийная остановка туннеля.", errors);
        speedCancellation?.Cancel();
        LogState("engine.exit-notification.active-permits-revoked");
        if (!busy)
        {
            await Execute(RecoverPendingConnectionFailure, "engine.exit-recovery");
        }
        else
        {
            AppLog.Write("ENGINE exit recovery queued until current operation completes");
        }
    }

    Task RecoverPendingConnectionFailure()
    {
        // A queued Release may have handled this failure and removed protection
        // before this callback reaches the front of the operation queue.
        var failure = pendingConnectionFailure;
        return failure != null && protection.ProtectionRequired
            ? RecoverConnection(failure)
            : Task.CompletedTask;
    }

    void CancelSpeedTest()
    {
        AppLog.Write($"ACTION ui.speed-cancel active={speedCancellation != null}");
        speedCancellation?.Cancel();
    }

    void LogState(string stage)
    {
        // Observations must not add policy checks or interfere with recovery.
        string running;
        try
        {
            running = engine.Running.ToString();
        }
        catch (Exception ex) { running = "unavailable:" + ex.GetType().Name; }
        AppLog.Write($"STATE {stage} visual={VisualState} busy={busy} exiting={exiting} observeOnly={observeOnly} " +
            $"connectWanted={protection.ConnectWanted} protectionRequired={protection.ProtectionRequired} " +
            $"activeLuid={protection.ActiveLuid} stoppedDnsAllowed={protection.StoppedDnsAllowed} settingsUsable={protection.SettingsUsable} " +
            $"engineRunning={running} generation={engine.Generation} engineStopConfirmed={protection.EngineStopConfirmed} forcedStop={engine.LastStopForced}");
    }
    void LogOutcome(string stage, ProtectionOutcome outcome, Stopwatch elapsed)
    {
        CacheDiagnosticContext(stage, outcome.PolicyVerified);
        AppLog.Write($"OUTCOME {stage} elapsedMs={elapsed.ElapsedMilliseconds} succeeded={outcome.Succeeded} " +
            $"policyVerified={outcome.PolicyVerified} engineStopped={outcome.EngineStopped} released={outcome.Released} errors={outcome.Errors.Count}");
        LogState(stage);
    }
    void CacheDiagnosticContext(string stage, bool? policyVerified)
    {
        if (observeOnly)
        {
            return;
        }

        try
        {
            // Caller passes an already computed policy result. This method
            // deliberately performs no Guard checks or network snapshots.
            diagnosticContext = new(settings.Host, settings.Port, settings.Protocol, engine.ProcessId, engine.Generation,
                protection.ActiveLuid, protection.ProtectionRequired, protection.ConnectWanted,
                policyVerified, DateTimeOffset.Now, stage, engine.ProcessStartedUtc);
            DiagnosticJournal.UpdateContext(diagnosticContext);
        }
        catch { }
    }
    void ObserveProbe(ProbeObservation observation)
    {
        if (observeOnly)
        {
            return;
        }

        try
        {
            DiagnosticJournal.Record("probe.phase", observation, observation.EventTime, observation.MonoTicks);
            if (observation.Outcome is ProbeOutcome.Failed or ProbeOutcome.TimedOut)
            {
                DiagnosticJournal.Trigger("probe-first-error", observation);
            }
        }
        catch { }
    }
    void ShowRecovery(ProtectionOutcome outcome, string context, bool manual)
    {
        bool blocked = outcome.PolicyVerified && outcome.EngineStopped;
        int exclusionCount = settings.ExcludedApplications.Length + settings.ExcludedAddresses.Length;
        string blockedDetails = exclusionCount == 0
            ? " · блокировка подтверждена, исключений нет"
            : $" · блокировка подтверждена · исключений: {exclusionCount}";
        if (blocked && settings.ExcludedApplications.Length > 0)
        {
            blockedDetails += protection.StoppedDnsAllowed
                ? " · службе DNS разрешены запросы к настроенным DNS-серверам"
                : " · прямой системный DNS не разрешён";
        }

        SetStatus(context + (blocked
            ? blockedDetails
            : " · защита не подтверждена; требуется повторная проверка"),
            manual && outcome.Succeeded ? ProxyVisualState.Paused : ProxyVisualState.Failed);
        foreach (var error in outcome.Errors)
        {
            AppLog.Error(context, error);
            Append(error.Message, false);
        }
    }
    async Task RecoverConnection(Exception? cause)
    {
        if (!observeOnly)
        {
            try
            {
                // Freeze the existing ring and last verified context before
                // fail-closed begins. No probe/native enumeration/disk wait.
                DiagnosticJournal.Trigger("recovery-requested", new
                {
                    CachedContext = diagnosticContext,
                    CauseCodes = cause == null ? null : AppLog.ExceptionCodes(cause)
                });
            }
            catch { }
        }
        PromoteMonitorMutation();
        using var operation = AppLog.BeginOperation("connection.recovery");
        var elapsed = Stopwatch.StartNew();
        SetVisualState(ProxyVisualState.Failed);
        if (pendingConnectionFailure != null && !ReferenceEquals(pendingConnectionFailure, cause))
        {
            cause = cause == null ? pendingConnectionFailure : new AggregateException(cause, pendingConnectionFailure);
        }

        pendingConnectionFailure = null;
        var outcome = await protection.RearmAsync(cause);
        LogOutcome("recovery.complete", outcome, elapsed);
        AppLog.Write("RECOVERY causeType=" + (cause?.GetType().Name ?? "none"));
        AppLog.Snapshot("recovery.complete", settings);
        ShowRecovery(outcome, protection.ConnectWanted ? "Сбой подключения · повтор через 8 с" : "Ошибка защиты", false);
    }
    async Task MonitorProtection(CancellationToken cancellationToken)
    {
        try
        {
            if (!protection.ConnectWanted)
            {
                if (!protection.IsExpectedPolicy() || protection.ActiveLuid != 0 || engine.Running || !protection.EngineStopConfirmed)
                {
                    await RecoverConnection(new IOException("Ожидаемая блокировка нарушена."));
                }
                return;
            }
            if (!protection.IsConnectedCandidate())
            {
                if (!protection.IsExpectedPolicy() || protection.ActiveLuid != 0 || engine.Running || !protection.EngineStopConfirmed)
                {
                    await RecoverConnection(new IOException("Туннель или ожидаемая политика защиты утрачены."));
                    return;
                }
                using var operation = AppLog.BeginOperation("monitor.retry");
                LogState("monitor.retry");
                await StartProtected();
                return;
            }
            await Probe(cancellationToken, quietSuccess: true);
            cancellationToken.ThrowIfCancellationRequested();
            if (!protection.IsConnectedCandidate())
            {
                throw new IOException("Защита изменилась во время проверки подключения.");
            }

            CacheDiagnosticContext("monitor.policy-verified", true);
            if (VisualState != ProxyVisualState.Connected)
            {
                SetStatus("Подключено · KillSwitch активен · DNS через прокси", ProxyVisualState.Connected);
            }
        }
        catch (OperationCanceledException ex) when (cancellationToken.IsCancellationRequested && ex.CancellationToken == cancellationToken)
        {
            throw;
        }
        catch (Exception ex) { await RecoverConnection(ex); }
    }
    async Task TestSpeed()
    {
        Exception? connectionFailure = null;
        bool ConnectionVerified()
        {
            try
            {
                bool verified = protection.IsConnectedCandidate();
                if (!verified && protection.ConnectWanted)
                {
                    connectionFailure ??= new IOException("Туннель или политика защиты не подтверждены.");
                    SetVisualState(ProxyVisualState.Failed);
                }
                return verified;
            }
            catch (Exception ex)
            {
                connectionFailure = ex;
                if (protection.ConnectWanted)
                {
                    SetVisualState(ProxyVisualState.Failed);
                }

                throw;
            }
        }
        try
        {
            if (!ConnectionVerified())
            {
                if (protection.ConnectWanted)
                {
                    await RecoverConnection(connectionFailure);
                }
                else
                {
                    Append("Сначала подключитесь к прокси, затем запустите тест скорости.");
                }

                return;
            }
        }
        catch (Exception ex)
        {
            if (protection.ProtectionRequired)
            {
                await RecoverConnection(ex);
                return;
            }
            throw;
        }
        using var cancellation = new CancellationTokenSource();
        using var watchdog = new System.Windows.Forms.Timer { Interval = 1000 };
        watchdog.Tick += (_, _) =>
        {
            try
            {
                if (ConnectionVerified())
                {
                    return;
                }
            }
            catch (Exception ex) { connectionFailure = new IOException("Ошибка проверки защиты во время теста.", ex); }
            connectionFailure ??= new IOException("Туннель или защита изменились во время теста; результат недействителен.");
            cancellation.Cancel();
        };
        speedCancellation = cancellation;
        cancelSpeed.Enabled = true;
        watchdog.Start();
        try
        {
            Append("Тест скорости: проверка подключения через туннель…");
            try
            {
                await Probe(cancellation.Token);
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { throw; }
            catch (Exception ex) { connectionFailure = ex; SetVisualState(ProxyVisualState.Failed); throw; }
            var result = await ProxySpeedTest.RunAsync(new Progress<string>(Append), cancellation.Token);
            if (connectionFailure != null || !ConnectionVerified())
            {
                connectionFailure ??= new IOException("Туннель или защита изменились во время теста; результат недействителен.");
                throw connectionFailure;
            }
            Append($"Загрузка: {result.DownloadMbps:F2} Мбит/с; задержка HTTPS: {result.LatencyMs:F0} мс; получено {result.BytesReceived / 1048576.0:F1} МиБ за {result.Duration.TotalSeconds:F1} с. Сервер: {result.Endpoint}");
            Append("Результат зависит от тестового сервера, прокси и вашего подключения.");
        }
        catch (OperationCanceledException) when (connectionFailure != null || pendingConnectionFailure != null)
        {
            Append("Тест скорости прерван из-за сбоя подключения.");
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            Append("Тест скорости отменён.");
        }
        finally
        {
            watchdog.Stop();
            speedCancellation = null;
            if (!IsDisposed)
            {
                cancelSpeed.Enabled = false;
            }

            if (!IsDisposed && (connectionFailure != null || pendingConnectionFailure != null))
            {
                await RecoverConnection(connectionFailure);
            }
        }
    }
    async Task Connect()
    {
        LogState("connect.request");
        var next = ReadSettings();
        next.Validate();
        next.Save();
        settings = next;
        ActivitySettingsSaved();
        protection.UseSettings(settings);
        protection.RequestConnect();
        AppLog.Write($"CONNECT settings accepted protocol={settings.Protocol} exclusions={settings.ExcludedApplications.Length} addressExclusions={settings.ExcludedAddresses.Length}");
        await StartProtected();
    }
    async Task StartProtected()
    {
        PromoteMonitorMutation();
        var elapsed = Stopwatch.StartNew();
        string stage = "prepare";
        bool connected = false;
        if (VisualState != ProxyVisualState.Failed)
        {
            SetVisualState(ProxyVisualState.Connecting);
        }

        try
        {
            if (!await PrepareConnection(elapsed))
            {
                return;
            }
            // Capture only after the requested fail-closed preparation has run.
            AppLog.Snapshot("connect.start-after-prepare", settings);
            SetStatus("Политика блокировки подтверждена · запуск туннеля…");
            Append("Проверка конфигурации прокси…");
            stage = "configuration-check";
            AppLog.Write($"CONNECT stage={stage} elapsedMs={elapsed.ElapsedMilliseconds}");
            await engine.Check(settings);
            stage = "engine-start";
            AppLog.Write($"CONNECT stage={stage} elapsedMs={elapsed.ElapsedMilliseconds}");
            Append("Запуск сетевого движка и TUN…");
            engine.Start();
            stage = "tun-wait";
            ulong luid = await WaitForTun(elapsed);
            stage = "active-policy";
            ActivateTunnelPolicy(luid);
            stage = "https-probe";
            AppLog.Write($"CONNECT stage={stage} elapsedMs={elapsed.ElapsedMilliseconds}");
            await Probe();
            if (!protection.IsConnectedCandidate())
            {
                throw new IOException("Туннель или политика защиты изменились при подключении.");
            }

            CacheDiagnosticContext("connect.connected", true);
            SetStatus("Подключено · KillSwitch активен · DNS через прокси", ProxyVisualState.Connected);
            connected = true;
            stage = "connected";
            LogState("connect.connected");
            AppLog.Snapshot("connect.connected", settings);
        }
        catch (Exception ex)
        {
            long failedAtMs = elapsed.ElapsedMilliseconds;
            await RecoverConnection(ex);
            AppLog.Write($"CONNECT failedStage={stage} failedAtMs={failedAtMs} errorType={ex.GetType().Name}; recovery completed");
        }
        finally
        {
            AppLog.Write($"CONNECT attempt-end stage={stage} connected={connected} elapsedMs={elapsed.ElapsedMilliseconds} generation={engine.Generation}");
        }
    }
    async Task<bool> PrepareConnection(Stopwatch elapsed)
    {
        var pending = pendingConnectionFailure;
        pendingConnectionFailure = null;
        var preparation = await protection.RearmAsync(pending);
        LogOutcome("connect.prepare", preparation, elapsed);
        if (pendingConnectionFailure != null)
        {
            await RecoverConnection(preparation.Errors.Count == 0 ? null : new AggregateException(preparation.Errors));
            return false;
        }
        if (!preparation.Succeeded)
        {
            ShowRecovery(preparation, "Подготовка подключения не завершена", false);
            AppLog.Snapshot("connect.prepare-failed", settings);
            return false;
        }
        return true;
    }

    async Task<ulong> WaitForTun(Stopwatch elapsed)
    {
        var tunWait = Stopwatch.StartNew();
        ulong luid = 0;
        for (int attempt = 0; attempt < 60 && engine.Running; attempt++)
        {
            await Task.Delay(250);
            luid = Guard.TunLuid();
            if (luid != 0)
            {
                break;
            }
        }
        AppLog.Write($"CONNECT stage=tun-wait elapsedMs={elapsed.ElapsedMilliseconds} waitMs={tunWait.ElapsedMilliseconds} discoveredLuid={luid} generation={engine.Generation}");
        if (luid == 0 || !engine.Running)
        {
            throw new InvalidOperationException("TUN не запустился. Проверьте журнал и правила Касперского.");
        }

        return luid;
    }

    void ActivateTunnelPolicy(ulong luid)
    {
        protection.ConfigureActive(luid);
        CacheDiagnosticContext("connect.active-policy-verified", true);
        LogState("connect.active-policy-verified");
        AppLog.Snapshot("connect.tun-active-policy", settings);
        Append("Туннель готов. Проверка HTTPS через прокси…");
    }

    async Task Probe(CancellationToken cancellationToken = default, bool quietSuccess = false)
    {
        var context = new ProbeContext(engine.Generation);
        if (!quietSuccess)
        {
            await ConnectionProbe.CheckObservedAsync(context, ObserveProbe, cancellationToken, message => Append(message));
            return;
        }
        var messages = new List<(DateTimeOffset EventTime, long MonoTicks, string Message)>(8);
        bool completed = false;
        try
        {
            await ConnectionProbe.CheckObservedAsync(context, ObserveProbe, cancellationToken, message =>
            {
                if (messages.Count < 8)
                {
                    messages.Add((DateTimeOffset.Now, Stopwatch.GetTimestamp(), message));
                }
            });
            completed = true;
        }
        finally
        {
            // Only the first-endpoint healthy result is quiet. Preserve every
            // failed attempt when a later endpoint succeeds, and all failures.
            if (!completed || messages.Count > 2)
            {
                foreach (var message in messages)
                {
                    try
                    {
                        AppendAt(message.EventTime, message.MonoTicks, message.Message, true);
                    }
                    catch { /* Diagnostics must not alter the probe outcome. */ }
                }
            }
        }
    }
    async Task Block()
    {
        var elapsed = Stopwatch.StartNew();
        protection.RequestBlock();
        var outcome = await protection.RearmAsync();
        LogOutcome("block.complete", outcome, elapsed);
        AppLog.Snapshot("block.complete", settings);
        ShowRecovery(outcome, "Остановка прокси", true);
    }
    async Task Release() => await ReleaseProtection();
    async Task<bool> ReleaseProtection()
    {
        var elapsed = Stopwatch.StartNew();
        var outcome = await protection.ReleaseAsync();
        LogOutcome("release.complete", outcome, elapsed);
        AppLog.Snapshot("release.complete", settings);
        if (outcome.Succeeded)
        {
            pendingConnectionFailure = null;
            SetStatus(engine.LastStopForced
                ? "Прокси остановлен · блокировка снята · сетевое восстановление не подтверждено"
                : "Прокси остановлен · блокировка снята", ProxyVisualState.Paused);
            return true;
        }
        ShowRecovery(outcome, "Не удалось завершить снятие защиты", false);
        return false;
    }
}
