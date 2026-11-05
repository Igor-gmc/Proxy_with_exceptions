using System.Diagnostics;

namespace ProxyBridge;
internal sealed partial class MainForm : Form
{
    readonly TextBox host = new(), port = new(), username = new(), password = new() { UseSystemPasswordChar = true };
    readonly ComboBox protocol = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    readonly Label status = new() { AutoSize = true, ForeColor = Color.SteelBlue, Text = "Готово к подключению" };
    readonly TextBox log = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill };
    readonly TextBox userLogNote = new() { Multiline = true, AcceptsReturn = true, ScrollBars = ScrollBars.Vertical, WordWrap = true };
    readonly Button writeLogNote = new ThemeButton() { Text = "Записать в лог" };
    readonly CheckBox activityLogging = new() { AutoSize = true };
    readonly Button openActivityLog = new ThemeButton() { Text = "Открыть журнал" };
    readonly Label activityStatus = new() { AutoSize = false, AutoEllipsis = true };
    readonly ActivityMonitor activityMonitor = new();
    readonly SemaphoreSlim activityGate = new(1, 1);
    bool changingActivityCheck, activitySettingsUsable;
    int pendingActivityChanges;
    string? activityOperationError, displayedActivityError;
    readonly Button connect = new ThemeButton() { Text = "Подключить", AutoSize = true };
    readonly Button apply = new ThemeButton() { Text = "Сохранить / применить", AutoSize = true };
    readonly Button block = new ThemeButton() { Text = "Остановить и блокировать", AutoSize = true };
    readonly Button release = new ThemeButton() { Text = "Отключить и вернуть интернет", AutoSize = true };
    readonly ListBox exclusions = new() { Dock = DockStyle.Fill, HorizontalScrollbar = true };
    readonly Button addExclusion = new ThemeButton() { Text = "Добавить EXE…", AutoSize = true };
    readonly Button removeExclusion = new ThemeButton() { Text = "Удалить", AutoSize = true };
    readonly CheckBox autoStart = new() { Text = "Запускать при входе в Windows", AutoSize = true };
    readonly Button speed = new ThemeButton() { Text = "Тест скорости", AutoSize = true };
    readonly Button cancelSpeed = new ThemeButton() { Text = "Отменить тест", AutoSize = true, Enabled = false };
    CancellationTokenSource? speedCancellation;
    bool changingAutoStart;
    readonly StatusIcons statusIcons = new();
    readonly NotifyIcon tray;
    readonly Engine engine = new();
    readonly ProtectionController protection;
    readonly bool observeOnly;
    readonly System.Windows.Forms.Timer monitor = new() { Interval = 8000 };
    readonly SemaphoreSlim operationGate = new(1, 1);
    CancellationTokenSource? monitorCancellation;
    int pendingCommands;
    bool monitorReadOnly, controlsDisabled;
    Settings settings;
    bool busy, exiting, resourcesDisposed;
    string? displayedLogError;
    bool writingUserNote;
    DiagnosticContext? diagnosticContext;
    Exception? pendingConnectionFailure;
    internal ProxyVisualState VisualState { get; private set; } = ProxyVisualState.Paused;
    public MainForm(bool autoConnect = true, bool startup = false, bool observeOnly = false)
    {
        this.observeOnly = observeOnly;
        Text = $"ProxyBridge {AppVersion.Display} — защищённое подключение"; Size = new(790, 680); MinimumSize = new(750, 640);
        StartPosition = FormStartPosition.CenterScreen; Font = new("Segoe UI", 10); Icon = statusIcons.ForState(VisualState);
        string? loadError = null;
        Exception? loadException = null;
        try { settings = Settings.Load(); }
        catch (Exception ex) {
            settings = Settings.Default;
            autoConnect = false;
            loadException = ex;
            loadError = "Не удалось загрузить настройки. Проверьте поля и сохраните их заново. Автоподключение отменено. " + ex.Message;
        }
        bool initialSetupNeeded = loadError == null && string.IsNullOrWhiteSpace(settings.Host);
        bool settingsReady = loadError == null && !initialSetupNeeded;
        if (initialSetupNeeded) autoConnect = false;
        AppLog.RegisterSecret(settings.Password);
        if (loadException != null) AppLog.Error("Загрузка настроек", loadException);
        protection = new(settings, new ProtectionOperations(() => Guard.Status, () => engine.Running,
            (s, luid, dns) => Guard.Configure(s, luid, allowStoppedDns: dns),
            (s, luid, dns) => Guard.IsConfigured(s, luid, allowStoppedDns: dns), engine.Stop, Guard.Remove, Guard.Deactivate));
        protection.ObserveStartup(0, settingsReady);
        host.Text = settings.Host; port.Text = settings.Port.ToString(); username.Text = settings.Username; password.Text = settings.Password;
        protocol.Items.AddRange(["HTTP CONNECT", "SOCKS5 (TCP)"]); protocol.SelectedIndex = settings.Protocol == "http" ? 0 : 1;
        exclusions.Items.AddRange(settings.ExcludedApplications);
        activitySettingsUsable = settingsReady;
        activityLogging.Checked = settings.ActivityLoggingEnabled;
        BuildLayout(startup);
        activityLogging.CheckedChanged += async (_, _) => {
            if (changingActivityCheck || OperationsClosed || observeOnly) return;
            await ChangeActivityLoggingAsync(activityLogging.Checked, savePreference: true);
        };
        openActivityLog.Click += (_, _) => OpenActivityLog();
        activityMonitor.StateChanged += ActivityStateChanged;
        RefreshActivityStatus();
        addExclusion.Click += (_, _) => {
            using var operation = AppLog.BeginOperation("ui.exclusion.add");
            using var dialog = new OpenFileDialog { Filter = "Приложения (*.exe)|*.exe", CheckFileExists = true, Multiselect = true, Title = "Приложения с прямым доступом" };
            if (dialog.ShowDialog(this) != DialogResult.OK) { AppLog.Write("ACTION exclusion.add cancelled"); return; }
            try {
                var paths = Settings.NormalizeExcludedApplications(exclusions.Items.Cast<string>().Concat(dialog.FileNames));
                exclusions.Items.Clear(); exclusions.Items.AddRange(paths); RefreshOverviewSummary();
                AppLog.Write($"ACTION exclusion.add pendingCount={exclusions.Items.Count}");
            } catch (Exception ex) { Append(ex.Message); }
        };
        removeExclusion.Click += (_, _) => {
            using var operation = AppLog.BeginOperation("ui.exclusion.remove");
            if (exclusions.SelectedIndex >= 0) exclusions.Items.RemoveAt(exclusions.SelectedIndex);
            RefreshOverviewSummary();
            AppLog.Write($"ACTION exclusion.remove pendingCount={exclusions.Items.Count}");
        };
        try { autoStart.Checked = StartupRegistration.IsEnabled; }
        catch (Exception ex) { Append("Не удалось проверить автозапуск: " + ex.Message); }
        autoStart.CheckedChanged += async (_, _) => {
            if (changingAutoStart) return;
            bool requested = autoStart.Checked;
            await Execute(async () => {
                try {
                    await StartupRegistration.SetEnabledAsync(requested);
                    Append(requested ? "Автозапуск включён. При входе в Windows откроется журнал проверки." : "Автозапуск отключён.");
                } finally {
                    changingAutoStart = true;
                    try { autoStart.Checked = StartupRegistration.IsEnabled; }
                    finally { changingAutoStart = false; }
                }
            }, requested ? "ui.startup.enable" : "ui.startup.disable");
        };
        var menu = new ContextMenuStrip();
        menu.Items.Add("Открыть", null, (_, _) => { AppLog.Write("ACTION tray.open"); ShowWindow(); });
        menu.Items.Add("Подключить", null, async (_, _) => await Execute(Connect, "tray.connect"));
        menu.Items.Add("Остановить и блокировать", null, async (_, _) => await Execute(Block, "tray.block"));
        menu.Items.Add("Отключить и вернуть интернет", null, async (_, _) => await Execute(Release, "tray.release"));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Выход и восстановить интернет", null, async (_, _) => await Execute(async () => {
            Append("Команда пользователя: выход и восстановление интернета.");
            if (await ReleaseProtection()) {
                AppLog.Snapshot("exit.release-complete", settings);
                LogState("exit.release-complete");
                exiting = true; Close();
            }
        }, "tray.exit-release"));
        var preserveExit = menu.Items.Add("Выход (сохранить KillSwitch)", null, async (_, _) => await Execute(async () => {
            Append("Команда пользователя: выход с сохранением KillSwitch.");
            var elapsed = Stopwatch.StartNew();
            var result = await protection.PrepareExitAsync();
            LogOutcome("exit.preserve", result, elapsed);
            AppLog.Snapshot("exit.preserve-complete", settings);
            if (!result.Succeeded) { ShowRecovery(result, "Выход отменён", false); return; }
            SetVisualState(ProxyVisualState.Paused); exiting = true; Close();
        }, "exit.preserve"));
        exitApplication.Click += (_, _) => { AppLog.Write("ACTION ui.exit-preserve"); preserveExit.PerformClick(); };
        tray = new NotifyIcon { Icon = statusIcons.ForState(VisualState), Text = StatusIcons.Tooltip(VisualState), Visible = true, ContextMenuStrip = menu };
        tray.DoubleClick += (_, _) => { AppLog.Write("ACTION tray.double-click"); ShowWindow(); };
        connect.Click += async (_, _) => await Execute(Connect, "ui.connect");
        apply.Click += async (_, _) => await Execute(ApplySettings, "ui.apply-settings");
        block.Click += async (_, _) => await Execute(Block, "ui.block");
        release.Click += async (_, _) => await Execute(Release, "ui.release");
        speed.Click += async (_, _) => await Execute(TestSpeed, "ui.speed-test");
        writeLogNote.Click += async (_, _) => await WriteUserNoteAsync();
        cancelSpeed.Click += (_, _) => { AppLog.Write($"ACTION ui.speed-cancel active={speedCancellation != null}"); speedCancellation?.Cancel(); };
        engine.ObservedLog += observation => {
            // The bounded logger accepts an immutable original timestamp;
            // neither disk I/O nor the UI can block stdout draining here.
            AppLog.WriteAt(observation.EventTime, observation.MonoTicks, "sing-box: " + observation.Message);
            try { if (!IsDisposed && IsHandleCreated) BeginInvoke(() => {
                if (!IsDisposed) AppendAt(observation.EventTime, observation.MonoTicks, observation.Message, false);
            }); }
            catch (InvalidOperationException) { /* The window can close between the check and BeginInvoke. */ }
        };
        if (!observeOnly) engine.Exited += generation => {
            AppLog.Write($"Движок завершился: поколение {generation}.");
            try {
                if (!IsDisposed && IsHandleCreated) BeginInvoke(async () => {
                    if (IsDisposed || generation != engine.Generation || engine.Running || !protection.ConnectWanted) {
                        AppLog.Write($"ENGINE exit-notification ignored eventGeneration={generation} currentGeneration={engine.Generation}");
                        return;
                    }
                    SetVisualState(ProxyVisualState.Failed);
                    var errors = new List<Exception> { new IOException("Движок туннеля неожиданно завершился.") };
                    try { Guard.Deactivate(); } catch (Exception ex) { errors.Add(ex); }
                    pendingConnectionFailure = new AggregateException("Аварийная остановка туннеля.", errors);
                    speedCancellation?.Cancel();
                    LogState("engine.exit-notification.active-permits-revoked");
                    if (!busy) await Execute(async () => await RecoverConnection(pendingConnectionFailure), "engine.exit-recovery");
                    else AppLog.Write("ENGINE exit recovery queued until current operation completes");
                });
            } catch (InvalidOperationException) { }
        };
        FormClosing += (_, e) => {
            AppLog.Write($"ACTION window.close reason={e.CloseReason} explicitExit={exiting}");
            if (!exiting && e.CloseReason == CloseReason.UserClosing) {
                Append("Окно скрыто в трей; приложение продолжает работу.");
                e.Cancel = true; Hide(); tray.ShowBalloonTip(2500, "ProxyBridge", "Приложение работает в трее.", ToolTipIcon.Info);
            } else Append($"Закрытие окна: {e.CloseReason}.");
        };
        Shown += async (_, _) => {
            if (!observeOnly && activitySettingsUsable)
                await ChangeActivityLoggingAsync(settings.ActivityLoggingEnabled, savePreference: false);
            if (OperationsClosed) return;
            Append("Файл журнала: " + AppLog.FilePath);
            await Execute(async () => {
                AppLog.Write($"STARTUP startup={startup} autoConnect={autoConnect} observeOnly={observeOnly} settingsLoaded={settingsReady}");
                try {
                    uint count = Guard.Status;
                    protection.ObserveStartup(count, settingsReady);
                    if (count != 0) {
                        Append($"Найдено собственных фильтров: {count}. Проверка полного состава политики…");
                        if (settingsReady && protection.IsExpectedPolicy()) {
                            CacheDiagnosticContext("startup.policy-verified", true);
                            SetStatus("Политика блокировки подтверждена · приложения из исключений разрешены");
                        } else {
                            CacheDiagnosticContext("startup.policy-unverified", false);
                            SetStatus("Найдены фильтры, но полная защита не подтверждена", ProxyVisualState.Failed);
                        }
                    } else CacheDiagnosticContext("startup.no-policy", false);
                } catch { protection.RequestBlock(); SetVisualState(ProxyVisualState.Failed); throw; }
                if (loadError != null) { ReportError(loadError); return; }
                if (initialSetupNeeded) {
                    NavigateTo("proxy");
                    if (!protection.ProtectionRequired)
                        SetStatus("Укажите настройки своего прокси для подключения");
                    Append("Прокси ещё не настроен. Заполните адрес, порт и учётные данные, затем сохраните настройки.");
                    return;
                }
                Append(startup ? "Автозапуск: настройки загружены, начинаю проверку прокси." : "Настройки загружены.");
                if (autoConnect && !observeOnly) {
                    await Task.Yield(); // Let the first paint complete before startup work.
                    await Connect();
                }
            }, startup ? "startup.logon" : "startup.open");
        };
        monitor.Tick += async (_, _) => {
            if (busy || pendingCommands != 0 || !protection.ProtectionRequired) return;
            await RunMonitorCycle(MonitorProtection);
        };
        if (!observeOnly) monitor.Start();
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing && !resourcesDisposed) {
            resourcesDisposed = true;
            activityMonitor.StateChanged -= ActivityStateChanged;
            try { activityMonitor.Dispose(); }
            catch (Exception ex) { AppLog.Write("ACTIVITY dispose failed: " + AppLog.ExceptionCodes(ex)); }
            monitorCancellation?.Cancel();
            speedCancellation?.Cancel(); monitor.Stop(); monitor.Dispose();
            if (!observeOnly) {
                try { Guard.Deactivate(); }
                catch (Exception ex) {
                    AppLog.Error("Снятие активных разрешений при закрытии", ex);
                    Append("Не удалось снять активные разрешения при закрытии: " + ex.Message, false);
                }
            }
            tray?.Dispose(); engine.Dispose(); statusIcons.Dispose(); hints.Dispose();
            LogState("dispose.complete");
            AppLog.Snapshot("exit.disposed", settings);
        }
        base.Dispose(disposing);
    }
    void ShowWindow() { Show(); WindowState = FormWindowState.Normal; Activate(); }
    void ActivityStateChanged()
    {
        try {
            if (!OperationsClosed && IsHandleCreated)
                BeginInvoke(() => { if (!OperationsClosed) RefreshActivityStatus(); });
        } catch (InvalidOperationException) { }
    }
    void RefreshActivityStatus()
    {
        if (OperationsClosed) return;
        activityLogging.Enabled = !observeOnly && activitySettingsUsable && pendingActivityChanges == 0;
        openActivityLog.Enabled = !observeOnly;
        string? error = activityOperationError ?? activityMonitor.LastError;
        if (observeOnly) {
            activityStatus.Text = "Предпросмотр · запись не запускается";
            activityStatus.ForeColor = AppTheme.Muted;
        } else if (!activitySettingsUsable) {
            activityStatus.Text = "Сначала сохраните исправленные настройки";
            activityStatus.ForeColor = AppTheme.Amber;
        } else if (error != null) {
            activityStatus.Text = activityMonitor.Running ? "Ошибка журнала · мониторинг работает" : "Ошибка журнала активности";
            activityStatus.ForeColor = AppTheme.Red;
            if (displayedActivityError != error) {
                displayedActivityError = error;
                AppLog.Write("ACTIVITY error: " + error);
            }
        } else if (pendingActivityChanges != 0) {
            activityStatus.Text = activityLogging.Checked ? "Включение записи…" : "Остановка записи…";
            activityStatus.ForeColor = AppTheme.Amber;
        } else {
            activityStatus.Text = activityMonitor.Running ? "Запись включена · процессы и подключения" : "Запись выключена";
            activityStatus.ForeColor = activityMonitor.Running ? AppTheme.Green : AppTheme.Muted;
            displayedActivityError = null;
        }
        hints.SetToolTip(activityStatus, error == null ? activityMonitor.FilePath : error);
    }
    async Task ChangeActivityLoggingAsync(bool requested, bool savePreference)
    {
        if (observeOnly || OperationsClosed || !activitySettingsUsable) return;
        bool entered = false;
        pendingActivityChanges++;
        RefreshActivityStatus();
        try {
            await activityGate.WaitAsync();
            entered = true;
            if (OperationsClosed) return;
            activityOperationError = null;
            if (savePreference) {
                // Persist only the metadata preference. Unsaved proxy fields
                // and exclusions stay untouched; no protection operation runs.
                var next = settings with { ActivityLoggingEnabled = requested };
                next.Save();
                settings = next;
            }
            if (requested) await activityMonitor.StartAsync();
            else await activityMonitor.StopAsync();
            if (OperationsClosed) return;
            AppLog.Write($"ACTIVITY preference={settings.ActivityLoggingEnabled}; running={activityMonitor.Running}");
        } catch (Exception ex) {
            activityOperationError = AppLog.ExceptionCodes(ex);
            if (!OperationsClosed) {
                changingActivityCheck = true;
                try { activityLogging.Checked = settings.ActivityLoggingEnabled; }
                finally { changingActivityCheck = false; }
            }
        } finally {
            pendingActivityChanges--;
            if (entered) activityGate.Release();
            if (!OperationsClosed) RefreshActivityStatus();
        }
    }
    void ActivitySettingsSaved()
    {
        if (activitySettingsUsable) return;
        activitySettingsUsable = true;
        // This path follows first-time setup or a previously failed settings load. The method
        // contains its own error handling and does not touch the network gate.
        _ = ChangeActivityLoggingAsync(settings.ActivityLoggingEnabled, savePreference: false);
        RefreshActivityStatus();
    }
    void OpenActivityLog()
    {
        if (observeOnly || OperationsClosed) return;
        try {
            if (!File.Exists(activityMonitor.FilePath)) {
                activityOperationError = "Журнал активности ещё не создан.";
                RefreshActivityStatus();
                return;
            }
            using var viewer = Process.Start(new ProcessStartInfo(activityMonitor.FilePath) { UseShellExecute = true });
            activityOperationError = null;
        } catch (Exception ex) { activityOperationError = AppLog.ExceptionCodes(ex); }
        RefreshActivityStatus();
    }
    async Task WriteUserNoteAsync()
    {
        if (writingUserNote || OperationsClosed) return;
        string original = userLogNote.Text;
        string note = original;
        if (string.IsNullOrWhiteSpace(note)) return;
        note = AppLog.Redact(note, password.Text, settings.Password);
        string normalized = note.Replace("\r\n", "\n").Replace('\r', '\n').Replace('\u0085', '\n').Replace('\u2028', '\n').Replace('\u2029', '\n');
        string entry = string.Join(Environment.NewLine, normalized.Split('\n').Select(line => "Заметка пользователя: " + line));
        entry = AppLog.Redact(entry, password.Text, settings.Password);
        writingUserNote = true;
        writeLogNote.Enabled = false;
        try {
            bool saved = await AppLog.WriteConfirmedAsync(entry);
            if (OperationsClosed) return;
            Append(entry, false);
            // Edits made while the writer was pending belong to the user and
            // must survive confirmation of the older submitted text.
            if (saved && userLogNote.Text == original) userLogNote.Clear();
            else if (!saved) Append("Заметка не подтверждена в файле журнала. Текст оставлен в поле для повторной записи.", false);
        } catch (Exception ex) {
            if (!OperationsClosed) Append("Заметка не записана: " + AppLog.ExceptionCodes(ex), false);
        } finally {
            writingUserNote = false;
            if (!OperationsClosed) writeLogNote.Enabled = true;
        }
    }
    void Append(string text) => Append(text, true);
    void Append(string text, bool persist) => AppendAt(DateTimeOffset.Now, Stopwatch.GetTimestamp(), text, persist);
    void AppendAt(DateTimeOffset eventTime, long monoTicks, string text, bool persist)
    {
        text = AppLog.Redact(text, password.Text, settings.Password);
        if (persist) AppLog.WriteAt(eventTime, monoTicks, text);
        if (IsDisposed || log.IsDisposed) return;
        if (log.TextLength > 24000) log.Clear();
        log.AppendText($"{eventTime:HH:mm:ss}  {text}{Environment.NewLine}");
        string? writeError = AppLog.LastError;
        if (writeError != null && writeError != displayedLogError)
            log.AppendText($"{DateTime.Now:HH:mm:ss}  Не удалось записать журнал на диск ({writeError}). Файл: {AppLog.FilePath}{Environment.NewLine}");
        displayedLogError = writeError;
        RefreshOverviewSummary();
    }
    internal void SetVisualState(ProxyVisualState state)
    {
        if (IsDisposed) return;
        var previous = VisualState;
        VisualState = state;
        Icon = statusIcons.ForState(state);
        tray.Icon = statusIcons.ForState(state);
        tray.Text = StatusIcons.Tooltip(state);
        RefreshLayoutStatus();
        if (previous != state) AppLog.Write($"VISUAL state {previous} -> {state}");
    }
    void SetStatus(string text, ProxyVisualState? state = null)
    {
        if (state.HasValue) SetVisualState(state.Value);
        status.Text = text;
        RefreshLayoutStatus();
        Append(text);
    }
    void ReportError(string message)
    {
        if (IsDisposed) return;
        Append(message);
        status.Text = VisualState == ProxyVisualState.Failed ? "Сбой подключения. См. журнал." : "Ошибка операции. См. журнал.";
        status.ForeColor = AppTheme.Red;
    }
    bool OperationsClosed => resourcesDisposed || IsDisposed || Disposing;

    async Task RunMonitorCycle(Func<CancellationToken, Task> action, bool syntheticTestCommand = false)
    {
        await Execute(async () => {
            using var cancellation = new CancellationTokenSource();
            monitorCancellation = cancellation;
            monitorReadOnly = true;
            try { await action(cancellation.Token); }
            catch (OperationCanceledException ex) when (cancellation.IsCancellationRequested && ex.CancellationToken == cancellation.Token) {
                AppLog.Write("MONITOR read-only probe canceled by caller; no recovery requested");
            } finally {
                monitorReadOnly = false;
                monitorCancellation = null;
            }
        }, background: true, syntheticTestCommand: syntheticTestCommand);
    }
    internal Task RunMonitorForUiTestAsync(Func<CancellationToken, Task> action)
    {
        if (!observeOnly) throw new InvalidOperationException("Synthetic monitor is restricted to observe-only UI tests.");
        return RunMonitorCycle(action, syntheticTestCommand: true);
    }
    internal Task RunCommandForUiTestAsync(Func<Task> action)
    {
        if (!observeOnly) throw new InvalidOperationException("Synthetic command is restricted to observe-only UI tests.");
        return Execute(action, "ui-test.command", syntheticTestCommand: true);
    }
    void PromoteMonitorMutation()
    {
        if (!busy || OperationsClosed) return;
        monitorReadOnly = false;
        SetControlsEnabled(false);
    }
    async Task Execute(Func<Task> action, string? operationName = null, bool background = false, bool syntheticTestCommand = false)
    {
        // Keep native UI input harmless in the visible test window and tray.
        // Only explicit synthetic hooks may run commands in observe-only mode.
        if (observeOnly && !syntheticTestCommand) return;
        if (syntheticTestCommand && !observeOnly)
            throw new InvalidOperationException("Synthetic commands require observe-only mode.");
        if (OperationsClosed || background && (busy || pendingCommands != 0)) return;
        using var operation = operationName == null ? null : AppLog.BeginOperation(operationName);
        bool entered = false, registered = false;
        try {
            if (!background) {
                pendingCommands++;
                registered = true;
                SetControlsEnabled(false);
                if (monitorReadOnly) monitorCancellation?.Cancel();
            }
            await operationGate.WaitAsync();
            entered = true;
            if (OperationsClosed) return;
            busy = true;
            if (operationName != null) LogState("operation.begin");
            try { await action(); }
            catch (Exception ex) { AppLog.Error("Ошибка операции", ex); if (!OperationsClosed) ReportError(ex.Message); }
            finally {
                // Preserve the immediate exit revocation and finish its recovery
                // under the same gate before allowing a queued user command.
                if (!OperationsClosed && pendingConnectionFailure != null && protection.ProtectionRequired) {
                    try { await RecoverConnection(pendingConnectionFailure); }
                    catch (Exception ex) { AppLog.Error("Ошибка восстановления защиты", ex); SetVisualState(ProxyVisualState.Failed); ReportError(ex.Message); }
                }
            }
        } catch (Exception ex) {
            AppLog.Error("Ошибка ожидания операции", ex);
            if (!OperationsClosed) ReportError(ex.Message);
        } finally {
            if (entered) busy = false;
            if (registered) pendingCommands--;
            try {
                if (!OperationsClosed && !busy && pendingCommands == 0) SetControlsEnabled(true);
                if (operationName != null) LogState("operation.end");
            } finally {
                if (entered) operationGate.Release();
            }
        }
    }

    void LogState(string stage)
    {
        // Observations must not add policy checks or interfere with recovery.
        string running;
        try { running = engine.Running.ToString(); }
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
        if (observeOnly) return;
        try {
            // Caller passes an already computed policy result. This method
            // deliberately performs no Guard checks or network snapshots.
            diagnosticContext = new(settings.Host, settings.Port, settings.Protocol, engine.ProcessId, engine.Generation,
                protection.ActiveLuid, protection.ProtectionRequired, protection.ConnectWanted,
                policyVerified, DateTimeOffset.Now, stage, engine.ProcessStartedUtc);
            DiagnosticJournal.UpdateContext(diagnosticContext);
        } catch { }
    }
    void ObserveProbe(ProbeObservation observation)
    {
        if (observeOnly) return;
        try {
            DiagnosticJournal.Record("probe.phase", observation, observation.EventTime, observation.MonoTicks);
            if (observation.Outcome is ProbeOutcome.Failed or ProbeOutcome.TimedOut)
                DiagnosticJournal.Trigger("probe-first-error", observation);
        } catch { }
    }
    void SetControlsEnabled(bool enabled)
    {
        if (controlsDisabled == !enabled) return;
        controlsDisabled = !enabled;
        connect.Enabled = apply.Enabled = block.Enabled = release.Enabled = speed.Enabled = enabled;
        host.Enabled = port.Enabled = username.Enabled = password.Enabled = protocol.Enabled = enabled;
        exclusions.Enabled = addExclusion.Enabled = removeExclusion.Enabled = autoStart.Enabled = enabled;
    }
    void ShowRecovery(ProtectionOutcome outcome, string context, bool manual)
    {
        bool blocked = outcome.PolicyVerified && outcome.EngineStopped;
        string blockedDetails = settings.ExcludedApplications.Length == 0
            ? " · блокировка подтверждена, исключений нет"
            : $" · блокировка подтверждена · исключений: {settings.ExcludedApplications.Length}";
        if (blocked && settings.ExcludedApplications.Length > 0)
            blockedDetails += protection.StoppedDnsAllowed
                ? " · службе DNS разрешены запросы к настроенным DNS-серверам"
                : " · прямой системный DNS не разрешён";
        SetStatus(context + (blocked
            ? blockedDetails
            : " · защита не подтверждена; требуется повторная проверка"),
            manual && outcome.Succeeded ? ProxyVisualState.Paused : ProxyVisualState.Failed);
        foreach (var error in outcome.Errors) {
            AppLog.Error(context, error);
            Append(error.Message, false);
        }
    }
    async Task RecoverConnection(Exception? cause)
    {
        if (!observeOnly) {
            try {
                // Freeze the existing ring and last verified context before
                // fail-closed begins. No probe/native enumeration/disk wait.
                DiagnosticJournal.Trigger("recovery-requested", new {
                    CachedContext = diagnosticContext, CauseCodes = cause == null ? null : AppLog.ExceptionCodes(cause)
                });
            } catch { }
        }
        PromoteMonitorMutation();
        using var operation = AppLog.BeginOperation("connection.recovery");
        var elapsed = Stopwatch.StartNew();
        SetVisualState(ProxyVisualState.Failed);
        if (pendingConnectionFailure != null && !ReferenceEquals(pendingConnectionFailure, cause))
            cause = cause == null ? pendingConnectionFailure : new AggregateException(cause, pendingConnectionFailure);
        pendingConnectionFailure = null;
        var outcome = await protection.RearmAsync(cause);
        LogOutcome("recovery.complete", outcome, elapsed);
        AppLog.Write("RECOVERY causeType=" + (cause?.GetType().Name ?? "none"));
        AppLog.Snapshot("recovery.complete", settings);
        ShowRecovery(outcome, protection.ConnectWanted ? "Сбой подключения · повтор через 8 с" : "Ошибка защиты", false);
    }
    async Task MonitorProtection(CancellationToken cancellationToken)
    {
        try {
            if (!protection.ConnectWanted) {
                if (!protection.IsExpectedPolicy() || protection.ActiveLuid != 0 || engine.Running || !protection.EngineStopConfirmed) {
                    await RecoverConnection(new IOException("Ожидаемая блокировка нарушена."));
                }
                return;
            }
            if (!protection.IsConnectedCandidate()) {
                if (!protection.IsExpectedPolicy() || protection.ActiveLuid != 0 || engine.Running || !protection.EngineStopConfirmed) {
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
            if (!protection.IsConnectedCandidate()) throw new IOException("Защита изменилась во время проверки подключения.");
            CacheDiagnosticContext("monitor.policy-verified", true);
            if (VisualState != ProxyVisualState.Connected)
                SetStatus("Подключено · KillSwitch активен · DNS через прокси", ProxyVisualState.Connected);
        } catch (OperationCanceledException ex) when (cancellationToken.IsCancellationRequested && ex.CancellationToken == cancellationToken) {
            throw;
        } catch (Exception ex) { await RecoverConnection(ex); }
    }
    async Task TestSpeed()
    {
        Exception? connectionFailure = null;
        bool ConnectionVerified()
        {
            try {
                bool verified = protection.IsConnectedCandidate();
                if (!verified && protection.ConnectWanted) {
                    connectionFailure ??= new IOException("Туннель или политика защиты не подтверждены.");
                    SetVisualState(ProxyVisualState.Failed);
                }
                return verified;
            } catch (Exception ex) {
                connectionFailure = ex;
                if (protection.ConnectWanted) SetVisualState(ProxyVisualState.Failed);
                throw;
            }
        }
        try {
            if (!ConnectionVerified()) {
                if (protection.ConnectWanted)
                    await RecoverConnection(connectionFailure);
                else Append("Сначала подключитесь к прокси, затем запустите тест скорости.");
                return;
            }
        } catch (Exception ex) {
            if (protection.ProtectionRequired) { await RecoverConnection(ex); return; }
            throw;
        }
        using var cancellation = new CancellationTokenSource();
        using var watchdog = new System.Windows.Forms.Timer { Interval = 1000 };
        watchdog.Tick += (_, _) => {
            try { if (ConnectionVerified()) return; }
            catch (Exception ex) { connectionFailure = new IOException("Ошибка проверки защиты во время теста.", ex); }
            connectionFailure ??= new IOException("Туннель или защита изменились во время теста; результат недействителен.");
            cancellation.Cancel();
        };
        speedCancellation = cancellation; cancelSpeed.Enabled = true;
        watchdog.Start();
        try {
            Append("Тест скорости: проверка подключения через туннель…");
            try { await Probe(cancellation.Token); }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { throw; }
            catch (Exception ex) { connectionFailure = ex; SetVisualState(ProxyVisualState.Failed); throw; }
            var result = await ProxySpeedTest.RunAsync(new Progress<string>(Append), cancellation.Token);
            if (connectionFailure != null || !ConnectionVerified()) {
                connectionFailure ??= new IOException("Туннель или защита изменились во время теста; результат недействителен.");
                throw connectionFailure;
            }
            Append($"Загрузка: {result.DownloadMbps:F2} Мбит/с; задержка HTTPS: {result.LatencyMs:F0} мс; получено {result.BytesReceived / 1048576.0:F1} МиБ за {result.Duration.TotalSeconds:F1} с. Сервер: {result.Endpoint}");
            Append("Результат зависит от тестового сервера, прокси и вашего подключения.");
        } catch (OperationCanceledException) when (connectionFailure != null || pendingConnectionFailure != null) {
            Append("Тест скорости прерван из-за сбоя подключения.");
        } catch (OperationCanceledException) when (cancellation.IsCancellationRequested) {
            Append("Тест скорости отменён.");
        } finally {
            watchdog.Stop();
            speedCancellation = null;
            if (!IsDisposed) cancelSpeed.Enabled = false;
            if (!IsDisposed && (connectionFailure != null || pendingConnectionFailure != null))
                await RecoverConnection(connectionFailure);
        }
    }
    async Task Connect()
    {
        LogState("connect.request");
        var next = ReadSettings();
        next.Validate(); next.Save(); settings = next;
        ActivitySettingsSaved();
        protection.UseSettings(settings); protection.RequestConnect();
        AppLog.Write($"CONNECT settings accepted protocol={settings.Protocol} exclusions={settings.ExcludedApplications.Length}");
        await StartProtected();
    }
    Settings ReadSettings()
    {
        AppLog.RegisterSecret(password.Text);
        return new(host.Text.Trim(), int.TryParse(port.Text, out int p) ? p : 0, username.Text, password.Text, protocol.SelectedIndex == 0 ? "http" : "socks") {
            ExcludedApplications = exclusions.Items.Cast<string>().ToArray(),
            ActivityLoggingEnabled = settings.ActivityLoggingEnabled
        };
    }
    async Task ApplySettings()
    {
        var next = ReadSettings();
        next.Validate(); next.Save();
        bool reconnect = protection.ConnectWanted;
        settings = next;
        ActivitySettingsSaved();
        protection.UseSettings(settings);
        AppLog.Write($"SETTINGS applied protocol={settings.Protocol} exclusions={settings.ExcludedApplications.Length} reconnect={reconnect}");
        Append(reconnect ? "Настройки сохранены. Переподключение с новым прокси…" : "Настройки сохранены. Нажмите «Подключить», чтобы использовать их.");
        if (reconnect) {
            protection.RequestConnect();
            await StartProtected();
        }
        else if (protection.ProtectionRequired) {
            var elapsed = Stopwatch.StartNew();
            var outcome = await protection.RearmAsync();
            LogOutcome("settings.rearm", outcome, elapsed);
            AppLog.Snapshot("settings.rearm-complete", settings);
            ShowRecovery(outcome, "Применение настроек защиты", true);
        }
    }
    async Task StartProtected()
    {
        PromoteMonitorMutation();
        var elapsed = Stopwatch.StartNew();
        string stage = "prepare";
        bool connected = false;
        if (VisualState != ProxyVisualState.Failed) SetVisualState(ProxyVisualState.Connecting);
        try {
            var pending = pendingConnectionFailure;
            pendingConnectionFailure = null;
            var preparation = await protection.RearmAsync(pending);
            LogOutcome("connect.prepare", preparation, elapsed);
            if (pendingConnectionFailure != null) {
                await RecoverConnection(preparation.Errors.Count == 0 ? null : new AggregateException(preparation.Errors));
                return;
            }
            if (!preparation.Succeeded) {
                ShowRecovery(preparation, "Подготовка подключения не завершена", false);
                AppLog.Snapshot("connect.prepare-failed", settings);
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
            Append("Запуск сетевого движка и TUN…"); engine.Start();
            stage = "tun-wait";
            var tunWait = Stopwatch.StartNew();
            ulong luid = 0;
            for (int i = 0; i < 60 && engine.Running; i++) { await Task.Delay(250); luid = Guard.TunLuid(); if (luid != 0) break; }
            AppLog.Write($"CONNECT stage=tun-wait elapsedMs={elapsed.ElapsedMilliseconds} waitMs={tunWait.ElapsedMilliseconds} discoveredLuid={luid} generation={engine.Generation}");
            if (luid == 0 || !engine.Running) throw new InvalidOperationException("TUN не запустился. Проверьте журнал и правила Касперского.");
            stage = "active-policy";
            protection.ConfigureActive(luid);
            CacheDiagnosticContext("connect.active-policy-verified", true);
            LogState("connect.active-policy-verified");
            AppLog.Snapshot("connect.tun-active-policy", settings);
            Append("Туннель готов. Проверка HTTPS через прокси…");
            stage = "https-probe";
            AppLog.Write($"CONNECT stage={stage} elapsedMs={elapsed.ElapsedMilliseconds}");
            await Probe();
            if (!protection.IsConnectedCandidate()) throw new IOException("Туннель или политика защиты изменились при подключении.");
            CacheDiagnosticContext("connect.connected", true);
            SetStatus("Подключено · KillSwitch активен · DNS через прокси", ProxyVisualState.Connected);
            connected = true; stage = "connected";
            LogState("connect.connected");
            AppLog.Snapshot("connect.connected", settings);
        } catch (Exception ex) {
            long failedAtMs = elapsed.ElapsedMilliseconds;
            await RecoverConnection(ex);
            AppLog.Write($"CONNECT failedStage={stage} failedAtMs={failedAtMs} errorType={ex.GetType().Name}; recovery completed");
        } finally {
            AppLog.Write($"CONNECT attempt-end stage={stage} connected={connected} elapsedMs={elapsed.ElapsedMilliseconds} generation={engine.Generation}");
        }
    }
    async Task Probe(CancellationToken cancellationToken = default, bool quietSuccess = false)
    {
        var context = new ProbeContext(engine.Generation);
        if (!quietSuccess) {
            await ConnectionProbe.CheckObservedAsync(context, ObserveProbe, cancellationToken, message => Append(message));
            return;
        }
        var messages = new List<(DateTimeOffset EventTime, long MonoTicks, string Message)>(8);
        bool completed = false;
        try {
            await ConnectionProbe.CheckObservedAsync(context, ObserveProbe, cancellationToken, message => {
                if (messages.Count < 8) messages.Add((DateTimeOffset.Now, Stopwatch.GetTimestamp(), message));
            });
            completed = true;
        } finally {
            // Only the first-endpoint healthy result is quiet. Preserve every
            // failed attempt when a later endpoint succeeds, and all failures.
            if (!completed || messages.Count > 2)
                foreach (var message in messages) {
                    try { AppendAt(message.EventTime, message.MonoTicks, message.Message, true); }
                    catch { /* Diagnostics must not alter the probe outcome. */ }
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
        if (outcome.Succeeded) {
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
