using System.Diagnostics;

namespace ProxyBridge;

internal sealed partial class MainForm : Form
{
    readonly TextBox host = new();
    readonly TextBox port = new();
    readonly TextBox username = new();
    readonly TextBox password = new() { UseSystemPasswordChar = true };
    readonly ComboBox protocol = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    readonly Label status = new() { AutoSize = true, ForeColor = Color.SteelBlue, Text = "Готово к подключению" };
    readonly TextBox log = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill };
    readonly TextBox userLogNote = new() { Multiline = true, AcceptsReturn = true, ScrollBars = ScrollBars.Vertical, WordWrap = true };
    readonly Button writeLogNote = new ThemeButton() { Text = "Записать в лог" };
    readonly CheckBox activityLogging = new() { AutoSize = true };
    readonly Button openActivityLog = new ThemeButton() { Text = "Открыть журнал" };
    readonly Label activityStatus = new() { AutoSize = false, AutoEllipsis = true };
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
    readonly StatusIcons statusIcons = new();
    readonly NotifyIcon tray;
    readonly bool observeOnly;
    Settings settings;
    bool exiting;
    bool resourcesDisposed;
    internal ProxyVisualState VisualState { get; private set; } = ProxyVisualState.Paused;
    readonly bool startedAtLogon;
    readonly bool autoConnectOnStartup;
    readonly bool initialSettingsReady;
    readonly bool initialSetupNeeded;
    readonly string? initialSettingsError;

    public MainForm(bool autoConnect = true, bool startup = false, bool observeOnly = false)
    {
        this.observeOnly = observeOnly;
        startedAtLogon = startup;
        InitializeWindow();

        (settings, initialSettingsError) = LoadInitialSettings();
        initialSetupNeeded = initialSettingsError == null && string.IsNullOrWhiteSpace(settings.Host);
        initialSettingsReady = initialSettingsError == null && !initialSetupNeeded;
        autoConnectOnStartup = autoConnect && initialSettingsReady;
        protection = CreateProtectionController();
        protection.ObserveStartup(0, initialSettingsReady);

        PopulateSettingsControls();
        activitySettingsUsable = initialSettingsReady;
        activityLogging.Checked = settings.ActivityLoggingEnabled;
        BuildLayout(startup);
        WireActivityEvents();
        RefreshActivityStatus();
        WireSettingsEvents();
        tray = CreateTray();
        WireCommandEvents();
        WireEngineEvents();
        FormClosing += OnWindowClosing;
        Shown += OnWindowShown;
        monitor.Tick += OnMonitorTick;
        if (!observeOnly)
        {
            monitor.Start();
        }
    }

    void InitializeWindow()
    {
        Text = $"ProxyBridge {AppVersion.Display} — защищённое подключение";
        Size = new(790, 680);
        MinimumSize = new(750, 640);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new("Segoe UI", 10);
        Icon = statusIcons.ForState(VisualState);
    }

    ProtectionController CreateProtectionController() => new(settings, new ProtectionOperations(
        () => Guard.Status,
        () => engine.Running,
        (profile, luid, dns) => Guard.Configure(profile, luid, allowStoppedDns: dns),
        (profile, luid, dns) => Guard.IsConfigured(profile, luid, allowStoppedDns: dns),
        engine.Stop,
        Guard.Remove,
        Guard.Deactivate));

    void WireCommandEvents()
    {
        connect.Click += async (_, _) => await Execute(Connect, "ui.connect");
        apply.Click += async (_, _) => await Execute(ApplySettings, "ui.apply-settings");
        block.Click += async (_, _) => await Execute(Block, "ui.block");
        release.Click += async (_, _) => await Execute(Release, "ui.release");
        speed.Click += async (_, _) => await Execute(TestSpeed, "ui.speed-test");
        writeLogNote.Click += async (_, _) => await WriteUserNoteAsync();
        cancelSpeed.Click += (_, _) => CancelSpeedTest();
    }

    NotifyIcon CreateTray()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Открыть", null, (_, _) => OpenFromTray("tray.open"));
        menu.Items.Add("Подключить", null, async (_, _) => await Execute(Connect, "tray.connect"));
        menu.Items.Add("Остановить и блокировать", null, async (_, _) => await Execute(Block, "tray.block"));
        menu.Items.Add("Отключить и вернуть интернет", null, async (_, _) => await Execute(Release, "tray.release"));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Выход и восстановить интернет", null,
            async (_, _) => await Execute(ExitAndReleaseProtection, "tray.exit-release"));
        var preserveExit = menu.Items.Add("Выход (сохранить KillSwitch)", null,
            async (_, _) => await Execute(ExitPreservingProtection, "exit.preserve"));
        exitApplication.Click += (_, _) =>
        {
            AppLog.Write("ACTION ui.exit-preserve");
            preserveExit.PerformClick();
        };
        var icon = new NotifyIcon
        {
            Icon = statusIcons.ForState(VisualState),
            Text = StatusIcons.Tooltip(VisualState),
            Visible = true,
            ContextMenuStrip = menu
        };
        icon.DoubleClick += (_, _) => OpenFromTray("tray.double-click");
        return icon;
    }

    void OpenFromTray(string action)
    {
        AppLog.Write("ACTION " + action);
        ShowWindow();
    }

    async Task ExitAndReleaseProtection()
    {
        Append("Команда пользователя: выход и восстановление интернета.");
        if (!await ReleaseProtection())
        {
            return;
        }

        AppLog.Snapshot("exit.release-complete", settings);
        LogState("exit.release-complete");
        exiting = true;
        Close();
    }

    async Task ExitPreservingProtection()
    {
        Append("Команда пользователя: выход с сохранением KillSwitch.");
        var elapsed = Stopwatch.StartNew();
        var result = await protection.PrepareExitAsync();
        LogOutcome("exit.preserve", result, elapsed);
        AppLog.Snapshot("exit.preserve-complete", settings);
        if (!result.Succeeded)
        {
            ShowRecovery(result, "Выход отменён", false);
            return;
        }

        SetVisualState(ProxyVisualState.Paused);
        exiting = true;
        Close();
    }

    void OnWindowClosing(object? sender, FormClosingEventArgs e)
    {
        AppLog.Write($"ACTION window.close reason={e.CloseReason} explicitExit={exiting}");
        if (!exiting && e.CloseReason == CloseReason.UserClosing)
        {
            Append("Окно скрыто в трей; приложение продолжает работу.");
            e.Cancel = true;
            Hide();
        }
        else
        {
            Append($"Закрытие окна: {e.CloseReason}.");
        }
    }

    async void OnWindowShown(object? sender, EventArgs e)
    {
        if (!observeOnly && activitySettingsUsable)
        {
            await ChangeActivityLoggingAsync(settings.ActivityLoggingEnabled, savePreference: false);
        }

        if (OperationsClosed)
        {
            return;
        }

        Append("Файл журнала: " + AppLog.FilePath);
        await Execute(InitializeConnectionState, startedAtLogon ? "startup.logon" : "startup.open");
    }

    async Task InitializeConnectionState()
    {
        AppLog.Write($"STARTUP startup={startedAtLogon} autoConnect={autoConnectOnStartup} observeOnly={observeOnly} settingsLoaded={initialSettingsReady}");
        ObserveStartupProtection();
        if (initialSettingsError != null)
        {
            ReportError(initialSettingsError);
            return;
        }
        if (initialSetupNeeded)
        {
            NavigateTo("proxy");
            if (!protection.ProtectionRequired)
            {
                SetStatus("Укажите настройки своего прокси для подключения");
            }

            Append("Прокси ещё не настроен. Заполните адрес, порт и учётные данные, затем сохраните настройки.");
            return;
        }

        Append(startedAtLogon ? "Автозапуск: настройки загружены, начинаю проверку прокси." : "Настройки загружены.");
        if (autoConnectOnStartup && !observeOnly)
        {
            await Task.Yield(); // Let the first paint complete before startup work.
            await Connect();
        }
    }

    void ObserveStartupProtection()
    {
        try
        {
            uint count = Guard.Status;
            protection.ObserveStartup(count, initialSettingsReady);
            if (count == 0)
            {
                CacheDiagnosticContext("startup.no-policy", false);
                return;
            }

            Append($"Найдено собственных фильтров: {count}. Проверка полного состава политики…");
            if (initialSettingsReady && protection.IsExpectedPolicy())
            {
                CacheDiagnosticContext("startup.policy-verified", true);
                SetStatus("Политика блокировки подтверждена · приложения из исключений разрешены");
            }
            else
            {
                CacheDiagnosticContext("startup.policy-unverified", false);
                SetStatus("Найдены фильтры, но полная защита не подтверждена", ProxyVisualState.Failed);
            }
        }
        catch
        {
            protection.RequestBlock();
            SetVisualState(ProxyVisualState.Failed);
            throw;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !resourcesDisposed)
        {
            resourcesDisposed = true;
            activityMonitor.StateChanged -= ActivityStateChanged;
            try
            {
                activityMonitor.Dispose();
            }
            catch (Exception ex) { AppLog.Write("ACTIVITY dispose failed: " + AppLog.ExceptionCodes(ex)); }
            monitorCancellation?.Cancel();
            speedCancellation?.Cancel();
            monitor.Stop();
            monitor.Dispose();
            if (!observeOnly)
            {
                try
                {
                    Guard.Deactivate();
                }
                catch (Exception ex)
                {
                    AppLog.Error("Снятие активных разрешений при закрытии", ex);
                    Append("Не удалось снять активные разрешения при закрытии: " + ex.Message, false);
                }
            }
            tray?.Dispose();
            engine.Dispose();
            statusIcons.Dispose();
            hints.Dispose();
            LogState("dispose.complete");
            AppLog.Snapshot("exit.disposed", settings);
        }
        base.Dispose(disposing);
    }
    void ShowWindow()
    {
        Show();
        WindowState = FormWindowState.Normal;
        Activate();
    }
    internal void SetVisualState(ProxyVisualState state)
    {
        if (IsDisposed)
        {
            return;
        }

        var previous = VisualState;
        VisualState = state;
        Icon = statusIcons.ForState(state);
        tray.Icon = statusIcons.ForState(state);
        tray.Text = StatusIcons.Tooltip(state);
        RefreshLayoutStatus();
        if (previous != state)
        {
            AppLog.Write($"VISUAL state {previous} -> {state}");
        }
    }
    void SetStatus(string text, ProxyVisualState? state = null)
    {
        if (state.HasValue)
        {
            SetVisualState(state.Value);
        }

        status.Text = text;
        RefreshLayoutStatus();
        Append(text);
    }
    void ReportError(string message)
    {
        if (IsDisposed)
        {
            return;
        }

        Append(message);
        status.Text = VisualState == ProxyVisualState.Failed ? "Сбой подключения. См. журнал." : "Ошибка операции. См. журнал.";
        status.ForeColor = AppTheme.Red;
    }
    void SetControlsEnabled(bool enabled)
    {
        if (controlsDisabled == !enabled)
        {
            return;
        }

        controlsDisabled = !enabled;
        connect.Enabled = apply.Enabled = block.Enabled = release.Enabled = speed.Enabled = enabled;
        host.Enabled = port.Enabled = username.Enabled = password.Enabled = protocol.Enabled = enabled;
        exclusions.Enabled = addExclusion.Enabled = removeExclusion.Enabled = autoStart.Enabled = enabled;
    }
}
