using System.Diagnostics;

namespace ProxyBridge;

internal sealed partial class MainForm
{
    bool changingAutoStart;

    static (Settings Settings, string? Error) LoadInitialSettings()
    {
        Settings loaded;
        Exception? loadException = null;
        try
        {
            loaded = Settings.Load();
        }
        catch (Exception ex)
        {
            loaded = Settings.Default;
            loadException = ex;
        }

        AppLog.RegisterSecret(loaded.Password);
        if (loadException == null)
        {
            return (loaded, null);
        }

        AppLog.Error("Загрузка настроек", loadException);
        return (loaded, "Не удалось загрузить настройки. Проверьте поля и сохраните их заново. Автоподключение отменено. " + loadException.Message);
    }

    void PopulateSettingsControls()
    {
        host.Text = settings.Host;
        port.Text = settings.Port.ToString();
        username.Text = settings.Username;
        password.Text = settings.Password;
        protocol.Items.AddRange(["HTTP CONNECT", "SOCKS5 (TCP)"]);
        protocol.SelectedIndex = settings.Protocol == "http" ? 0 : 1;
        exclusions.Items.AddRange(settings.ExcludedApplications);
        exclusions.Items.AddRange(settings.ExcludedAddresses);
    }

    void WireSettingsEvents()
    {
        addExclusion.Click += (_, _) => AddExcludedApplications();
        addAddressExclusion.Click += (_, _) => AddExcludedAddress();
        removeExclusion.Click += (_, _) => RemoveSelectedExclusion();
        try
        {
            autoStart.Checked = StartupRegistration.IsEnabled;
        }
        catch (Exception ex) { Append("Не удалось проверить автозапуск: " + ex.Message); }
        autoStart.CheckedChanged += OnAutoStartChanged;
    }

    void AddExcludedApplications()
    {
        using var operation = AppLog.BeginOperation("ui.exclusion.add");
        using var dialog = new OpenFileDialog
        {
            Filter = "Приложения (*.exe)|*.exe",
            CheckFileExists = true,
            Multiselect = true,
            Title = "Приложения с прямым доступом"
        };
        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            AppLog.Write("ACTION exclusion.add cancelled");
            return;
        }
        try
        {
            var paths = Settings.NormalizeExcludedApplications(ExcludedApplicationItems().Concat(dialog.FileNames));
            var addresses = ExcludedAddressItems();
            exclusions.Items.Clear();
            exclusions.Items.AddRange(paths);
            exclusions.Items.AddRange(addresses);
            RefreshOverviewSummary();
            AppLog.Write($"ACTION exclusion.add pendingCount={exclusions.Items.Count}");
        }
        catch (Exception ex)
        {
            Append(ex.Message);
        }
    }

    string[] ExcludedApplicationItems() => exclusions.Items.Cast<string>()
        .Where(value => !AddressExclusion.TryParse(value, out _)).ToArray();

    string[] ExcludedAddressItems() => exclusions.Items.Cast<string>()
        .Where(value => AddressExclusion.TryParse(value, out _)).ToArray();

    void AddExcludedAddress()
    {
        using var operation = AppLog.BeginOperation("ui.exclusion.address.add");
        using var dialog = new AddressExclusionDialog();
        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        try
        {
            AddAddressExclusion(dialog.Value!);
            AppLog.Write($"ACTION exclusion.address.add pendingCount={ExcludedAddressItems().Length}");
        }
        catch (Exception ex)
        {
            Append(ex.Message);
        }
    }

    void AddAddressExclusion(string value)
    {
        string canonical = AddressExclusion.Parse(value).Value;
        var addresses = Settings.NormalizeExcludedAddresses(ExcludedAddressItems().Append(canonical));
        var applications = ExcludedApplicationItems();
        exclusions.Items.Clear();
        exclusions.Items.AddRange(applications);
        exclusions.Items.AddRange(addresses);
        exclusions.SelectedItem = canonical;
        RefreshOverviewSummary();
    }

    void RemoveSelectedExclusion()
    {
        using var operation = AppLog.BeginOperation("ui.exclusion.remove");
        if (exclusions.SelectedIndex >= 0)
        {
            exclusions.Items.RemoveAt(exclusions.SelectedIndex);
        }

        RefreshOverviewSummary();
        AppLog.Write($"ACTION exclusion.remove pendingCount={exclusions.Items.Count}");
    }

    async void OnAutoStartChanged(object? sender, EventArgs e)
    {
        if (changingAutoStart)
        {
            return;
        }

        bool requested = autoStart.Checked;
        await Execute(() => UpdateAutoStart(requested), requested ? "ui.startup.enable" : "ui.startup.disable");
    }

    async Task UpdateAutoStart(bool requested)
    {
        try
        {
            await StartupRegistration.SetEnabledAsync(requested);
            Append(requested ? "Автозапуск включён. При входе в Windows откроется журнал проверки." : "Автозапуск отключён.");
        }
        finally
        {
            changingAutoStart = true;
            try
            {
                autoStart.Checked = StartupRegistration.IsEnabled;
            }
            finally { changingAutoStart = false; }
        }
    }

    Settings ReadSettings()
    {
        AppLog.RegisterSecret(password.Text);
        return new(host.Text.Trim(), int.TryParse(port.Text, out int p) ? p : 0, username.Text, password.Text, protocol.SelectedIndex == 0 ? "http" : "socks")
        {
            ExcludedApplications = ExcludedApplicationItems(),
            ExcludedAddresses = ExcludedAddressItems(),
            ActivityLoggingEnabled = settings.ActivityLoggingEnabled
        };
    }
    async Task ApplySettings()
    {
        var next = ReadSettings();
        next.Validate();
        next.Save();
        bool reconnect = protection.ConnectWanted;
        settings = next;
        ActivitySettingsSaved();
        protection.UseSettings(settings);
        AppLog.Write($"SETTINGS applied protocol={settings.Protocol} exclusions={settings.ExcludedApplications.Length} addressExclusions={settings.ExcludedAddresses.Length} reconnect={reconnect}");
        Append(reconnect ? "Настройки сохранены. Переподключение с новым прокси…" : "Настройки сохранены. Нажмите «Подключить», чтобы использовать их.");
        if (reconnect)
        {
            protection.RequestConnect();
            await StartProtected();
        }
        else if (protection.ProtectionRequired)
        {
            var elapsed = Stopwatch.StartNew();
            var outcome = await protection.RearmAsync();
            LogOutcome("settings.rearm", outcome, elapsed);
            AppLog.Snapshot("settings.rearm-complete", settings);
            ShowRecovery(outcome, "Применение настроек защиты", true);
        }
    }
}
