namespace ProxyBridge;

// Runs the real WinForms controls with isolated synthetic settings and observeOnly=true.
internal static class UiTestSuite
{
    static readonly List<object> UiCaptures = [];

    internal static void Run(bool startup)
    {
        UiCaptures.Clear();
        var sample = new Settings("192.0.2.10", 8080, "qa-user", "qa-ui-password", "http")
        {
            ExcludedApplications = [@"C:\QA Apps\Firefox\firefox.exe", @"C:\QA Apps\Яндекс Музыка\Яндекс Музыка.exe"]
        };
        sample.Save();
        using var form = new MainForm(false, startup: startup, observeOnly: true);
        form.Text += " [ТЕСТ ИНТЕРФЕЙСА]";
        form.Shown += (_, _) => form.BeginInvoke(async () =>
        {
            try
            {
                var controls = Descendants(form).ToArray();
                var protocol = controls.OfType<ComboBox>().Single(c => c.Name == "protocol");
                var exclusions = controls.OfType<ListBox>().Single(c => c.Name == "exclusions");
                var password = controls.OfType<TextBox>().Single(c => c.Name == "password");
                if (protocol.SelectedIndex != 0 || protocol.Text != "HTTP CONNECT")
                {
                    throw new InvalidOperationException("UI protocol selection is empty or incorrect.");
                }

                if (!exclusions.Items.Cast<string>().SequenceEqual(sample.ExcludedApplications))
                {
                    throw new InvalidOperationException("UI did not load both application exclusions.");
                }

                if (password.Text != sample.Password || !password.UseSystemPasswordChar)
                {
                    throw new InvalidOperationException("UI did not load the masked password.");
                }

                var activity = controls.OfType<CheckBox>().Single(c => c.Name == "activityLogging");
                var activityOpen = controls.OfType<Button>().Single(c => c.Name == "openActivityLog");
                if (!activity.Checked || activity.Enabled || activityOpen.Enabled || File.Exists(Path.Combine(Settings.DataDir, "ProxyBridge-activity.log")))
                {
                    throw new InvalidOperationException("Activity controls must show the default preference without recording or opening external viewers in observe-only tests.");
                }

                if (form.CurrentPage != "overview" || form.IsCompact != startup)
                {
                    throw new InvalidOperationException("Initial overview does not match the startup mode.");
                }

                CaptureUi(form, "ui-preview.png");
                VerifyNavigation(form);
                VerifyStatusIcons(form);
                await MonitorUiTests.RunAsync(form, name => CaptureUi(form, name));
                bool wasVisible = form.Visible && form.WindowState == FormWindowState.Normal;
                CaptureUi(form, "ui-close-before.png");
                form.Close();
                bool passed = wasVisible && !form.Visible && !form.IsDisposed && form.VisualState == ProxyVisualState.Paused;
                File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "ui-test.txt"), passed ? "PASS: visible overview/startup, four navigation pages, embedded help, unsaved indicator, minimum-size capture and action button height, protocol/exclusions/masked password, D/P/S icons, operation-error state preservation, stable monitor controls, canceled probe joins before serialized commands, disabled-button capture, close-to-tray" : "FAIL: startup visibility or close-to-tray");
                if (!passed)
                {
                    Environment.ExitCode = 1;
                }
            }
            catch (Exception ex) { TestHostProgram.WriteFailure("ui-test.txt", ex.Message.Replace(sample.Password, "***", StringComparison.Ordinal)); }
            finally { Application.ExitThread(); }
        });
        Application.Run(form);
        return;
    }

    static void CaptureUi(Form form, string name)
    {
        form.PerformLayout();
        using var bitmap = new Bitmap(form.Width, form.Height);
        form.DrawToBitmap(bitmap, new Rectangle(0, 0, form.Width, form.Height));
        bitmap.Save(Path.Combine(AppContext.BaseDirectory, name));
        var main = form as MainForm;
        UiCaptures.Add(new
        {
            file = name,
            capturedAt = DateTimeOffset.Now,
            source = "observe-only WinForms UI test; synthetic operations, no live connection",
            page = main?.CurrentPage,
            visualState = main?.VisualState.ToString(),
            compact = main?.IsCompact,
            width = form.Width,
            height = form.Height,
            dpi = form.DeviceDpi,
            buttons = Descendants(form).OfType<Button>().Select(b => new
            {
                name = b.Name,
                text = b.Text,
                enabled = b.Enabled,
                visible = b.Visible,
                focused = b.Focused,
                width = b.Width,
                height = b.Height
            }).ToArray()
        });
        File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "ui-captures.json"),
            System.Text.Json.JsonSerializer.Serialize(new { schemaVersion = 1, captures = UiCaptures },
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }
    static void VerifyNavigation(MainForm form)
    {
        // Navigating never invokes a connection or edits persistent user settings.
        // Tests use the same navigation controls as the production interface.
        form.NavigateTo("proxy");
        if (form.IsCompact)
        {
            throw new InvalidOperationException("Proxy settings did not expand the startup window.");
        }

        var address = Descendants(form).OfType<TextBox>().Single(c => c.Name == "host");
        var unsaved = Descendants(form).Single(c => c.Name == "unsavedChanges");
        string originalAddress = address.Text;
        if (unsaved.Visible)
        {
            throw new InvalidOperationException("Unchanged settings are shown as unsaved.");
        }

        address.Text = originalAddress + "1";
        if (!unsaved.Visible)
        {
            throw new InvalidOperationException("Edited settings have no unsaved indicator.");
        }

        CaptureUi(form, "ui-settings-dirty.png");
        address.Text = originalAddress;
        if (unsaved.Visible)
        {
            throw new InvalidOperationException("Restored settings still show an unsaved indicator.");
        }

        var buttons = Descendants(form).OfType<Button>().ToArray();
        foreach (var page in new[] { ("overview", "navOverview"), ("proxy", "navProxy"), ("exclusions", "navExclusions"), ("help", "navHelp") })
        {
            var navigation = buttons.Single(c => c.Name == page.Item2);
            if (!navigation.Visible || !navigation.Enabled || string.IsNullOrWhiteSpace(navigation.AccessibleName))
            {
                throw new InvalidOperationException("Navigation is inaccessible: " + page.Item1);
            }

            CaptureUi(form, "ui-nav-" + page.Item1 + "-before.png");
            navigation.Focus();
            CaptureUi(form, "ui-nav-" + page.Item1 + "-focused.png");
            navigation.PerformClick();
            if (form.CurrentPage != page.Item1)
            {
                throw new InvalidOperationException("Navigation did not select " + page.Item1);
            }

            CaptureUi(form, "ui-" + page.Item1 + ".png");
        }
        if (HelpContent.Sections.Count < 5 || HelpContent.Sections.Any(s => string.IsNullOrWhiteSpace(s.Title) || string.IsNullOrWhiteSpace(s.Body)))
        {
            throw new InvalidOperationException("Embedded help is incomplete.");
        }

        var help = Descendants(form).Single(c => c.Name == "helpBody");
        string Normalize(string value) => value.Replace("\r\n", "\n").Trim();
        if (!help.Visible || !Normalize(help.Text).Contains(Normalize(HelpContent.Sections[0].Body), StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Help page did not display its first topic.");
        }

        form.NavigateTo("overview");
        var previousSize = form.Size;
        form.Size = form.MinimumSize;
        form.PerformLayout();
        foreach (var action in Descendants(form).OfType<Button>().Where(c => c.Name is "block" or "release"))
        {
            var required = action.GetPreferredSize(new Size(action.Width, 0));
            if (required.Height > action.Height)
            {
                throw new InvalidOperationException("Action button text is too tall at minimum window size: " + action.Name);
            }
        }
        CaptureUi(form, "ui-minimum.png");
        form.Size = previousSize;
    }
    static void VerifyStatusIcons(MainForm form)
    {
        var flags = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;
        var tray = (NotifyIcon)typeof(MainForm).GetField("tray", flags)!.GetValue(form)!;
        var reportError = typeof(MainForm).GetMethod("ReportError", flags)!;
        if (form.VisualState != ProxyVisualState.Paused)
        {
            throw new InvalidOperationException("UI initially claims a connection without a probe.");
        }

        var handles = new HashSet<IntPtr>();
        foreach (var state in new[] { ProxyVisualState.Connecting, ProxyVisualState.Connected, ProxyVisualState.Failed, ProxyVisualState.Paused })
        {
            form.SetVisualState(state);
            Descendants(form).Single(c => c.Name == "connectionStatus").Text = state switch
            {
                ProxyVisualState.Connecting => "Тестовый сценарий: выполняется проверка подключения…",
                ProxyVisualState.Connected => "Тестовый сценарий: подключено · KillSwitch активен · DNS через прокси",
                ProxyVisualState.Failed => "Тестовый сценарий: проверка не пройдена · блокировка сохранена",
                _ => "Тестовый сценарий: прокси остановлен · ожидание команды"
            };
            CaptureUi(form, "ui-state-" + state.ToString().ToLowerInvariant() + ".png");
            char letter = state == ProxyVisualState.Connected ? 'D' : state == ProxyVisualState.Failed ? 'S' : 'P';
            if (form.VisualState != state || form.Icon!.Handle != tray.Icon!.Handle || !tray.Text.Contains($": {letter} ·"))
            {
                throw new InvalidOperationException("Window and tray status icons disagree.");
            }

            handles.Add(form.Icon.Handle);
            if (state != ProxyVisualState.Connecting)
            {
                using var preview = form.Icon.ToBitmap();
                preview.Save(Path.Combine(AppContext.BaseDirectory, $"icon-{letter}.png"));
            }
            if (state is ProxyVisualState.Connected or ProxyVisualState.Failed)
            {
                IntPtr original = form.Icon.Handle;
                string tooltip = tray.Text;
                reportError.Invoke(form, ["QA simulated operation error"]);
                if (form.VisualState != state || form.Icon.Handle != original || tray.Icon.Handle != original || tray.Text != tooltip)
                {
                    throw new InvalidOperationException("An unrelated operation error changed connection status.");
                }
            }
        }
        if (handles.Count != 3)
        {
            throw new InvalidOperationException("Three distinct status icons are required.");
        }
    }
    static IEnumerable<Control> Descendants(Control parent)
    {
        foreach (Control child in parent.Controls)
        {
            yield return child;
            foreach (var descendant in Descendants(child))
            {
                yield return descendant;
            }
        }
    }
}
