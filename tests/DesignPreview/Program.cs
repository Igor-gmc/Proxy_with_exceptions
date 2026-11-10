using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;

namespace ProxyBridge.DesignPreview;

// A separate renderer, never the production entry point. No payload installation,
// production mutex changes, proxy connection, WFP mutation, or real credentials.
internal static class Program
{
    const BindingFlags Instance = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
    const BindingFlags Static = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
    static readonly List<object> Captures = [];
    static readonly List<object> Checks = [];
    static readonly List<object> CornerEvidence = [];
    static int failures;
    static string output = "";
    static Assembly app = null!;
    static MethodInfo? monitorSuite;
    static string? testHostSha256;

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr SendMessage(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")]
    static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    static extern IntPtr WindowFromPoint(Point point);
    [DllImport("user32.dll")]
    static extern IntPtr GetAncestor(IntPtr window, uint flags);

    [STAThread]
    static int Main(string[] args)
    {
        string? dll = Value(args, "--dll");
        string? destination = Value(args, "--out");
        string? testHostDll = Value(args, "--test-host");
        bool verify = args.Contains("--verify", StringComparer.Ordinal);
        if (dll == null || destination == null || verify && testHostDll == null)
        {
            Console.Error.WriteLine("Usage: DesignPreview --dll <ProxyBridge.dll> --out <new-artifacts-directory> [--verify --test-host <absolute-ProxyBridge.TestHost.dll>] [--corners-only] [--desktop-corners]");
            return 2;
        }
        Form? form = null;
        string? error = null;
        string? hash = null;
        bool ownsOutput = false;
        try
        {
            dll = Path.GetFullPath(dll);
            output = Path.GetFullPath(destination);
            if (!File.Exists(dll))
            {
                throw new FileNotFoundException("Application DLL was not found.", dll);
            }
            // Refuse reuse, so an old successful capture cannot hide a failed run.
            if (Directory.Exists(output) && Directory.EnumerateFileSystemEntries(output).Any())
            {
                throw new InvalidOperationException("Output directory must be new or empty.");
            }

            Directory.CreateDirectory(output);
            ownsOutput = true;
            hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(dll)));
            var resolver = new AssemblyDependencyResolver(dll);
            string dllDirectory = Path.GetDirectoryName(dll)!;
            AssemblyLoadContext.Default.Resolving += (context, name) =>
            {
                string? dependency = resolver.ResolveAssemblyToPath(name);
                if (dependency == null)
                {
                    string adjacent = Path.Combine(dllDirectory, name.Name + ".dll");
                    if (File.Exists(adjacent))
                    {
                        dependency = adjacent;
                    }
                }
                return dependency == null ? null : context.LoadFromAssemblyPath(dependency);
            };
            app = AssemblyLoadContext.Default.LoadFromAssemblyPath(dll);
            if (app.GetName().Name != "ProxyBridge")
            {
                throw new InvalidOperationException("Expected the ProxyBridge assembly.");
            }
            // Intentionally never resolve the production guard in this renderer.
            // Dispose may request an observational snapshot; its missing-native
            // status is handled by AppLog. Windows framework DLLs resolve normally.
            NativeLibrary.SetDllImportResolver(app, (name, _, _) =>
            {
                if (name.Equals("ProxyGuard.dll", StringComparison.OrdinalIgnoreCase))
                {
                    throw new DllNotFoundException("Native guard is disabled in the isolated design renderer.");
                }

                return IntPtr.Zero;
            });
            if (verify)
            {
                if (!Path.IsPathFullyQualified(testHostDll!))
                {
                    throw new ArgumentException("--test-host requires an absolute DLL path.");
                }

                testHostDll = Path.GetFullPath(testHostDll!);
                if (!File.Exists(testHostDll))
                {
                    throw new FileNotFoundException("The explicit test-host DLL was not found.", testHostDll);
                }

                var testHost = AssemblyLoadContext.Default.LoadFromAssemblyPath(testHostDll);
                if (testHost.GetName().Name != "ProxyBridge.TestHost")
                {
                    throw new InvalidOperationException("Expected the ProxyBridge.TestHost assembly.");
                }

                var appReference = testHost.GetReferencedAssemblies().Single(reference => reference.Name == "ProxyBridge");
                if (appReference.FullName != app.GetName().FullName)
                {
                    throw new InvalidOperationException("The test host references a different application identity.");
                }

                monitorSuite = testHost.GetType("ProxyBridge.MonitorUiTests", throwOnError: true)!
                    .GetMethod("RunAsync", Static)
                    ?? throw new InvalidOperationException("The test-host monitor suite is missing.");
                // The default load context must bind the host to this exact loaded app.
                // Matching names alone would miss an accidental duplicate MainForm type.
                if (monitorSuite.GetParameters()[0].ParameterType != Type("MainForm"))
                {
                    throw new InvalidOperationException("The test host resolved a different MainForm type.");
                }

                testHostSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(testHostDll)));
            }
            Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            var settingsType = Type("Settings");
            settingsType.GetField("TestDirectory", Static)!.SetValue(null, Path.Combine(output, "settings"));
            var sample = Activator.CreateInstance(settingsType,
                ["192.0.2.10", 8080, "preview-user", "synthetic-preview-only", "http"])!;
            settingsType.GetProperty("ExcludedApplications")!.SetValue(sample,
                new[] { @"C:\Preview Apps\Firefox\firefox.exe", @"C:\Preview Apps\Music\music.exe" });
            settingsType.GetProperty("ExcludedAddresses")!.SetValue(sample,
                new[] { "192.168.1.0/24", "192.168.2.10:8080", "[fd00::/64]:8443" });
            settingsType.GetMethod("Save")!.Invoke(sample, null);

            form = (Form)Activator.CreateInstance(Type("MainForm"), [false, false, true])!;
            var tray = (NotifyIcon)Type("MainForm").GetField("tray", Instance)!.GetValue(form)!;
            tray.Visible = false;
            form.Text += " [СИНТЕТИЧЕСКИЙ ПРЕДПРОСМОТР]";
            form.Shown += async (_, _) =>
            {
                try
                {
                    await Task.Delay(120);
                    await RenderAsync(form, verify,
                        args.Contains("--corners-only", StringComparer.Ordinal),
                        args.Contains("--desktop-corners", StringComparer.Ordinal));
                }
                catch (Exception exception)
                {
                    error = Explain(exception);
                    Check("render", false, error);
                }
                finally
                {
                    try
                    { form.Dispose(); }
                    catch (Exception exception) { Check("dispose-after-render", false, Explain(exception)); }
                    finally { Application.ExitThread(); }
                }
            };
            Application.Run(form);
        }
        catch (Exception exception)
        {
            error = Explain(exception);
            Check("setup", false, error);
        }
        finally
        {
            try
            { form?.Dispose(); }
            catch (Exception exception) { Check("dispose", false, Explain(exception)); }
            if (app != null)
            {
                try
                { ((Task)Type("AppLog").GetMethod("StopAsync", Static)!.Invoke(null, null)!).GetAwaiter().GetResult(); }
                catch (Exception exception) { Check("log-flush", false, Explain(exception)); }
            }
            if (ownsOutput)
            {
                var report = new
                {
                    schemaVersion = 1,
                    status = failures == 0 ? "PASS" : "FAIL",
                    error,
                    sourceAssembly = dll,
                    sourceSha256 = hash,
                    testHostAssembly = verify ? testHostDll : null,
                    testHostSha256,
                    capturedAt = DateTimeOffset.Now,
                    source = "Isolated real WinForms rendering with synthetic settings and observeOnly=true; no live connectivity claim",
                    limitations = new[] {
                        "Does not test proxy connectivity, WFP policy, startup registration, or production mutex behavior",
                        "Only the active monitor DPI and current Windows contrast/motion settings are covered",
                        "Constructor reads Task Scheduler; disposal reads local network diagnostics; native ProxyGuard resolution is blocked",
                        "Hover/press are injected control events, not an end-to-end hardware pointer test",
                        "Paint-only corner tests deliberately omit OnPaintBackground and start with a magenta sentinel buffer",
                        "Desktop corner sampling is opt-in and skipped if the target is not foreground/unobstructed; no pointer movement is performed"
                    },
                    checks = Checks,
                    captures = Captures,
                    cornerEvidence = CornerEvidence
                };
                File.WriteAllText(Path.Combine(output, "preview-report.json"),
                    JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
            }
        }
        Console.WriteLine(failures == 0 ? "PASS: isolated UI render completed" : "FAIL: see preview-report.json");
        return failures == 0 ? 0 : 1;
    }

    static string? Value(string[] args, string name)
    {
        int index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
    static Type Type(string name) => app.GetType("ProxyBridge." + name, throwOnError: true)!;
    static string Explain(Exception error)
    {
        while (error is TargetInvocationException invocation && invocation.InnerException is Exception inner)
        {
            error = inner;
        }

        return error.GetType().Name + ": " + error.Message.Replace("synthetic-preview-only", "***", StringComparison.Ordinal);
    }
    static void Check(string name, bool pass, string detail)
    {
        Checks.Add(new { name, status = pass ? "PASS" : "FAIL", detail });
        if (!pass)
        {
            failures++;
        }
    }
    static void Skip(string name, string detail) => Checks.Add(new { name, status = "SKIP", detail });
    static IEnumerable<Control> Descendants(Control parent)
    {
        foreach (Control control in parent.Controls)
        {
            yield return control;
            foreach (var nested in Descendants(control))
            {
                yield return nested;
            }
        }
    }
    static Control Named(Form form, string name) => Descendants(form).Single(c => c.Name == name);
    static void Call(Form form, string name, params object[] values) => Type("MainForm").GetMethod(name, Instance)!.Invoke(form, values);

    static async Task RenderAsync(Form form, bool verify, bool cornersOnly, bool desktopCorners)
    {
        var status = Named(form, "connectionStatus");
        status.Text = "Предпросмотр интерфейса · подключение не выполнялось";
        Named(form, "startupLog").Text = "14:30:00  Демонстрационный журнал. Сетевые операции отключены.\r\n14:30:01  Настройки примера загружены.";
        Check("masked-password", ((TextBox)Named(form, "password")).UseSystemPasswordChar, "Synthetic password remains masked.");
        Check("activity-disabled", !Named(form, "activityLogging").Enabled && !Named(form, "openActivityLog").Enabled,
            "Observe-only activity controls cannot record or open a viewer.");
        await CornerRegressionAsync(form, desktopCorners);
        if (cornersOnly)
        {
            return;
        }

        foreach (var page in new[] { ("overview", "navOverview"), ("proxy", "navProxy"), ("exclusions", "navExclusions"), ("help", "navHelp") })
        {
            ((Button)Named(form, page.Item2)).PerformClick();
            await Task.Delay(220);
            Check("navigation-" + page.Item1,
                (string?)Type("MainForm").GetProperty("CurrentPage", Instance)!.GetValue(form) == page.Item1,
                "Real navigation button selected the requested page.");
            Capture(form, "ui-" + page.Item1 + ".png");
        }
        await AddressExclusionUiAsync(form);
        Call(form, "NavigateTo", "overview");
        Size full = form.Size;
        form.Size = form.MinimumSize;
        await Task.Delay(180);
        Capture(form, "ui-minimum.png");
        form.Size = full;

        var primary = (Button)Named(form, "connect");
        primary.Focus();
        // UIS_CLEAR | UISF_HIDEFOCUS: expose the genuine keyboard focus cue.
        SendMessage(form.Handle, 0x0127, new IntPtr(2 | (1 << 16)), IntPtr.Zero);
        await Task.Delay(180);
        Capture(form, "ui-focus.png");
        primary.GetType().GetMethod("OnMouseEnter", Instance)!.Invoke(primary, [EventArgs.Empty]);
        await Task.Delay(250);
        Capture(form, "ui-hover.png");
        primary.GetType().GetMethod("OnMouseDown", Instance)!.Invoke(primary,
            [new MouseEventArgs(MouseButtons.Left, 1, primary.Width / 2, primary.Height / 2, 0)]);
        await Task.Delay(180);
        Capture(form, "ui-pressed.png");
        // Never inject MouseUp: it could dispatch a Click. Disabling clears the
        // visual pressed state without executing the button's action.
        primary.Enabled = false;
        await Task.Delay(180);
        Capture(form, "ui-disabled.png");
        primary.Enabled = true;
        primary.GetType().GetMethod("OnMouseLeave", Instance)!.Invoke(primary, [EventArgs.Empty]);

        Call(form, "SetCompactLayout", true);
        Call(form, "NavigateTo", "overview");
        await Task.Delay(220);
        Capture(form, "ui-compact.png");
        form.Size = form.MinimumSize;
        await Task.Delay(180);
        Capture(form, "ui-compact-minimum.png");
        string priorStatus = status.Text;
        try
        {
            // Exercise long recovery copy through the label only. Never call
            // ShowRecovery or any real protection/network operation.
            status.Text = "Тестовый сбой · блокировка подтверждена · исключений: 2 · службе DNS разрешены запросы к настроенным DNS-серверам";
            await Task.Delay(180);
            Size required = TextRenderer.MeasureText(status.Text, status.Font,
                new Size(Math.Max(1, status.ClientSize.Width - status.Padding.Horizontal), int.MaxValue),
                TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl);
            Check("compact-recovery-text-height", required.Height <= status.ClientSize.Height - status.Padding.Vertical,
                $"Long synthetic recovery copy needs {required.Height}px; status label offers {status.ClientSize.Height - status.Padding.Vertical}px.");
            Capture(form, "ui-compact-recovery-long.png");
        }
        finally { status.Text = priorStatus; }
        Call(form, "SetCompactLayout", false);
        Call(form, "NavigateTo", "overview");
        if (verify)
        {
            // The explicitly selected test assembly shares the loaded MainForm type.
            // Its scheduler suite uses only synthetic callbacks and writes captures
            // through this renderer, so all images stay under --out.
            Action<string> capture = name => Capture(form, "verify-" + name);
            var task = (Task)(monitorSuite ?? throw new InvalidOperationException("Test-host suite was not loaded."))
                .Invoke(null, [form, capture])!;
            await task.WaitAsync(TimeSpan.FromSeconds(60));
            Check("synthetic-monitor-suite", true,
                "MonitorUiTests and real window/tray stop/release FIFO checks completed, including repeated retry ticks, awaited cleanup, failures, stale recovery after release and disposal; all operation bodies were synthetic.");
        }
    }

    static async Task AddressExclusionUiAsync(Form form)
    {
        Call(form, "NavigateTo", "exclusions");
        var list = (ListBox)Named(form, "exclusions");
        string[] original = list.Items.Cast<string>().ToArray();
        Check("address-list-load", original.Length == 5 && original.Contains("192.168.1.0/24") &&
            original.Contains("[fd00::/64]:8443"), "Mixed EXE, IPv4 subnet, port and IPv6 settings loaded.");
        Check("address-add-action", Named(form, "addAddressExclusion") is Button,
            "A dedicated address action exists on the exclusions page.");
        Check("address-initial-clean", !Named(form, "unsavedChanges").Visible, "Loading mixed settings is not a pending change.");
        try
        {
            Call(form, "AddAddressExclusion", "198.51.100.77/24:9443");
            Check("address-add-normalized", list.Items.Contains("198.51.100.0/24:9443") && list.Items.Count == 6,
                "Adding an address normalizes its network and retains existing EXE rows.");
            Check("address-add-dirty", Named(form, "unsavedChanges").Visible, "Address edits show unsaved changes.");
            Call(form, "AddAddressExclusion", "198.51.100.99/24:9443");
            Check("address-add-deduplicated", list.Items.Count == 6, "Equivalent subnets do not duplicate a row.");
            var pending = Type("MainForm").GetMethod("ReadSettings", Instance)!.Invoke(form, null)!;
            var settings = Type("Settings");
            Check("address-read-settings", ((string[])settings.GetProperty("ExcludedAddresses")!.GetValue(pending)!).Length == 4 &&
                ((string[])settings.GetProperty("ExcludedApplications")!.GetValue(pending)!).Length == 2,
                "Pending settings keep address and EXE rules in their respective fields.");
            Capture(form, "ui-exclusions-address-pending.png");
            list.SelectedItem = "198.51.100.0/24:9443";
            Call(form, "RemoveSelectedExclusion");
            Check("address-remove-restores-clean", list.Items.Cast<string>().SequenceEqual(original) &&
                !Named(form, "unsavedChanges").Visible, "Removing the pending address restores the saved list and clean state.");

            Size full = form.Size;
            form.Size = form.MinimumSize;
            await Task.Delay(120);
            Capture(form, "ui-exclusions-address-minimum.png");
            form.Size = full;

            using (var dialog = (Form)Activator.CreateInstance(Type("AddressExclusionDialog"))!)
            {
                dialog.Show(form);
                await Task.Delay(80);
                var address = (TextBox)Named(dialog, "exclusionAddress");
                var port = (TextBox)Named(dialog, "exclusionPort");
                var confirm = Type("AddressExclusionDialog").GetMethod("Confirm", Instance)!;
                address.Text = "192.168.1.0/24";
                port.Text = "53";
                confirm.Invoke(dialog, null);
                Check("address-dialog-dns-rejected", dialog.DialogResult != DialogResult.OK &&
                    Named(dialog, "addressExclusionError").Text.Length > 0,
                    "Direct DNS is rejected with an inline error while the dialog stays open.");
                Capture(dialog, "ui-address-dialog-error.png");
                address.Text = "[fd00::1]:443";
                port.Text = "8443";
                confirm.Invoke(dialog, null);
                Check("address-dialog-duplicate-port-rejected", dialog.DialogResult != DialogResult.OK &&
                    Named(dialog, "addressExclusionError").Text.Length > 0, "Conflicting inline and separate ports are rejected.");
                address.Text = "fd00::1234/64";
                port.Text = "8443";
                Capture(dialog, "ui-address-dialog.png");
                confirm.Invoke(dialog, null);
                Check("address-dialog-subnet-and-port", dialog.DialogResult == DialogResult.OK &&
                    (string?)Type("AddressExclusionDialog").GetProperty("Value")!.GetValue(dialog) == "[fd00::/64]:8443",
                    "Separate address and port fields produce the canonical IPv6 subnet rule.");
            }
            using (var dialog = (Form)Activator.CreateInstance(Type("AddressExclusionDialog"))!)
            {
                dialog.Show(form);
                ((TextBox)Named(dialog, "exclusionAddress")).Text = "192.168.1.0/24";
                ((Button)Named(dialog, "cancelAddressExclusion")).PerformClick();
                Check("address-dialog-cancel", dialog.DialogResult == DialogResult.Cancel &&
                    Type("AddressExclusionDialog").GetProperty("Value")!.GetValue(dialog) == null &&
                    list.Items.Cast<string>().SequenceEqual(original), "Cancel creates no rule and preserves the pending list.");
            }
        }
        finally
        {
            list.Items.Clear();
            list.Items.AddRange(original);
            Call(form, "RefreshOverviewSummary");
        }
    }

    static async Task CornerRegressionAsync(Form form, bool desktop)
    {
        if (SystemInformation.HighContrast)
        {
            Skip("corner-regression", "Windows High Contrast intentionally uses rectangular buttons; rounded-corner expectations do not apply.");
            return;
        }
        var buttons = new[] { "navOverview", "navProxy", "navExclusions", "navHelp" }
            .Select(name => (Button)Named(form, name)).ToArray();
        if (!desktop)
        {
            Skip("desktop-corners", "Run with --desktop-corners on an unobstructed test desktop for on-screen pixels; paint-only regression still runs.");
        }

        Call(form, "NavigateTo", "overview");
        for (int cycle = 0; cycle < 12; cycle++)
        {
            var button = buttons[cycle % buttons.Length];
            var next = buttons[(cycle + 1) % buttons.Length];
            next.PerformClick(); // Begin with the tested button unselected.
            await Task.Delay(35);
            button.GetType().GetMethod("OnMouseEnter", Instance)!.Invoke(button, [EventArgs.Empty]);
            await Step("hover", 35);
            button.PerformClick(); // Navigation only: never a connection/action button.
            await Step("selected", 35);
            button.GetType().GetMethod("OnMouseLeave", Instance)!.Invoke(button, [EventArgs.Empty]);
            await Step("leave", 190);
            next.PerformClick();
            await Step("unselected", 35);

            async Task Step(string phase, int delay)
            {
                await Task.Delay(delay);
                // Flush pending normal invalidation only. Do not Refresh the form,
                // call DrawToBitmap, or explicitly erase the background here.
                button.Update();
                next.Update();
                string name = $"corner-{cycle:00}-{phase}";
                if (desktop)
                {
                    CaptureDesktopCorners(form, button, name + "-desktop");
                }
                // Desktop sampling precedes this detached paint-only probe.
                CapturePaintOnlyCorners(form, button, name + "-paint-only");
            }
        }
        Call(form, "NavigateTo", "overview");
    }

    static Color OpaqueParentBackground(Control control)
    {
        for (Control? parent = control.Parent; parent != null; parent = parent.Parent)
        {
            if (parent.BackColor.A == 255)
            {
                return parent.BackColor;
            }
        }

        throw new InvalidOperationException("Corner test requires an opaque ancestor background.");
    }

    static Point[] CornerPoints(Size size)
    {
        var result = new List<Point>();
        foreach (int x in new[] { 0, 1, size.Width - 2, size.Width - 1 })
        {
            foreach (int y in new[] { 0, 1, size.Height - 2, size.Height - 1 })
            {
                result.Add(new Point(x, y));
            }
        }

        return result.ToArray();
    }

    static void CapturePaintOnlyCorners(Form form, Button button, string name)
    {
        int radius = (int)(button.GetType().GetProperty("CornerRadius", Instance)?.GetValue(button) ?? 8);
        if (radius * button.DeviceDpi / 96f < 8 || button.Width < 12 || button.Height < 12)
        {
            Skip(name, "Rounded button is too small for safely exterior 2x2 corner samples.");
            return;
        }
        using var bitmap = new Bitmap(button.ClientSize.Width, button.ClientSize.Height);
        using (var graphics = Graphics.FromImage(bitmap))
        {
            graphics.Clear(Color.Magenta);
            using var paint = new PaintEventArgs(graphics, button.ClientRectangle);
            // Key regression contract: a paint pass must replace stale corner
            // pixels even when the separate background erase was omitted.
            button.GetType().GetMethod("OnPaint", Instance)!.Invoke(button, [paint]);
        }
        EvaluateCorners(form, button, bitmap, name, "OnPaint only; magenta sentinel; no OnPaintBackground or DrawToBitmap", 0);
    }

    static void CaptureDesktopCorners(Form form, Button button, string name)
    {
        Rectangle screenBounds = button.RectangleToScreen(button.ClientRectangle);
        if (!form.Visible || form.WindowState != FormWindowState.Normal || GetForegroundWindow() != form.Handle ||
            !SystemInformation.VirtualScreen.Contains(screenBounds))
        {
            Skip(name, "Target is not a fully on-screen foreground test window; desktop pixels are not trustworthy.");
            return;
        }
        // Check target corners and a dense grid for another window/tooltip before
        // copying only this button's pixels. No screen outside the target is saved.
        var probes = CornerPoints(button.ClientSize).ToList();
        for (int y = 0; y < button.Height; y += 6)
        {
            for (int x = 0; x < button.Width; x += 6)
            {
                probes.Add(new Point(x, y));
            }
        }

        bool Owned(Point point) => GetAncestor(WindowFromPoint(new Point(screenBounds.Left + point.X,
            screenBounds.Top + point.Y)), 2) == form.Handle;
        if (probes.Any(point => !Owned(point)))
        {
            Skip(name, "Target pixels are obscured by another window; no desktop capture saved.");
            return;
        }
        using var bitmap = new Bitmap(button.ClientSize.Width, button.ClientSize.Height);
        try
        {
            using var graphics = Graphics.FromImage(bitmap);
            graphics.CopyFromScreen(screenBounds.Location, Point.Empty, screenBounds.Size, CopyPixelOperation.SourceCopy);
        }
        catch (System.ComponentModel.Win32Exception error)
        {
            Skip(name, "Desktop pixel capture unavailable: " + error.NativeErrorCode);
            return;
        }
        if (GetForegroundWindow() != form.Handle || probes.Any(point => !Owned(point)))
        {
            Skip(name, "Window ownership changed during capture; pixels discarded.");
            return;
        }
        EvaluateCorners(form, button, bitmap, name, "CopyFromScreen after ordinary invalidation; injected hover events; pointer not moved", 2);
    }

    static void EvaluateCorners(Form form, Button button, Bitmap bitmap, string name, string source, int tolerance)
    {
        Color expected = OpaqueParentBackground(button);
        var samples = CornerPoints(bitmap.Size).Select(point =>
        {
            Color actual = bitmap.GetPixel(point.X, point.Y);
            int delta = Math.Max(Math.Abs(actual.R - expected.R), Math.Max(Math.Abs(actual.G - expected.G), Math.Abs(actual.B - expected.B)));
            return new { point.X, point.Y, actual = $"#{actual.R:X2}{actual.G:X2}{actual.B:X2}", delta };
        }).ToArray();
        string file = name + ".png";
        bitmap.Save(Path.Combine(output, file));
        bool pass = samples.All(sample => sample.delta <= tolerance);
        Check(name, pass, $"All 16 exterior-corner pixels match opaque parent #{expected.R:X2}{expected.G:X2}{expected.B:X2}; tolerance {tolerance}, maximum delta {samples.Max(sample => sample.delta)}.");
        CornerEvidence.Add(new
        {
            file,
            source,
            button = button.Name,
            selected = button.GetType().GetProperty("Selected", Instance)?.GetValue(button),
            expected = $"#{expected.R:X2}{expected.G:X2}{expected.B:X2}",
            tolerance,
            samples
        });
        Captures.Add(new
        {
            file,
            source,
            capturedAt = DateTimeOffset.Now,
            width = bitmap.Width,
            height = bitmap.Height,
            dpi = button.DeviceDpi,
            page = Type("MainForm").GetProperty("CurrentPage", Instance)!.GetValue(form),
            compact = false,
            controls = Array.Empty<object>()
        });
    }

    static void Capture(Form form, string name)
    {
        form.PerformLayout();
        form.Refresh();
        using var bitmap = new Bitmap(form.Width, form.Height);
        form.DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size));
        bitmap.Save(Path.Combine(output, name));
        var visible = Descendants(form).Where(control => control.Visible).ToArray();
        var buttons = visible.OfType<Button>().ToArray();
        foreach (var button in buttons)
        {
            string checkName = name + ":" + button.Name;
            Check(checkName + ":nonzero-bounds", button.Width > 0 && button.Height > 0,
                "Visible button has nonzero dimensions.");
            var screenBounds = button.RectangleToScreen(button.ClientRectangle);
            bool clipped = false, scrollClipped = false;
            string clippingParent = "";
            for (Control? ancestor = button.Parent; ancestor != null; ancestor = ancestor.Parent)
            {
                var localBounds = ancestor.RectangleToClient(screenBounds);
                if (ancestor.ClientRectangle.Contains(localBounds))
                {
                    continue;
                }

                clippingParent = ancestor.Name.Length == 0 ? ancestor.GetType().Name : ancestor.Name;
                scrollClipped = ancestor is ScrollableControl { AutoScroll: true };
                clipped = !scrollClipped;
                // A deliberate scroll viewport may clip offscreen content, but
                // does not exempt clipping by a nearer non-scroll container.
                break;
            }
            if (scrollClipped)
            {
                Checks.Add(new
                {
                    name = checkName + ":ancestor-bounds",
                    status = "SKIP",
                    detail = "Content extends beyond the scroll viewport: " + clippingParent
                });
            }
            else
            {
                Check(checkName + ":ancestor-bounds", !clipped,
                    clipped ? "Button is clipped by ancestor: " + clippingParent : "Button fits every ancestor client rectangle.");
            }
            // These multiline actions retain normal Button sizing semantics;
            // navigation has custom icon/marker insets, so this API is not a
            // reliable text measurement for navigation and is not used there.
            if (button.Name is "block" or "release")
            {
                Size preferred = button.GetPreferredSize(new Size(button.Width, 0));
                Check(checkName + ":text-height", preferred.Height <= button.Height,
                    $"Required button height {preferred.Height}; available {button.Height}.");
            }
        }
        var journal = visible.SingleOrDefault(control => control.Name == "startupLog");
        if (journal != null)
        {
            Check(name + ":journal-readable-height", journal.ClientSize.Height >= journal.Font.Height * 3,
                $"Journal shows at least three lines: available {journal.ClientSize.Height}, required {journal.Font.Height * 3}.");
        }

        Captures.Add(new
        {
            file = name,
            capturedAt = DateTimeOffset.Now,
            width = form.Width,
            height = form.Height,
            dpi = form.DeviceDpi,
            page = form.GetType() == Type("MainForm") ? Type("MainForm").GetProperty("CurrentPage", Instance)!.GetValue(form) : form.Name,
            compact = form.GetType() == Type("MainForm") && (bool)Type("MainForm").GetProperty("IsCompact", Instance)!.GetValue(form)!,
            controls = visible.Select(control => new
            {
                name = control.Name,
                type = control.GetType().Name,
                bounds = new { control.Left, control.Top, control.Width, control.Height },
                control.Enabled,
                control.Focused,
                // Do not serialize field contents, even though this run uses only sample data.
                text = control is TextBoxBase ? "[field contents omitted]" : control.Text
            }).ToArray()
        });
    }
}
