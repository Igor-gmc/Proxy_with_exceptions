namespace ProxyBridge;

// Explicit diagnostic entry point. The shipping application never loads this host.
internal static class TestHostProgram
{
    static readonly string[] TestCommands = ["--bundle-test", "--self-test", "--ui-test"];

    [STAThread]
    static int Main(string[] args)
    {
        // Engine shutdown launches its own executable as this private helper.
        // It must not acquire the mutex already held by the diagnostic parent.
        if (EngineControlCommand.TryRun(args, out int helperExitCode))
        {
            return helperExitCode;
        }

        string report = ReportName(args);
        if (!TryGetCommand(args, out string command, out string error))
        {
            WriteFailure(report, error);
            return 1;
        }

        using var mutex = new Mutex(true, Program.InstanceMutexName, out bool first);
        if (!first)
        {
            WriteFailure(report, "ProxyBridge is already running; test refused without touching the active session.");
            return 1;
        }

        Environment.ExitCode = 0;
        string? previousDirectory = Settings.TestDirectory;
        try
        {
            // Matches the shipping project's default WinForms bootstrap. No custom
            // ApplicationDefaultFont or DPI properties are set in that project.
            Application.SetHighDpiMode(HighDpiMode.SystemAware);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            string prefix = command == "--ui-test" ? "uitest-data-" : "selftest-data-";
            Settings.TestDirectory = Path.Combine(AppContext.BaseDirectory, prefix + Environment.ProcessId);
            if (Directory.Exists(Settings.TestDirectory))
            {
                throw new IOException("The isolated test data directory already exists.");
            }

            BundledAssets.Prepare();
            switch (command)
            {
                case "--bundle-test":
                    VerifyBundle();
                    break;
                case "--self-test":
                    SelfTest.Run().GetAwaiter().GetResult();
                    break;
                case "--ui-test":
                    UiTestSuite.Run(args.Contains("--startup", StringComparer.Ordinal));
                    break;
            }
        }
        catch (Exception errorDuringTest)
        {
            // Failures may include configuration text. Persist only the exception type.
            WriteFailure(report, "Test host failed (" + errorDuringTest.GetType().Name + ").");
        }
        finally
        {
            try
            { AppLog.StopAsync().GetAwaiter().GetResult(); }
            catch (Exception shutdownError)
            {
                WriteFailure(report, "Test log shutdown failed (" + shutdownError.GetType().Name + ").");
            }
            Settings.TestDirectory = previousDirectory;
        }
        return Environment.ExitCode;
    }

    static bool TryGetCommand(string[] args, out string command, out string error)
    {
        command = "";
        error = "Usage: ProxyBridge.TestHost.exe --bundle-test | --self-test | --ui-test [--startup]";
        if (args.Contains("--network-test", StringComparer.Ordinal) ||
            args.Contains("--test-watchdog", StringComparer.Ordinal))
        {
            error = "Network testing is disabled until test-owned recovery is implemented.";
            return false;
        }
        if (args.Length is < 1 or > 2 || !TestCommands.Contains(args[0], StringComparer.Ordinal))
        {
            return false;
        }

        if (args.Length == 2 && (args[0] != "--ui-test" || args[1] != "--startup"))
        {
            return false;
        }

        command = args[0];
        return true;
    }

    static string ReportName(string[] args)
    {
        foreach (string candidate in TestCommands.Append("--network-test"))
        {
            if (args.Contains(candidate, StringComparer.Ordinal))
            {
                return candidate[2..] + ".txt";
            }
        }

        return "test-host.txt";
    }

    internal static void WriteFailure(string reportName, string message)
    {
        Environment.ExitCode = 1;
        File.WriteAllText(Path.Combine(AppContext.BaseDirectory, reportName), "FAIL: " + message);
    }

    static void VerifyBundle()
    {
        string[] required = ["ProxyGuard.dll", "core/sing-box.exe", "core/wintun.dll", "README.txt",
            "HELP.txt", "core/TRACEEVENT-LICENSE.txt", "core/DOTNET-LICENSE.txt"];
        foreach (string name in required)
        {
            if (!File.Exists(Path.Combine(BundledAssets.DirectoryPath, name)))
            {
                throw new IOException("Missing payload component.");
            }
        }

        File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "bundle-test.txt"),
            "PASS: embedded components extracted and verified; WFP filter count=" + Guard.Status);
    }
}
