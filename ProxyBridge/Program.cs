using System.Runtime.InteropServices;

namespace ProxyBridge;

internal static class Program
{
    internal const string InstanceMutexName = @"Global\ProxyBridge-8CBA1041";

    [STAThread]
    private static void Main(string[] args)
    {
        // The short-lived signal helper must not acquire the application mutex.
        if (EngineControlCommand.TryRun(args, out int controlExitCode))
        {
            Environment.ExitCode = controlExitCode;
            return;
        }

        ApplicationCommand command = ApplicationCommandParser.Parse(args);
        if (command.Mode == ApplicationMode.TestUnavailable)
        {
            RejectLegacyTest(command);
            return;
        }

        ApplicationConfiguration.Initialize();
        if (command.Mode == ApplicationMode.Invalid)
        {
            Environment.ExitCode = 2;
            ShowError(command.Error!);
            return;
        }

        using var instanceMutex = new Mutex(true, InstanceMutexName, out bool firstInstance);
        if (!firstInstance)
        {
            MessageBox.Show("ProxyBridge уже запущен. Откройте его через значок в трее.");
            return;
        }

        RunApplication(command);
    }

    private static void RunApplication(ApplicationCommand command)
    {
        RegisterExceptionLogging();
        LogStartup(command.Startup);

        try
        {
            BundledAssets.Prepare();
            DiagnosticJournal.Start();
            AppLog.Write($"COMPONENTS payload={Path.GetFileName(BundledAssets.DirectoryPath)}; " +
                "sing-box=1.14.4; guardABI=V4; engineLog=warn; networkSnapshots=local-read-only");
            AppLog.Snapshot("application.startup");

            if (command.Mode == ApplicationMode.Recover)
            {
                RecoverInternet();
                return;
            }

            Application.Run(new MainForm(startup: command.Startup));
        }
        catch (Exception error)
        {
            Environment.ExitCode = 1;
            AppLog.Error("Main", error);
            ShowError(AppLog.Redact(error.Message));
        }
        finally
        {
            AppLog.Write($"END ProxyBridge; exitCode={Environment.ExitCode}");
            try
            {
                DiagnosticJournal.StopAsync().GetAwaiter().GetResult();
            }
            finally
            {
                AppLog.StopAsync().GetAwaiter().GetResult();
            }
        }
    }

    private static void RecoverInternet()
    {
        AppLog.Write("USER: recovery requested");
        Guard.Remove();
        MessageBox.Show("Блокировка ProxyBridge снята. Обычный доступ в интернет восстановлен.");
    }

    private static void LogStartup(bool startup)
    {
        AppLog.Write($"START ProxyBridge {AppVersion.Display}; Windows {Environment.OSVersion.Version}; startup={startup}");
        AppLog.Write($"BUILD mvid={typeof(Program).Module.ModuleVersionId}; " +
            $"runtime={RuntimeInformation.FrameworkDescription}; " +
            $"architecture={RuntimeInformation.ProcessArchitecture}; diagnosticSchema=2");
    }

    private static void RegisterExceptionLogging()
    {
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception error)
            {
                AppLog.Error("Unhandled exception", error);
            }
            else
            {
                AppLog.Write("ERROR Unhandled non-Exception failure");
            }
        };
        TaskScheduler.UnobservedTaskException += (_, args) =>
            AppLog.Error("Unobserved task exception", args.Exception);
    }

    private static void RejectLegacyTest(ApplicationCommand command)
    {
        Environment.ExitCode = 1;
        if (command.TestReportName == null)
        {
            return;
        }

        try
        {
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, command.TestReportName), "FAIL: " + command.Error);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // Refusal must remain headless and must not fall through to normal startup.
        }
    }

    private static void ShowError(string message) =>
        MessageBox.Show(message, "ProxyBridge", MessageBoxButtons.OK, MessageBoxIcon.Error);
}
