namespace ProxyBridge;

// Compatibility suite owned by the explicit test host. Windows-dependent checks
// stay here; Core.Tests runs its pure suites without payload preparation or WFP.
internal static class SelfTest
{
    internal static async Task Run()
    {
        const string testPassword = "QA-only-secret-42";
        var results = new List<string>();
        string output = Path.Combine(AppContext.BaseDirectory, "self-test.txt");
        void Record(string text)
        {
            results.Add(text);
            File.WriteAllLines(output, results);
        }
        async Task Test(string name, Func<Task> action)
        {
            try
            {
                await action();
                Record("PASS: " + name);
            }
            catch (Exception error)
            {
                string message = AppLog.Redact(error.Message, testPassword);
                Record("FAIL: " + name + " (" + error.GetType().Name + "): " + message);
                Environment.ExitCode = 1;
            }
        }

        var settings = new Settings("192.0.2.10", 1080, "qa-user", testPassword, "http");
        string application = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        var excluded = settings with { ExcludedApplications = [application] };
        var multiple = settings with { ExcludedApplications = [@"C:\Program Files\Mozilla Firefox\firefox.exe", @"C:\Users\Тест\AppData\Local\Yandex Music\Яндекс Музыка.exe"] };
        await SettingsTests.RunAsync(Test);
        await TunReadinessTests.RunAsync(Test);
        await ProtectionControllerTests.RunAsync(Test, settings);
        await ConnectionProbeTests.RunAsync(Test);
        await DiagnosticSelfTests.RunAsync(Test, settings);
        await EngineSelfTests.RunAsync(Test, settings, multiple);
        await StartupSelfTests.RunAsync(Test);
        await ProxySpeedTests.RunAsync(Test);
        await GuardDryRunTests.RunAsync(Test, Record, settings, excluded, application);
        Record("SKIP: real routing, crash/existing flows, DNS/IPv6/UDP, logon and throughput require coordinator-run integration; dry runs do not establish network isolation");
    }
}
