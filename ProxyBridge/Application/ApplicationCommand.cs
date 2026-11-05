namespace ProxyBridge;

internal enum ApplicationMode
{
    Run,
    Recover,
    TestUnavailable,
    Invalid
}

internal sealed record ApplicationCommand(
    ApplicationMode Mode,
    bool Startup = false,
    string? TestReportName = null,
    string? Error = null);

/// <summary>Parses user-facing commands without loading settings or touching the network.</summary>
internal static class ApplicationCommandParser
{
    public static ApplicationCommand Parse(string[] args)
    {
        // Legacy test commands must never accidentally start the real application.
        // The separate test host owns their implementation and isolated data.
        string? testCommand = args.FirstOrDefault(argument =>
            argument.EndsWith("-test", StringComparison.Ordinal) || argument == "--test-watchdog");
        if (testCommand != null)
        {
            string? report = testCommand switch
            {
                "--bundle-test" => "bundle-test.txt",
                "--self-test" => "self-test.txt",
                "--ui-test" => "ui-test.txt",
                "--network-test" => "network-test.txt",
                _ => null
            };
            return new ApplicationCommand(ApplicationMode.TestUnavailable, TestReportName: report,
                Error: "Тесты вынесены в ProxyBridge.TestHost.exe. См. tests/README.md. Сетевой тест отключён.");
        }

        return args switch
        {
            [] => new ApplicationCommand(ApplicationMode.Run),
            ["--startup"] => new ApplicationCommand(ApplicationMode.Run, Startup: true),
            ["--recover"] => new ApplicationCommand(ApplicationMode.Recover),
            _ => new ApplicationCommand(ApplicationMode.Invalid,
                Error: "Допустимы запуск без аргументов, --startup или --recover.")
        };
    }
}
