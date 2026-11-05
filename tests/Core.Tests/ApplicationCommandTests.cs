namespace ProxyBridge;

internal static class ApplicationCommandTests
{
    static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Application command invariant failed.");
        }
    }

    internal static async Task RunAsync(Func<string, Func<Task>, Task> test)
    {
        await test("CLI: default, startup and explicit recovery retain their operational modes", () =>
        {
            Require(ApplicationCommandParser.Parse([]) == new ApplicationCommand(ApplicationMode.Run));
            Require(ApplicationCommandParser.Parse(["--startup"]) == new ApplicationCommand(ApplicationMode.Run, Startup: true));
            Require(ApplicationCommandParser.Parse(["--recover"]) == new ApplicationCommand(ApplicationMode.Recover));
            return Task.CompletedTask;
        });
        await test("CLI: unknown, repeated and mixed operational flags cannot start or recover", () =>
        {
            string[][] invalid = [["--unknown"], ["--startup", "--startup"], ["--recover", "--recover"],
                ["--startup", "--recover"], ["--recover", "--startup"], ["--startup", "extra"],
                ["--STARTUP"], [""], ["--signal-engine"]];
            foreach (var args in invalid)
            {
                var command = ApplicationCommandParser.Parse(args);
                Require(command.Mode == ApplicationMode.Invalid && !command.Startup);
                Require(command.TestReportName == null && !string.IsNullOrWhiteSpace(command.Error));
            }
            return Task.CompletedTask;
        });
        await test("CLI: legacy tests refuse production startup and use only fixed report names", () =>
        {
            foreach (var sample in new[] { ("--bundle-test", "bundle-test.txt"), ("--self-test", "self-test.txt"),
                ("--ui-test", "ui-test.txt"), ("--network-test", "network-test.txt") })
            {
                foreach (string[] args in new[] { new[] { sample.Item1 }, new[] { sample.Item1, "--startup" },
                    new[] { "--recover", sample.Item1 } })
                {
                    var command = ApplicationCommandParser.Parse(args);
                    Require(command.Mode == ApplicationMode.TestUnavailable && !command.Startup);
                    Require(command.TestReportName == sample.Item2 && !string.IsNullOrWhiteSpace(command.Error));
                }
            }
            return Task.CompletedTask;
        });
        await test("CLI: watchdog and arbitrary test-looking paths cannot choose output files", () =>
        {
            foreach (string argument in new[] { "--test-watchdog", "--unknown-test", "../outside-test", @"..\outside-test" })
            {
                var command = ApplicationCommandParser.Parse([argument]);
                Require(command.Mode == ApplicationMode.TestUnavailable && !command.Startup);
                Require(command.TestReportName == null && !string.IsNullOrWhiteSpace(command.Error));
            }
            return Task.CompletedTask;
        });
    }
}
