using System.Text.Json;

namespace ProxyBridge;

// Shared by isolated test hosts only; never compiled into the shipping application.
internal static class SettingsTests
{
    static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Assertion failed");
        }
    }
    static void Reject(Action action)
    {
        try
        { action(); }
        catch (ArgumentException) { return; }
        throw new InvalidOperationException("Invalid input accepted");
    }
    // A deliberately narrow entry point for a separate settings-only test host.
    // It performs local settings I/O only: no Program.Main, engine or WFP calls.
    internal static async Task RunInitialAsync(Func<string, Func<Task>, Task> test)
    {
        async Task Isolated(string name, Action check)
        {
            await test(name, () =>
            {
                string original = Settings.TestDirectory ?? throw new InvalidOperationException("Settings tests require an isolated test directory");
                Settings.TestDirectory = Path.Combine(original, Guid.NewGuid().ToString("N"));
                try
                { check(); }
                finally { Settings.TestDirectory = original; }
                return Task.CompletedTask;
            });
        }
        await Isolated("first-run defaults contain no endpoint, credentials or exclusions", () =>
        {
            var defaults = Settings.Default;
            Require(defaults.Host == "" && defaults.Username == "" && defaults.Password == "");
            Require(defaults.ExcludedApplications.Length == 0);
            Require(defaults.Port is >= 1 and <= 65535 && (defaults.Protocol is "http" or "socks"));
            Require(!Directory.Exists(Settings.DataDir));
        });
        await Isolated("loading missing settings returns setup state without persisting a configuration", () =>
        {
            Require(!Directory.Exists(Settings.DataDir));
            var loaded = Settings.Load();
            Require(loaded.Host == "" && loaded.Username == "" && loaded.Password == "");
            Require(loaded.ExcludedApplications.Length == 0);
            Require(loaded.Port == Settings.Default.Port && loaded.Protocol == Settings.Default.Protocol);
            Require(!File.Exists(Path.Combine(Settings.DataDir, "settings.dat")));
            Require(!File.Exists(Path.Combine(Settings.DataDir, "settings.dat.tmp")));
            Reject(loaded.Validate);
        });
        await Isolated("unconfigured defaults reject validation and save without creating settings files", () =>
        {
            var defaults = Settings.Default;
            Reject(defaults.Validate);
            Reject(defaults.Save);
            Require(!File.Exists(Path.Combine(Settings.DataDir, "settings.dat")));
            Require(!File.Exists(Path.Combine(Settings.DataDir, "settings.dat.tmp")));
        });
    }
    internal static async Task RunAsync(Func<string, Func<Task>, Task> Test)
    {
        const string testPassword = "QA-only-secret-42";
        var s = new Settings("192.0.2.10", 1080, "qa-user", testPassword, "http");
        string app = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        var excluded = s with { ExcludedApplications = [app] };
        var multiple = s with { ExcludedApplications = [@"C:\Program Files\Mozilla Firefox\firefox.exe", @"C:\Users\Тест\AppData\Local\Yandex Music\Яндекс Музыка.exe"] };
        async Task SettingsTest(string name, Action test)
        {
            await Test(name, () =>
            {
                string original = Settings.TestDirectory ?? throw new InvalidOperationException("Settings tests require an isolated test directory");
                Settings.TestDirectory = Path.Combine(original, Guid.NewGuid().ToString("N"));
                try
                { test(); }
                finally { Settings.TestDirectory = original; }
                return Task.CompletedTask;
            });
        }
        await RunInitialAsync(Test);
        await SettingsTest("DPAPI storage roundtrip preserves Unicode exclusions and encrypts credentials", () =>
        {
            multiple.Save();
            var loaded = Settings.Load();
            Require(loaded.Host == multiple.Host && loaded.Port == multiple.Port && loaded.Protocol == multiple.Protocol);
            Require(loaded.Username == multiple.Username && loaded.Password == multiple.Password);
            Require(loaded.ExcludedApplications.SequenceEqual(multiple.ExcludedApplications));
            byte[] bytes = File.ReadAllBytes(Path.Combine(Settings.DataDir, "settings.dat"));
            Require(!System.Text.Encoding.UTF8.GetString(bytes).Contains(s.Password, StringComparison.Ordinal));
            Require(!File.Exists(Path.Combine(Settings.DataDir, "settings.dat.tmp")));
        });
        await SettingsTest("corrupt DPAPI settings fail visibly and remain intact until explicit save", () =>
        {
            Settings.PrepareDirectory();
            string path = Path.Combine(Settings.DataDir, "settings.dat");
            byte[] corrupt = [0, 1, 2, 3, 4, 5];
            File.WriteAllBytes(path, corrupt);
            bool rejected = false;
            try
            { _ = Settings.Load(); }
            catch (System.ComponentModel.Win32Exception) { rejected = true; }
            Require(rejected && File.ReadAllBytes(path).SequenceEqual(corrupt));
            multiple.Save();
            Require(Settings.Load().ExcludedApplications.SequenceEqual(multiple.ExcludedApplications));
        });
        await SettingsTest("failed settings replacement preserves last saved data; retry succeeds", () =>
        {
            s.Save();
            string path = Path.Combine(Settings.DataDir, "settings.dat");
            byte[] before = File.ReadAllBytes(path);
            bool rejected = false;
            using (var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                try
                { multiple.Save(); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { rejected = true; }
            }
            Require(rejected && File.ReadAllBytes(path).SequenceEqual(before));
            Require(Settings.Load().ExcludedApplications.Length == 0);
            multiple.Save();
            Require(Settings.Load().ExcludedApplications.SequenceEqual(multiple.ExcludedApplications));
            Require(!File.Exists(path + ".tmp"));
        });
        await SettingsTest("settings test directories isolate persisted state", () =>
        {
            s.Save();
            string first = Settings.TestDirectory!;
            Settings.TestDirectory = Path.Combine(first, "second");
            Require(Settings.Load().ExcludedApplications.Length == 0);
            multiple.Save();
            Settings.TestDirectory = first;
            Require(Settings.Load().ExcludedApplications.Length == 0);
        });
        await Test("legacy settings default to empty exclusions; JSON roundtrip preserves paths", () =>
        {
            string legacy = JsonSerializer.Serialize(new { s.Host, s.Port, s.Username, s.Password, s.Protocol });
            var loaded = JsonSerializer.Deserialize<Settings>(legacy)!;
            loaded.Validate();
            Require(loaded.ExcludedApplications.Length == 0);
            var roundtrip = JsonSerializer.Deserialize<Settings>(JsonSerializer.Serialize(excluded))!;
            roundtrip.Validate();
            Require(roundtrip.ExcludedApplications.SequenceEqual(excluded.ExcludedApplications));
            return Task.CompletedTask;
        });
        await Test("invalid endpoints/exclusions rejected; paths normalized and deduplicated", () =>
        {
            foreach (var invalid in new[] { s with { Host = "localhost" }, s with { Host = "::1" }, s with { Port = 0 }, s with { Port = 65536 }, s with { Protocol = "direct" } })
            {
                Reject(invalid.Validate);
            }

            foreach (string bad in new[] { "", "firefox.exe", @"C:firefox.exe", @"C:\Apps\firefox.dll", Engine.Executable, Environment.ProcessPath!, @"C:\Other\ProxyBridge.exe" })
            {
                Reject(() => (s with { ExcludedApplications = [bad] }).Validate());
            }

            Reject(() => (s with { ExcludedApplications = null! }).Validate());
            Reject(() => (s with { ExcludedApplications = Enumerable.Range(0, 65).Select(i => $@"C:\Apps\App{i}.exe").ToArray() }).Validate());
            var normalized = s with { ExcludedApplications = [app, app.ToUpperInvariant(), Path.Combine(Path.GetDirectoryName(app)!, ".", "notepad.exe")] };
            Require(normalized.ExcludedApplications.Length == 1);
            return Task.CompletedTask;
        });
    }
}
