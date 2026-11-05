namespace ProxyBridge;

// All external actions are fakes. Tests exercise the production controller used
// by MainForm; they never touch WFP, a TUN, user settings or a real process.
internal static class ProtectionControllerTests
{
    static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
    static bool Contains(IEnumerable<Exception> errors, Exception expected) => errors.Any(error =>
        ReferenceEquals(error, expected) || error.InnerException != null && Contains([error.InnerException], expected));
    static void RecoveryWasAttempted(Fixture f, bool settingsUsable = true)
    {
        int deactivate = f.Calls.IndexOf("Deactivate"), stop = f.Calls.IndexOf("Stop");
        Require(deactivate >= 0 && stop > deactivate, "Deactivate and Stop must both be attempted, in that order");
        if (settingsUsable)
        {
            int configure = f.Calls.IndexOf("Configure:0"), matches = f.Calls.IndexOf("Matches:0");
            Require(configure > deactivate && stop > configure && matches > stop, "Recovery skipped or reordered an independent stage");
        }
        Require(!f.Calls.Contains("Remove"), "Recovery must not release protection");
    }

    public static async Task RunAsync(Func<string, Func<Task>, Task> test, Settings settings)
    {
        await test("lifecycle: observed filters preserve intent but do not prove policy or connection", () =>
        {
            var f = new Fixture(settings);
            f.Controller.ObserveStartup(1, true);
            Require(f.Controller.ProtectionRequired && !f.Controller.ConnectWanted, "Observed policy must retain protection intent");
            Require(!f.Controller.IsExpectedPolicy() && !f.Controller.IsConnectedCandidate(), "A nonzero count is not a verified policy");
            f.Controller.ObserveStartup(0, true);
            Require(f.Controller.ProtectionRequired, "Later zero count must not erase protection intent");
            Require(!f.Calls.Any(c => c.StartsWith("Configure:") || c == "Remove"), "Startup observation mutated policy");
            return Task.CompletedTask;
        });
        await test("lifecycle: successful Block revokes active permits and verifies stopped protection", async () =>
        {
            var f = new Fixture(settings);
            f.ArmActive();
            f.Controller.RequestBlock();
            var result = await f.Controller.RearmAsync();
            RecoveryWasAttempted(f);
            Require(result.Succeeded && result.PolicyVerified && result.EngineStopped && !result.Released, "Verified Block did not succeed");
            Require(f.Controller.ProtectionRequired && !f.Controller.ConnectWanted && f.Controller.ActiveLuid == 0, "Block lost persistent intent or retained active state");
            Require(f.Controller.IsExpectedPolicy() && !f.Controller.IsConnectedCandidate(), "Blocked monitoring must verify policy without claiming connection");
        });
        await test("lifecycle: each recovery stage failure preserves errors and still attempts later stages", async () =>
        {
            foreach (string stage in new[] { "Deactivate", "Configure", "Stop", "Matches" })
            {
                var f = new Fixture(settings);
                f.ArmActive();
                f.Controller.RequestBlock();
                if (stage == "Stop")
                {
                    f.Running = false; // Process can be gone while job cleanup still fails.
                }

                var failure = f.FailNext(stage);
                var result = await f.Controller.RearmAsync();
                RecoveryWasAttempted(f);
                Require(!result.Succeeded && !result.Released && Contains(result.Errors, failure), "A recovery error disappeared or became success: " + stage);
                Require(f.Controller.ProtectionRequired && !f.Controller.ConnectWanted, "Failed Block lost protection intent");
                if (stage == "Stop")
                {
                    Require(result.PolicyVerified && !f.Controller.EngineStopConfirmed, "Running=false or valid policy falsely confirmed failed cleanup");
                    f.Calls.Clear();
                    result = await f.Controller.RearmAsync();
                    Require(f.Calls.Contains("Stop") && result.Succeeded && f.Controller.EngineStopConfirmed, "Failed engine cleanup was not retried");
                }
            }
        });
        await test("lifecycle: simultaneous deactivate/configure/stop/verify faults are all retained", async () =>
        {
            var f = new Fixture(settings);
            f.ArmActive();
            f.Controller.RequestBlock();
            var failures = new[] { "Deactivate", "Configure", "Stop", "Matches" }.Select(f.FailNext).ToArray();
            var result = await f.Controller.RearmAsync();
            RecoveryWasAttempted(f);
            Require(!result.Succeeded && failures.All(e => Contains(result.Errors, e)), "Combined recovery hid one or more stage failures");
            Require(f.Controller.ProtectionRequired, "Combined failures must not authorize release");
        });
        await test("lifecycle: original connection failure survives successful blocked recovery", async () =>
        {
            var f = new Fixture(settings);
            f.ArmActive();
            var cause = new IOException("synthetic probe failure");
            var result = await f.Controller.RearmAsync(cause);
            Require(result.PolicyVerified && result.EngineStopped && !result.Succeeded && Contains(result.Errors, cause), "Recovery hid the original connection failure");
            Require(f.Controller.ConnectWanted && f.Controller.ProtectionRequired, "Recovery unexpectedly cancelled connection retry intent");
            Require(f.Controller.ActiveLuid == 0 && !f.Controller.IsConnectedCandidate(), "Blocked recovery retained a connected claim");
        });
        await test("lifecycle: unmatched policy prevents Block success even with nonzero filter count", async () =>
        {
            var f = new Fixture(settings);
            f.ArmActive();
            f.Controller.RequestBlock();
            f.ForceMismatch = true;
            var result = await f.Controller.RearmAsync();
            Require(f.BasePresent && !result.PolicyVerified && !result.Succeeded && result.Errors.Count > 0, "Count or successful Configure replaced exact verification");
            Require(f.Controller.ProtectionRequired, "Mismatch discarded protection intent");
        });
        await test("lifecycle: unusable settings still revoke active permits and stop without applying defaults", async () =>
        {
            var f = new Fixture(settings);
            f.ArmActive();
            f.Controller.ObserveStartup(1, false);
            var result = await f.Controller.RearmAsync();
            RecoveryWasAttempted(f, settingsUsable: false);
            Require(!f.Calls.Any(c => c.StartsWith("Configure:") || c.StartsWith("Matches:")), "Unusable settings were applied or treated as verified");
            Require(result.EngineStopped && !result.PolicyVerified && !result.Succeeded && f.Controller.ProtectionRequired, "Unknown settings became safe-to-release state");
            bool invalidRejected = false;
            try
            { f.Controller.UseSettings(settings with { Port = 0 }); }
            catch (ArgumentException) { invalidRejected = true; }
            Require(invalidRejected && !f.Controller.SettingsUsable, "Invalid settings enabled policy writes");
            f.Controller.UseSettings(settings);
            result = await f.Controller.RearmAsync();
            Require(f.Controller.SettingsUsable && result.Succeeded, "Valid replacement settings did not allow recovery");
        });
        await test("lifecycle: explicit successful Release clears intent and exit does not rearm", async () =>
        {
            var f = new Fixture(settings);
            f.ArmActive();
            var result = await f.Controller.ReleaseAsync();
            Require(result.Succeeded && result.Released && !f.Controller.ProtectionRequired && !f.Controller.ConnectWanted && f.Controller.ActiveLuid == 0, "Successful Release retained protection intent");
            Require(f.Calls.IndexOf("Stop") < f.Calls.IndexOf("Remove") && f.Calls.IndexOf("Remove") < f.Calls.IndexOf("Count"), "Release removed policy before stopping or omitted confirmation");
            f.Calls.Clear();
            result = await f.Controller.PrepareExitAsync();
            Require(result.Succeeded && result.Released && !f.Controller.ProtectionRequired, "Released exit changed protection intent");
            Require(!f.Calls.Any(c => c.StartsWith("Configure:") || c == "Remove"), "Exit silently rearmed a successfully released session");
        });
        await test("lifecycle: failed Release deactivate/stop/remove/status stages recover sticky protection", async () =>
        {
            foreach (string stage in new[] { "Deactivate", "Stop", "Remove", "Count" })
            {
                var f = new Fixture(settings);
                f.ArmActive();
                var failure = f.FailNext(stage);
                var result = await f.Controller.ReleaseAsync();
                Require(!result.Succeeded && !result.Released && Contains(result.Errors, failure), "Release error became success: " + stage);
                Require(f.Controller.ProtectionRequired && !f.Controller.ConnectWanted && result.PolicyVerified && result.EngineStopped, "Failed Release did not recover prior required protection");
                Require(f.Calls.Contains("Deactivate") && f.Calls.Contains("Configure:0") && f.Calls.Contains("Matches:0"), "Failed Release skipped required recovery");
                if (stage is "Deactivate" or "Stop")
                {
                    Require(!f.Calls.Contains("Remove"), "Release removed policy despite unsuccessful deactivation or stop");
                }
            }
        });
        await test("lifecycle: Remove returning without removing filters cannot claim restored internet", async () =>
        {
            var f = new Fixture(settings);
            f.ArmActive();
            f.RemoveNoEffect = true;
            var result = await f.Controller.ReleaseAsync();
            Require(!result.Succeeded && !result.Released && result.Errors.Count > 0 && f.Controller.ProtectionRequired, "Residual filters were reported as successful Release");
            Require(f.Calls.Contains("Configure:0") && result.PolicyVerified, "Residual filters did not trigger recovery");
        });
        await test("lifecycle: exit preserves required protection despite missing or unreadable filters", async () =>
        {
            var f = new Fixture(settings);
            f.Controller.RequestBlock();
            var result = await f.Controller.PrepareExitAsync();
            Require(result.Succeeded && result.PolicyVerified && f.Controller.ProtectionRequired && f.BasePresent, "Zero observed filters erased required intent during exit");
            f = new Fixture(settings);
            var failure = f.FailNext("Count");
            result = await f.Controller.PrepareExitAsync();
            Require(!result.Succeeded && Contains(result.Errors, failure) && result.PolicyVerified && f.Controller.ProtectionRequired, "Unknown filter state silently permitted unprotected exit");
        });
        await test("lifecycle: connected candidate requires active policy, running engine and exact match", () =>
        {
            var f = new Fixture(settings);
            f.Controller.RequestConnect();
            Require(!f.Controller.IsConnectedCandidate(), "Intent alone claimed a connected candidate");
            f.Controller.ConfigureActive(0x10000);
            Require(f.Controller.IsConnectedCandidate(), "Verified active fixture rejected");
            f.Running = false;
            Require(!f.Controller.IsConnectedCandidate(), "Dead engine remained a connected candidate");
            f.Running = true;
            f.ForceMismatch = true;
            Require(!f.Controller.IsConnectedCandidate(), "Changed policy remained a connected candidate");
            f = new Fixture(settings);
            f.Controller.RequestConnect();
            f.ForceMismatch = true;
            bool rejected = false;
            try
            { f.Controller.ConfigureActive(0x10000); }
            catch (InvalidOperationException) { rejected = true; }
            Require(rejected && f.Controller.ActiveLuid == 0 && !f.Controller.IsConnectedCandidate(), "Unverified active configuration published its LUID");
            return Task.CompletedTask;
        });
        var excluded = settings with { ExcludedApplications = [@"C:\QA\excluded.exe"] };
        await test("DNS lifecycle: Block enables resolver only after strict baseline and confirmed Stop", async () =>
        {
            var f = new Fixture(excluded);
            f.ArmActive();
            f.Controller.RequestBlock();
            var result = await f.Controller.RearmAsync();
            Require(result.Succeeded && f.DnsAllowed && f.Controller.IsExpectedPolicy(), "Stopped exclusion DNS was not installed and verified");
            int strict = f.Calls.IndexOf("Configure:0"), stop = f.Calls.IndexOf("Stop"), dns = f.Calls.IndexOf("Configure:0:dns");
            Require(strict >= 0 && stop > strict && dns > stop && f.Calls.IndexOf("Matches:0:dns") > dns, "DNS permit preceded confirmed stop or escaped verification");
            Require(!f.Calls.Contains("Remove"), "Enabling DNS released application protection");
            f.DnsAllowed = false;
            Require(!f.Controller.IsExpectedPolicy(), "Missing expected DNS policy was accepted");
        });
        await test("DNS lifecycle: Connect preparation and retry remove stopped DNS before engine startup", async () =>
        {
            var f = new Fixture(excluded);
            f.ArmActive();
            f.Controller.RequestBlock();
            Require((await f.Controller.RearmAsync()).Succeeded && f.DnsAllowed, "Precondition Block failed");
            f.Calls.Clear();
            f.Controller.RequestConnect();
            Require((await f.Controller.RearmAsync()).Succeeded, "Connect preparation failed");
            Require(!f.DnsAllowed && !f.Calls.Contains("Configure:0:dns") && f.Calls.Contains("Configure:0"), "Connect preparation retained direct DNS");
            f.Running = true;
            f.Controller.ConfigureActive(0x10000);
            Require(!f.DnsAllowed && f.Controller.IsConnectedCandidate(), "Active configuration retained direct DNS");
            f.Calls.Clear();
            var result = await f.Controller.RearmAsync(new IOException("synthetic connection failure"));
            Require(!result.Succeeded && result.PolicyVerified && !f.DnsAllowed && !f.Calls.Contains("Configure:0:dns"), "Automatic retry enabled stopped DNS");
        });
        await test("DNS lifecycle: failed Stop never enables DNS and a successful retry may enable it", async () =>
        {
            var f = new Fixture(excluded);
            f.ArmActive();
            f.Controller.RequestBlock();
            var failure = f.FailNext("Stop");
            var result = await f.Controller.RearmAsync();
            Require(!result.Succeeded && Contains(result.Errors, failure) && !f.Controller.EngineStopConfirmed, "Stop failure was hidden");
            Require(!f.DnsAllowed && !f.Calls.Contains("Configure:0:dns"), "Unconfirmed Stop enabled direct DNS");
            f.Calls.Clear();
            result = await f.Controller.RearmAsync();
            Require(result.Succeeded && f.DnsAllowed && f.Controller.EngineStopConfirmed, "Confirmed retry failed to install stopped DNS");
        });
        await test("DNS lifecycle: resolver installation failure remains visible and no exclusions means no resolver permit", async () =>
        {
            var f = new Fixture(excluded);
            f.ArmActive();
            f.Controller.RequestBlock();
            var failure = f.FailNext("ConfigureDns");
            var result = await f.Controller.RearmAsync();
            Require(!result.Succeeded && Contains(result.Errors, failure) && !f.DnsAllowed && f.Controller.ProtectionRequired, "DNS installation failure became success or released protection");
            Require(result.PolicyVerified && !f.Controller.IsExpectedPolicy(), "Strict fallback suppressed required stopped-DNS recovery");
            f.Calls.Clear();
            var observation = new IOException("synthetic monitor observed missing stopped DNS");
            result = await f.Controller.RearmAsync(observation);
            Require(!result.Succeeded && Contains(result.Errors, observation) && f.DnsAllowed && f.Controller.IsExpectedPolicy() && f.Calls.Contains("Configure:0:dns"),
                "Historical monitor cause suppressed successful DNS recovery or was hidden");
            f = new Fixture(settings with { ExcludedApplications = [] });
            f.ArmActive();
            f.Controller.RequestBlock();
            result = await f.Controller.RearmAsync();
            Require(result.Succeeded && !f.DnsAllowed && !f.Calls.Contains("Configure:0:dns"), "Empty exclusions enabled shared resolver");
        });
    }

    sealed class Fixture
    {
        readonly Dictionary<string, Queue<Exception>> faults = [];
        Settings? applied;
        ulong active;
        public readonly List<string> Calls = [];
        public bool Running = true, BasePresent, ForceMismatch, RemoveNoEffect, DnsAllowed;
        public ProtectionController Controller { get; }
        public Fixture(Settings settings)
        {
            Controller = new(settings, new ProtectionOperations(
                Count: () => { Call("Count"); return BasePresent ? 1u : 0u; },
                Running: () => { Call("Running"); return Running; },
                Configure: (s, luid, dns) =>
                {
                    Call(dns ? "ConfigureDns" : "Configure", "Configure:" + luid + (dns ? ":dns" : ""));
                    Require(!dns || !Running && luid == 0 && s.ExcludedApplications.Length > 0, "Resolver permission requested outside confirmed stopped exclusions state");
                    applied = s;
                    BasePresent = true;
                    active = luid;
                    DnsAllowed = dns;
                },
                Matches: (s, luid, dns) => { Call("Matches", "Matches:" + luid + (dns ? ":dns" : "")); return !ForceMismatch && BasePresent && applied == s && active == luid && DnsAllowed == dns; },
                Stop: () => { Call("Stop"); Running = false; return Task.CompletedTask; },
                Remove: () => { Call("Remove"); if (!RemoveNoEffect) { BasePresent = false; active = 0; DnsAllowed = false; } },
                Deactivate: () => { Call("Deactivate"); active = 0; }));
        }
        public void ArmActive()
        {
            Controller.RequestConnect();
            Controller.ConfigureActive(0x10000);
            Calls.Clear();
        }
        public Exception FailNext(string stage)
        {
            var error = new IOException("synthetic " + stage + " failure");
            if (!faults.TryGetValue(stage, out var queue))
            {
                faults[stage] = queue = new();
            }

            queue.Enqueue(error);
            return error;
        }
        void Call(string stage, string? label = null)
        {
            Calls.Add(label ?? stage);
            if (faults.TryGetValue(stage, out var queue) && queue.Count > 0)
            {
                throw queue.Dequeue();
            }
        }
    }
}
