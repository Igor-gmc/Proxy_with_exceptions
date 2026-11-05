using System.Xml.Linq;
namespace ProxyBridge;

internal static class StartupSelfTests
{
    static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Test invariant failed.");
        }
    }

    internal static async Task RunAsync(Func<string, Func<Task>, Task> Test)
    {
        await Test("startup XML: escaped EXE, interactive user, visible unlimited logon task", () =>
        {
            const string sid = "S-1-5-21-100-200-300-1001";
            const string executable = @"C:\Program Files\A&B\ProxyBridge.exe";
            string xml = StartupRegistration.BuildXml(executable, sid);
            Require(StartupRegistration.Matches(xml, executable, sid));
            Require(!StartupRegistration.Matches(xml, executable + ".other", sid));
            Require(!StartupRegistration.Matches(xml, executable, sid + "2"));
            XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
            var doc = XDocument.Parse(xml);
            var task = doc.Root!;
            Require(task.Element(ns + "Settings")!.Element(ns + "Hidden")!.Value == "false");
            Require(task.Element(ns + "Settings")!.Element(ns + "ExecutionTimeLimit")!.Value == "PT0S");
            Require(task.Element(ns + "Settings")!.Element(ns + "RunOnlyIfNetworkAvailable")!.Value == "false");
            Require(task.Element(ns + "Triggers")!.Elements().Count() == 1);
            Require(!doc.Descendants().Any(x => x.Name.LocalName.Contains("Password", StringComparison.OrdinalIgnoreCase)));
            var actions = task.Element(ns + "Actions")!;
            actions.Add(new XElement(actions.Elements().Single()));
            Require(!StartupRegistration.Matches(doc.ToString(), executable, sid));
            doc = XDocument.Parse(xml);
            doc.Descendants(ns + "Arguments").Single().Value = "--recover";
            Require(!StartupRegistration.Matches(doc.ToString(), executable, sid));
            doc = XDocument.Parse(xml);
            doc.Descendants(ns + "LogonTrigger").Single().Element(ns + "Enabled")!.Value = "false";
            Require(!StartupRegistration.Matches(doc.ToString(), executable, sid));
            doc = XDocument.Parse(xml);
            doc.Descendants(ns + "ExecutionTimeLimit").Single().Value = "PT1H";
            Require(!StartupRegistration.Matches(doc.ToString(), executable, sid));
            foreach (var mutation in new[] { ("LogonType", "Password"), ("RunLevel", "LeastPrivilege"), ("Hidden", "true"), ("RunOnlyIfNetworkAvailable", "true"), ("StopIfGoingOnBatteries", "true") })
            {
                doc = XDocument.Parse(xml);
                doc.Descendants(ns + mutation.Item1).Single().Value = mutation.Item2;
                Require(!StartupRegistration.Matches(doc.ToString(), executable, sid));
            }
            doc = XDocument.Parse(xml);
            var triggers = doc.Root!.Element(ns + "Triggers")!;
            triggers.Add(new XElement(triggers.Elements().Single()));
            Require(!StartupRegistration.Matches(doc.ToString(), executable, sid));
            return Task.CompletedTask;
        });
        await Test("Windows Task Scheduler validates startup schema without creating a task", () =>
        {
            StartupRegistration.ValidateDefinition();
            return Task.CompletedTask;
        });
    }
}
