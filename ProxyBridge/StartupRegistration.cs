using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Xml.Linq;

namespace ProxyBridge;

internal static class StartupRegistration
{
    static string UserSid => WindowsIdentity.GetCurrent().User!.Value;
    static string TaskName => "ProxyBridge-" + UserSid;
    static string InstalledPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ProxyBridgeComponents", "Launcher", "ProxyBridge.exe");

    public static bool IsEnabled {
        get {
            dynamic service = Connect();
            try {
                dynamic folder = service.GetFolder("\\");
                try {
                    dynamic task;
                    try { task = folder.GetTask(TaskName); }
                    catch (Exception ex) when (ex.HResult == unchecked((int)0x80070002)) { return false; }
                    try { return (bool)task.Enabled && Matches((string)task.Xml, InstalledPath, UserSid); }
                    finally { Marshal.FinalReleaseComObject(task); }
                } finally { Marshal.FinalReleaseComObject(folder); }
            } finally { Marshal.FinalReleaseComObject(service); }
        }
    }

    public static Task SetEnabledAsync(bool enabled) => Task.Run(() => SetEnabled(enabled));

    internal static void ValidateDefinition()
    {
        dynamic service = Connect();
        try {
            dynamic folder = service.GetFolder("\\");
            try {
                // TASK_VALIDATE_ONLY: ask Windows to validate the schema without
                // registering a task, installing a launcher, or starting anything.
                object? result = folder.RegisterTask("ProxyBridge-Validate-" + Guid.NewGuid().ToString("N"),
                    BuildXml(InstalledPath, UserSid), 1, UserSid, null, 3, null);
                if (result != null && Marshal.IsComObject(result)) Marshal.FinalReleaseComObject(result);
            } finally { Marshal.FinalReleaseComObject(folder); }
        } finally { Marshal.FinalReleaseComObject(service); }
    }

    static void SetEnabled(bool enabled)
    {
        dynamic service = Connect();
        try {
            dynamic folder = service.GetFolder("\\");
            try {
                if (!enabled) {
                    try { folder.DeleteTask(TaskName, 0); }
                    catch (Exception ex) when (ex.HResult == unchecked((int)0x80070002)) { }
                    return;
                }
                // A highest-privilege logon task must not point at a replaceable
                // executable in Downloads or a user writable project directory.
                string source = Environment.ProcessPath ?? throw new IOException("Не найден путь программы.");
                BundledAssets.RejectReparsePoints(InstalledPath);
                Directory.CreateDirectory(Path.GetDirectoryName(InstalledPath)!);
                if (!string.Equals(Path.GetFullPath(source), InstalledPath, StringComparison.OrdinalIgnoreCase)) {
                    string temporary = InstalledPath + ".tmp";
                    BundledAssets.RejectReparsePoints(temporary);
                    File.Copy(source, temporary, true);
                    File.Move(temporary, InstalledPath, true);
                }
                string xml = BuildXml(InstalledPath, UserSid);
                dynamic registered = folder.RegisterTask(TaskName, xml, 6, UserSid, null, 3, null);
                try {
                    if (!(bool)registered.Enabled || !Matches((string)registered.Xml, InstalledPath, UserSid))
                        throw new IOException("Не удалось подтвердить регистрацию автозапуска.");
                } finally { Marshal.FinalReleaseComObject(registered); }
            } finally { Marshal.FinalReleaseComObject(folder); }
        } finally { Marshal.FinalReleaseComObject(service); }
    }

    static dynamic Connect()
    {
        var type = Type.GetTypeFromProgID("Schedule.Service") ?? throw new InvalidOperationException("Планировщик заданий недоступен.");
        dynamic service = Activator.CreateInstance(type)!;
        try { service.Connect(); return service; }
        catch { Marshal.FinalReleaseComObject(service); throw; }
    }

    internal static string BuildXml(string executable, string sid)
    {
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        XElement E(string name, object value) => new(ns + name, value);
        return new XDocument(new XElement(ns + "Task", new XAttribute("version", "1.2"),
            E("RegistrationInfo", E("Description", "ProxyBridge: видимый журнал и проверка прокси при входе в Windows")),
            E("Triggers", E("LogonTrigger", new object[] { E("Enabled", true), E("UserId", sid), E("Delay", "PT5S") })),
            E("Principals", new XElement(ns + "Principal", new XAttribute("id", "CurrentUser"), E("UserId", sid), E("LogonType", "InteractiveToken"), E("RunLevel", "HighestAvailable"))),
            E("Settings", new object[] { E("MultipleInstancesPolicy", "IgnoreNew"), E("DisallowStartIfOnBatteries", false), E("StopIfGoingOnBatteries", false), E("StartWhenAvailable", true), E("RunOnlyIfNetworkAvailable", false), E("Enabled", true), E("Hidden", false), E("ExecutionTimeLimit", "PT0S") }),
            new XElement(ns + "Actions", new XAttribute("Context", "CurrentUser"), E("Exec", new object[] { E("Command", executable), E("Arguments", "--startup"), E("WorkingDirectory", Path.GetDirectoryName(executable)!) }))
        )).ToString();
    }

    internal static bool Matches(string xml, string executable, string sid)
    {
        var document = XDocument.Parse(xml);
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var task = document.Root!;
        var actions = task.Element(ns + "Actions")?.Elements().ToArray();
        var principals = task.Element(ns + "Principals")?.Elements().ToArray();
        var triggers = task.Element(ns + "Triggers")?.Elements().ToArray();
        var principal = principals?.FirstOrDefault();
        var trigger = triggers?.FirstOrDefault();
        var settings = task.Element(ns + "Settings");
        return actions is { Length: 1 } && actions[0].Name == ns + "Exec"
            && principals is { Length: 1 } && principal!.Name == ns + "Principal"
            && triggers is { Length: 1 } && trigger!.Name == ns + "LogonTrigger"
            && string.Equals((string?)actions[0].Element(ns + "Command"), executable, StringComparison.OrdinalIgnoreCase)
            && (string?)actions[0].Element(ns + "Arguments") == "--startup"
            && (string?)principal?.Element(ns + "UserId") == sid
            && (string?)principal?.Element(ns + "LogonType") == "InteractiveToken"
            && (string?)principal?.Element(ns + "RunLevel") == "HighestAvailable"
            && (string?)trigger?.Element(ns + "UserId") == sid
            && (bool?)trigger?.Element(ns + "Enabled") == true
            && (bool?)settings?.Element(ns + "Enabled") == true
            && (bool?)settings?.Element(ns + "Hidden") == false
            && (string?)settings?.Element(ns + "ExecutionTimeLimit") == "PT0S"
            && (string?)settings?.Element(ns + "MultipleInstancesPolicy") == "IgnoreNew"
            && (bool?)settings?.Element(ns + "DisallowStartIfOnBatteries") == false
            && (bool?)settings?.Element(ns + "StopIfGoingOnBatteries") == false
            && (bool?)settings?.Element(ns + "RunOnlyIfNetworkAvailable") == false;
    }
}
