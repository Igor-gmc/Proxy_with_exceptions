using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace ProxyBridge;
internal static class BundledAssets
{
    public static string DirectoryPath { get; private set; } = AppContext.BaseDirectory;

    public static void Prepare()
    {
        using var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("ProxyBridge.Payload.zip");
        if (resource == null) throw new IOException("В сборке отсутствуют встроенные компоненты. Выполните build.ps1.");
        using var memory = new MemoryStream();
        resource.CopyTo(memory);
        string version = Convert.ToHexString(SHA256.HashData(memory.ToArray()))[..24];
        // Executable payload must not be writable by an unelevated process of
        // the same user. User settings remain in LocalApplicationData.
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ProxyBridgeComponents");
        RejectReparsePoints(root);
        Directory.CreateDirectory(root);
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        acl.SetOwner(administrators);
        foreach (var sid in new[] { new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), administrators })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        // The engine may have a direct outbound for explicit exclusions. Only
        // elevated processes may execute it or supply its runtime configuration.
        new DirectoryInfo(root).SetAccessControl(acl);
        DirectoryPath = Path.Combine(root, version);
        RejectReparsePoints(DirectoryPath);
        Directory.CreateDirectory(DirectoryPath);
        memory.Position = 0;
        using var zip = new ZipArchive(memory, ZipArchiveMode.Read);
        foreach (var entry in zip.Entries) {
            if (string.IsNullOrEmpty(entry.Name)) continue;
            string destination = Path.GetFullPath(Path.Combine(DirectoryPath, entry.FullName));
            if (!destination.StartsWith(DirectoryPath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Недопустимый путь встроенного компонента.");
            RejectReparsePoints(destination);
            using var source = entry.Open();
            using var bytes = new MemoryStream(); source.CopyTo(bytes);
            byte[] content = bytes.ToArray();
            if (File.Exists(destination)) {
                using var existing = File.OpenRead(destination);
                if (SHA256.HashData(existing).SequenceEqual(SHA256.HashData(content))) continue;
            }
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            string temporary = destination + ".tmp";
            RejectReparsePoints(temporary);
            File.WriteAllBytes(temporary, content);
            File.Move(temporary, destination, true);
        }
        NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(), (name, assembly, searchPath) =>
            name.Equals("ProxyGuard.dll", StringComparison.OrdinalIgnoreCase)
                ? NativeLibrary.Load(Path.Combine(DirectoryPath, "ProxyGuard.dll")) : IntPtr.Zero);
    }
    internal static void RejectReparsePoints(string path)
    {
        for (string? current = Path.GetFullPath(path); current != null; current = Path.GetDirectoryName(current)) {
            if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Папка компонентов не должна содержать символические ссылки: " + current);
        }
    }
}
