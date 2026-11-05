using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace ProxyBridge;
internal record Settings(string Host, int Port, string Username, string Password, string Protocol)
{
    public bool ActivityLoggingEnabled { get; init; } = true;
    string[] excludedApplications = [];
    public string[] ExcludedApplications { get => excludedApplications; init => excludedApplications = NormalizeExcludedApplications(value); }
    public static string[] NormalizeExcludedApplications(IEnumerable<string>? paths)
    {
        if (paths is null) throw new ArgumentException("Список исключений повреждён.");
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in paths) {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || !string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Для исключения нужен полный путь к файлу EXE.");
            string fullPath = Path.GetFullPath(path);
            if (string.Equals(fullPath, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fullPath, Engine.Executable, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Path.GetFileName(fullPath), "ProxyBridge.exe", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("ProxyBridge и его движок нельзя добавлять в исключения.");
            result.Add(fullPath);
            if (result.Count > 64) throw new ArgumentException("Можно добавить не более 64 приложений.");
        }
        return result.ToArray();
    }
    internal static string? TestDirectory;
    public static string DataDir => TestDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ProxyBridge");
    public static Settings Default => new("", 8080, "", "", "http");
    public void Validate()
    {
        if (!IPAddress.TryParse(Host, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any))
            throw new ArgumentException("Укажите IPv4-адрес прокси (не имя домена и не localhost).");
        if (Port is < 1 or > 65535 || Protocol is not ("http" or "socks")) throw new ArgumentException("Проверьте порт и протокол.");
        if (Username is null || Password is null) throw new ArgumentException("Проверьте логин и пароль прокси.");
        _ = NormalizeExcludedApplications(ExcludedApplications);
    }
    public static void PrepareDirectory()
    {
        Directory.CreateDirectory(DataDir);
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { WindowsIdentity.GetCurrent().User!, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(DataDir).SetAccessControl(acl);
    }
    public static Settings Load()
    {
        PrepareDirectory();
        var path = Path.Combine(DataDir, "settings.dat");
        // Missing settings are a first-run setup state, never a bundled proxy.
        if (!File.Exists(path)) return Default;
        var settings = JsonSerializer.Deserialize<Settings>(Crypt(File.ReadAllBytes(path), false));
        if (settings == null) throw new InvalidDataException("Файл настроек пуст или повреждён.");
        settings.Validate();
        return settings;
    }
    public void Save()
    {
        Validate(); PrepareDirectory();
        var path = Path.Combine(DataDir, "settings.dat");
        File.WriteAllBytes(path + ".tmp", Crypt(JsonSerializer.SerializeToUtf8Bytes(this), true));
        File.Move(path + ".tmp", path, true);
    }
    [StructLayout(LayoutKind.Sequential)] struct Blob { public int Size; public IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true)] static extern bool CryptProtectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)] static extern bool CryptUnprotectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
    static byte[] Crypt(byte[] bytes, bool protect)
    {
        var input = new Blob { Size = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) };
        try {
            Marshal.Copy(bytes, 0, input.Data, bytes.Length);
            Blob output;
            bool ok = protect ? CryptProtectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            try { var result = new byte[output.Size]; Marshal.Copy(output.Data, result, 0, result.Length); return result; }
            finally { LocalFree(output.Data); }
        } finally { Marshal.FreeHGlobal(input.Data); }
    }
}
