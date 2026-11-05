using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace ProxyBridge;

/// <summary>Persists the profile using current-user DPAPI and a restricted directory.</summary>
internal static class SettingsStore
{
    const string FileName = "settings.dat";
    const uint CryptProtectUiForbidden = 1;

    public static void PrepareDirectory(string directory)
    {
        Directory.CreateDirectory(directory);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        SecurityIdentifier[] owners =
        [
            WindowsIdentity.GetCurrent().User!,
            new(WellKnownSidType.LocalSystemSid, null),
            new(WellKnownSidType.BuiltinAdministratorsSid, null)
        ];
        foreach (var owner in owners)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                owner,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }
        new DirectoryInfo(directory).SetAccessControl(security);
    }

    public static Settings Load(string directory)
    {
        PrepareDirectory(directory);
        string path = Path.Combine(directory, FileName);
        // Absence means first-run setup. Corruption must never silently reset a profile.
        if (!File.Exists(path))
        {
            return Settings.Default;
        }

        byte[] plaintext = Transform(File.ReadAllBytes(path), protect: false);
        var settings = JsonSerializer.Deserialize<Settings>(plaintext)
            ?? throw new InvalidDataException("Файл настроек пуст или повреждён.");
        settings.Validate();
        return settings;
    }

    public static void Save(Settings settings, string directory)
    {
        settings.Validate();
        PrepareDirectory(directory);
        string path = Path.Combine(directory, FileName);
        byte[] encrypted = Transform(JsonSerializer.SerializeToUtf8Bytes(settings), protect: true);
        File.WriteAllBytes(path + ".tmp", encrypted);
        File.Move(path + ".tmp", path, overwrite: true);
    }

    static byte[] Transform(byte[] bytes, bool protect)
    {
        var input = new DataBlob { Size = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) };
        try
        {
            Marshal.Copy(bytes, 0, input.Data, bytes.Length);
            DataBlob output;
            bool succeeded = protect
                ? CryptProtectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out output)
                : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out output);
            if (!succeeded)
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                var result = new byte[output.Size];
                Marshal.Copy(output.Data, result, 0, result.Length);
                return result;
            }
            finally
            {
                LocalFree(output.Data);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(input.Data);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct DataBlob
    {
        public int Size;
        public IntPtr Data;
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    static extern bool CryptProtectData(ref DataBlob input, IntPtr description, IntPtr entropy,
        IntPtr reserved, IntPtr prompt, uint flags, out DataBlob output);

    [DllImport("crypt32.dll", SetLastError = true)]
    static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, IntPtr entropy,
        IntPtr reserved, IntPtr prompt, uint flags, out DataBlob output);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr pointer);
}
