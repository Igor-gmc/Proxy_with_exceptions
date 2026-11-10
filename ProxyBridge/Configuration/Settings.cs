using System.Net;

namespace ProxyBridge;

internal record Settings(string Host, int Port, string Username, string Password, string Protocol)
{
    const int MaximumExcludedApplications = 64;
    const int MaximumExcludedAddresses = 64;

    string[] excludedApplications = [];
    string[] excludedAddresses = [];

    public bool ActivityLoggingEnabled { get; init; } = true;

    public string[] ExcludedApplications
    {
        get => excludedApplications;
        init => excludedApplications = NormalizeExcludedApplications(value);
    }

    public string[] ExcludedAddresses
    {
        get => excludedAddresses;
        init => excludedAddresses = NormalizeExcludedAddresses(value);
    }

    public static string[] NormalizeExcludedAddresses(IEnumerable<string>? addresses)
    {
        if (addresses is null)
        {
            throw new ArgumentException("Список адресных исключений повреждён.");
        }

        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (string value in addresses)
        {
            result.Add(AddressExclusion.Parse(value).Value);
            if (result.Count > MaximumExcludedAddresses)
            {
                throw new ArgumentException("Можно добавить не более 64 адресов или подсетей.");
            }
        }
        return result.ToArray();
    }

    public static string[] NormalizeExcludedApplications(IEnumerable<string>? paths)
    {
        if (paths is null)
        {
            throw new ArgumentException("Список исключений повреждён.");
        }

        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in paths)
        {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || !string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Для исключения нужен полный путь к файлу EXE.");
            }

            string fullPath = Path.GetFullPath(path);
            if (string.Equals(fullPath, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fullPath, Engine.Executable, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Path.GetFileName(fullPath), "ProxyBridge.exe", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("ProxyBridge и его движок нельзя добавлять в исключения.");
            }

            result.Add(fullPath);
            if (result.Count > MaximumExcludedApplications)
            {
                throw new ArgumentException("Можно добавить не более 64 приложений.");
            }
        }
        return result.ToArray();
    }

    internal static string? TestDirectory;

    public static string DataDir => TestDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ProxyBridge");

    public static Settings Default => new("", 8080, "", "", "http");

    public void Validate()
    {
        if (!IPAddress.TryParse(Host, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any))
        {
            throw new ArgumentException("Укажите IPv4-адрес прокси (не имя домена и не localhost).");
        }

        if (Port is < 1 or > 65535 || Protocol is not ("http" or "socks"))
        {
            throw new ArgumentException("Проверьте порт и протокол.");
        }

        if (Username is null || Password is null)
        {
            throw new ArgumentException("Проверьте логин и пароль прокси.");
        }

        _ = NormalizeExcludedApplications(ExcludedApplications);
        _ = NormalizeExcludedAddresses(ExcludedAddresses);
    }

    public static void PrepareDirectory() => SettingsStore.PrepareDirectory(DataDir);

    public static Settings Load() => SettingsStore.Load(DataDir);

    public void Save() => SettingsStore.Save(this, DataDir);
}
