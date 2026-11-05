using System.Reflection;

namespace ProxyBridge;

internal static class AppVersion
{
    public static string Display { get; } = typeof(AppVersion).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
}
