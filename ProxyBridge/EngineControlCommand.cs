using System.Globalization;

namespace ProxyBridge;

// Private, short-lived helper: never takes the application mutex or touches WFP.
internal static class EngineControlCommand
{
    public static bool TryRun(string[] args, out int exitCode)
    {
        exitCode = 2;
        if (args.Length == 0 || args[0] != "--signal-engine") return false;
        try {
            if (args.Length != 4 ||
                !int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out int pid) || pid <= 0 ||
                !long.TryParse(args[2], NumberStyles.None, CultureInfo.InvariantCulture, out long ticks) || ticks <= 0)
                return true;
            string path = Path.GetFullPath(args[3]);
            string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ProxyBridgeComponents");
            string relative = Path.GetRelativePath(root, path);
            string[] parts = relative.Split(Path.DirectorySeparatorChar);
            if (parts.Length != 3 || parts[0].Length != 24 || !parts[0].All(char.IsAsciiHexDigit) ||
                !parts[1].Equals("core", StringComparison.OrdinalIgnoreCase) ||
                !parts[2].Equals("sing-box.exe", StringComparison.OrdinalIgnoreCase) ||
                !path.Equals(Path.Combine(root, parts[0], "core", "sing-box.exe"), StringComparison.OrdinalIgnoreCase))
                return true;
            BundledAssets.RejectReparsePoints(path);
            exitCode = EngineConsole.Signal(pid, ticks, path);
        } catch { exitCode = 2; } // No dialog or secret-bearing output from the helper.
        return true;
    }
}
