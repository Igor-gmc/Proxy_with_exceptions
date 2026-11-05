namespace ProxyBridge;

internal static class RuntimeStorage
{
    // BundledAssets.Prepare secures this tree to Administrators/SYSTEM. A user
    // writable runtime.json would let an unelevated process change direct rules.
    public static string ConfigPath => Path.Combine(BundledAssets.DirectoryPath, "runtime", $"runtime-{Environment.ProcessId}.json");
    public static void Prepare()
    {
        BundledAssets.RejectReparsePoints(ConfigPath);
        Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
    }
}
