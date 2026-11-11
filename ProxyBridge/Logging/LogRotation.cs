namespace ProxyBridge;

// Keeps exactly one previous generation (<file>.1) when a bounded log reaches
// its size limit, so evidence leading up to a failure survives the rollover.
// Disk usage is bounded by two files per log. If the previous generation cannot
// be replaced (for example, a viewer holds it open without delete sharing), the
// current file is truncated as before; logging must never stop because of it.
internal static class LogRotation
{
    public static string PreviousPath(string path) => path + ".1";

    // Closes the stream, moves the file to <file>.1 and returns a fresh empty
    // stream. Returns true when the previous records were preserved.
    public static bool Rotate(ref FileStream file, string fullPath)
    {
        bool preserved = false;
        file.Flush(flushToDisk: true);
        file.Dispose();
        try
        {
            File.Move(fullPath, PreviousPath(fullPath), overwrite: true);
            preserved = true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        file = new FileStream(fullPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read);
        if (!preserved)
        {
            file.SetLength(0);
        }

        file.Position = 0;
        return preserved;
    }
}
