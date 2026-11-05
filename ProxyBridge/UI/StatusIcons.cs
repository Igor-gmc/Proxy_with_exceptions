namespace ProxyBridge;

internal enum ProxyVisualState
{
    Paused, Connecting, Connected, Failed
}

internal sealed class StatusIcons : IDisposable
{
    readonly Icon drive = Load("drive");
    readonly Icon parking = Load("parking");
    readonly Icon stop = Load("stop");

    static Icon Load(string name)
    {
        using var stream = typeof(StatusIcons).Assembly.GetManifestResourceStream($"ProxyBridge.Icons.{name}.ico")
            ?? throw new IOException("В сборке отсутствует значок состояния: " + name);
        using var source = new Icon(stream, SystemInformation.SmallIconSize);
        return (Icon)source.Clone();
    }

    public Icon ForState(ProxyVisualState state) => state switch
    {
        ProxyVisualState.Connected => drive,
        ProxyVisualState.Failed => stop,
        _ => parking
    };

    public static string Tooltip(ProxyVisualState state) => state switch
    {
        ProxyVisualState.Connected => "ProxyBridge: D · прокси работает",
        ProxyVisualState.Failed => "ProxyBridge: S · сбой прокси или защиты",
        ProxyVisualState.Connecting => "ProxyBridge: P · подключение…",
        _ => "ProxyBridge: P · прокси остановлен"
    };

    public void Dispose()
    {
        drive.Dispose();
        parking.Dispose();
        stop.Dispose();
    }
}
