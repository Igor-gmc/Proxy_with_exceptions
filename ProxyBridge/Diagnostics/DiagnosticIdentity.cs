namespace ProxyBridge;

internal static class DiagnosticIdentity
{
    internal static bool Matches(DiagnosticContext? expected, DiagnosticContext? current,
        DateTimeOffset? actualStart) => expected?.EnginePid != null && expected.EngineStartedUtc != null &&
        actualStart == expected.EngineStartedUtc && current?.EnginePid == expected.EnginePid &&
        current.EngineGeneration == expected.EngineGeneration && current.EngineStartedUtc == expected.EngineStartedUtc;
}
