using System.Diagnostics;

namespace ProxyBridge;

internal sealed partial class MainForm
{
    readonly System.Windows.Forms.Timer monitor = new() { Interval = 8000 };
    readonly SemaphoreSlim operationGate = new(1, 1);
    CancellationTokenSource? monitorCancellation;
    int pendingCommands;
    bool busy;
    bool monitorReadOnly;
    bool controlsDisabled;

    async void OnMonitorTick(object? sender, EventArgs e)
    {
        if (busy || pendingCommands != 0 || !protection.ProtectionRequired)
        {
            return;
        }

        await RunMonitorCycle(MonitorProtection);
    }

    bool OperationsClosed => resourcesDisposed || IsDisposed || Disposing;

    async Task RunMonitorCycle(Func<CancellationToken, Task> action, bool syntheticTestCommand = false)
    {
        await Execute(async () =>
        {
            using var cancellation = new CancellationTokenSource();
            monitorCancellation = cancellation;
            monitorReadOnly = true;
            try
            {
                await action(cancellation.Token);
            }
            catch (OperationCanceledException ex) when (cancellation.IsCancellationRequested && ex.CancellationToken == cancellation.Token)
            {
                AppLog.Write("MONITOR read-only probe canceled by caller; no recovery requested");
            }
            finally
            {
                monitorReadOnly = false;
                monitorCancellation = null;
            }
        }, background: true, syntheticTestCommand: syntheticTestCommand);
    }
    internal Task RunMonitorForUiTestAsync(Func<CancellationToken, Task> action)
    {
        if (!observeOnly)
        {
            throw new InvalidOperationException("Synthetic monitor is restricted to observe-only UI tests.");
        }

        return RunMonitorCycle(action, syntheticTestCommand: true);
    }
    internal Task RunCommandForUiTestAsync(Func<Task> action)
    {
        if (!observeOnly)
        {
            throw new InvalidOperationException("Synthetic command is restricted to observe-only UI tests.");
        }

        return Execute(action, "ui-test.command", syntheticTestCommand: true);
    }
    void PromoteMonitorMutation()
    {
        if (!busy || OperationsClosed)
        {
            return;
        }

        monitorReadOnly = false;
        SetControlsEnabled(false);
    }
    async Task Execute(Func<Task> action, string? operationName = null, bool background = false, bool syntheticTestCommand = false)
    {
        // Keep native UI input harmless in the visible test window and tray.
        // Only explicit synthetic hooks may run commands in observe-only mode.
        if (observeOnly && !syntheticTestCommand)
        {
            return;
        }

        if (syntheticTestCommand && !observeOnly)
        {
            throw new InvalidOperationException("Synthetic commands require observe-only mode.");
        }

        if (OperationsClosed || background && (busy || pendingCommands != 0))
        {
            return;
        }

        using var operation = operationName == null ? null : AppLog.BeginOperation(operationName);
        bool entered = false, registered = false;
        try
        {
            if (!background)
            {
                pendingCommands++;
                registered = true;
                SetControlsEnabled(false);
                if (monitorReadOnly)
                {
                    monitorCancellation?.Cancel();
                }
            }
            await operationGate.WaitAsync();
            entered = true;
            if (OperationsClosed)
            {
                return;
            }

            busy = true;
            if (operationName != null)
            {
                LogState("operation.begin");
            }

            try
            {
                await action();
            }
            catch (Exception ex)
            {
                AppLog.Error("Ошибка операции", ex);
                if (!OperationsClosed)
                {
                    ReportError(ex.Message);
                }
            }
            finally
            {
                // Preserve the immediate exit revocation and finish its recovery
                // under the same gate before allowing a queued user command.
                if (!OperationsClosed && pendingConnectionFailure != null && protection.ProtectionRequired)
                {
                    try
                    {
                        await RecoverConnection(pendingConnectionFailure);
                    }
                    catch (Exception ex) { AppLog.Error("Ошибка восстановления защиты", ex); SetVisualState(ProxyVisualState.Failed); ReportError(ex.Message); }
                }
            }
        }
        catch (Exception ex)
        {
            AppLog.Error("Ошибка ожидания операции", ex);
            if (!OperationsClosed)
            {
                ReportError(ex.Message);
            }
        }
        finally
        {
            if (entered)
            {
                busy = false;
            }

            if (registered)
            {
                pendingCommands--;
            }

            try
            {
                if (!OperationsClosed && !busy && pendingCommands == 0)
                {
                    SetControlsEnabled(true);
                }

                if (operationName != null)
                {
                    LogState("operation.end");
                }
            }
            finally
            {
                if (entered)
                {
                    operationGate.Release();
                }
            }
        }
    }
}
