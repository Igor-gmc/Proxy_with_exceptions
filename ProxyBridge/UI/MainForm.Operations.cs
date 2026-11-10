using System.Diagnostics;

namespace ProxyBridge;

internal sealed partial class MainForm
{
    readonly System.Windows.Forms.Timer monitor = new() { Interval = 8000 };
    // All admission happens on the UI thread. Each ticket completes only after
    // its predecessor and its own cleanup, so every accepted click stays FIFO.
    Task operationTail = Task.CompletedTask;
    CancellationTokenSource? monitorCancellation;
    int pendingCommands;
    bool busy;
    bool monitorReadOnly;
    bool controlsDisabled;
    StopCommandTestScope? stopCommandTestScope;

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
    internal Task RunRetryForUiTestAsync(Func<Task> action)
    {
        if (!observeOnly)
        {
            throw new InvalidOperationException("Synthetic retry is restricted to observe-only UI tests.");
        }

        return RunMonitorCycle(_ =>
        {
            PromoteMonitorMutation();
            return action();
        }, syntheticTestCommand: true);
    }
    internal Task WaitForCommandsForUiTestAsync()
    {
        if (!observeOnly)
        {
            throw new InvalidOperationException("Synthetic queue inspection requires observe-only mode.");
        }

        return operationTail;
    }
    internal IDisposable OverrideStopCommandsForUiTest(Func<Task> blockAction, Func<Task> releaseAction)
    {
        if (!observeOnly)
        {
            throw new InvalidOperationException("Synthetic stop commands require observe-only mode.");
        }
        if (stopCommandTestScope != null)
        {
            throw new InvalidOperationException("A synthetic stop-command scope is already active.");
        }
        ArgumentNullException.ThrowIfNull(blockAction);
        ArgumentNullException.ThrowIfNull(releaseAction);
        stopCommandTestScope = new(this, blockAction, releaseAction);
        return stopCommandTestScope;
    }
    sealed class StopCommandTestScope(MainForm owner, Func<Task> blockAction, Func<Task> releaseAction) : IDisposable
    {
        public Func<Task> Block { get; } = blockAction;
        public Func<Task> Release { get; } = releaseAction;

        public void Dispose()
        {
            if (ReferenceEquals(owner.stopCommandTestScope, this))
            {
                owner.stopCommandTestScope = null;
            }
        }
    }
    Task QueueStopCommand(bool releaseProtection, string operationName)
    {
        var synthetic = stopCommandTestScope;
        Func<Task> action = releaseProtection
            ? synthetic?.Release ?? Release
            : synthetic?.Block ?? Block;
        return Execute(action, operationName, syntheticTestCommand: synthetic != null);
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

        Task predecessor = operationTail;
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        operationTail = completion.Task;
        IDisposable? operation = null;
        bool entered = false, registered = false;
        try
        {
            operation = operationName == null ? null : AppLog.BeginOperation(operationName);
            if (!background)
            {
                pendingCommands++;
                registered = true;
                SetControlsEnabled(false);
                if (!predecessor.IsCompleted)
                {
                    string? command = operationName switch
                    {
                        "ui.block" or "tray.block" => "Остановить и блокировать",
                        "ui.release" or "tray.release" => "Отключить и вернуть интернет",
                        _ => null
                    };
                    if (command != null)
                    {
                        Append($"Команда «{command}» поставлена в очередь и выполнится после текущей операции.");
                    }
                }
                if (monitorReadOnly)
                {
                    monitorCancellation?.Cancel();
                }
            }
            await predecessor;
            entered = true;
            if (OperationsClosed)
            {
                return;
            }

            busy = true;
            try
            {
                if (operationName != null)
                {
                    LogState("operation.begin");
                }
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
                // within the same queue ticket before allowing a user command.
                if (!OperationsClosed)
                {
                    try
                    {
                        await RecoverPendingConnectionFailure();
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
            try
            {
                // An admission/logging error or disposal must not complete this
                // ticket early and let a later command overtake its predecessor.
                if (!entered)
                {
                    await predecessor;
                }
                if (entered)
                {
                    busy = false;
                }
                if (registered)
                {
                    pendingCommands--;
                }
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
                try
                {
                    operation?.Dispose();
                }
                finally { completion.TrySetResult(); }
            }
        }
    }
}
