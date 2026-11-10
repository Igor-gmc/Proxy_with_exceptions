using System.Reflection;

namespace ProxyBridge;

// Real button and tray events, but only scoped synthetic command bodies.
// Hosts must forbid ProxyGuard.dll so a broken observe-only gate stays harmless.
internal static class QueuedStopUiTests
{
    const BindingFlags Instance = BindingFlags.Instance | BindingFlags.NonPublic;
    static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    static Task Await(Task task) => task.WaitAsync(TimeSpan.FromSeconds(10));
    static void Require(bool value, string message)
    {
        if (!value) throw new InvalidOperationException(message);
    }
    static IEnumerable<Control> Descendants(Control parent)
    {
        foreach (Control child in parent.Controls)
        {
            yield return child;
            foreach (var nested in Descendants(child)) yield return nested;
        }
    }
    static Control Named(MainForm form, string name) => Descendants(form).Single(control => control.Name == name);
    static NotifyIcon Tray(MainForm form) => (NotifyIcon)typeof(MainForm).GetField("tray", Instance)!.GetValue(form)!;
    static void Click(MainForm form, bool release, bool tray)
    {
        if (tray)
        {
            string text = release ? "Отключить и вернуть интернет" : "Остановить и блокировать";
            Tray(form).ContextMenuStrip!.Items.Cast<ToolStripItem>().Single(item => item.Text == text).PerformClick();
        }
        else
        {
            var button = (Button)Named(form, release ? "release" : "block");
            Require(button.Enabled && button.Visible, "A real stop/release button cannot receive the queued click.");
            button.PerformClick();
        }
    }
    static void BusyControls(MainForm form)
    {
        Require(Named(form, "block").Enabled && Named(form, "release").Enabled,
            "Stop/release must remain available throughout connect/retry and queued commands.");
        foreach (string name in new[] { "connect", "apply", "speed", "host", "port", "username", "password", "protocol",
            "exclusions", "addExclusion", "addAddressExclusion", "removeExclusion", "autoStart" })
            Require(!Named(form, name).Enabled, "A conflicting control remained available while busy: " + name);
    }
    static void IdleControls(MainForm form)
    {
        foreach (string name in new[] { "connect", "apply", "block", "release", "speed", "host", "port", "username", "password",
            "protocol", "exclusions", "addExclusion", "addAddressExclusion", "removeExclusion", "autoStart" })
            Require(Named(form, name).Enabled, "A control did not recover after draining commands: " + name);
    }

    internal static async Task RunAsync(MainForm form, Action<string>? capture)
    {
        var visual = form.VisualState;
        var status = Named(form, "connectionStatus");
        string text = status.Text;
        form.NavigateTo("overview");
        try
        {
            await DefaultClicksAreHarmless(form);
            await OrderedClicks(form, retry: false, firstRelease: false, firstTray: false, failOwner: true, capture);
            await OrderedClicks(form, retry: true, firstRelease: true, firstTray: false, failOwner: false, capture);
            await OrderedClicks(form, retry: true, firstRelease: false, firstTray: true, failOwner: true, capture);
            await RepeatedClicksAreNotCoalesced(form);
            await FailedStopDoesNotPoisonQueue(form);
            await ScopeRetainsQueuedCallback(form);
            await DeferredRecoveryDoesNotRearmAfterRelease(form);
            await CloseToTrayKeepsPendingStop(form);
            await DisposeDropsPendingCommands(form);
            await DefaultClicksAreHarmless(form);
            IdleControls(form);
            capture?.Invoke("ui-stop-queue-after.png");
        }
        finally
        {
            form.SetVisualState(visual);
            status.Text = text;
            form.NavigateTo("overview");
        }
    }

    static async Task DefaultClicksAreHarmless(MainForm form)
    {
        var protection = (ProtectionController)typeof(MainForm).GetField("protection", Instance)!.GetValue(form)!;
        var before = (protection.ConnectWanted, protection.ProtectionRequired, protection.ActiveLuid);
        Task tail = form.WaitForCommandsForUiTestAsync();
        Click(form, release: false, tray: false);
        Click(form, release: true, tray: false);
        Click(form, release: false, tray: true);
        Click(form, release: true, tray: true);
        await Await(form.WaitForCommandsForUiTestAsync());
        Require(ReferenceEquals(tail, form.WaitForCommandsForUiTestAsync()), "Unscoped observe-only clicks joined the command queue.");
        Require(before == (protection.ConnectWanted, protection.ProtectionRequired, protection.ActiveLuid),
            "Unscoped observe-only clicks changed protection intent.");
        IdleControls(form);
    }

    static async Task OrderedClicks(MainForm form, bool retry, bool firstRelease, bool firstTray, bool failOwner, Action<string>? capture)
    {
        var ownerEntered = Signal(); var finishOwner = Signal();
        var cleanupEntered = Signal(); var finishCleanup = Signal();
        var firstEntered = Signal(); var finishFirst = Signal();
        var secondEntered = Signal(); var finishSecond = Signal();
        var trace = new List<string>();
        int active = 0, callbacks = 0, retryOvertakes = 0;
        bool connectWanted = true;
        Task? owner = null;
        string prefix = retry ? firstRelease ? "retry-release" : "retry-block" : "connect-block";
        async Task Stop(string name)
        {
            Require(++active == 1, "Queued stop/release overlapped the owner or another command.");
            int index = ++callbacks;
            Require(index <= 2, "A queued click was executed twice.");
            trace.Add(name + ".enter");
            connectWanted = false; // Synthetic mutation must happen only under the command gate.
            try
            {
                (index == 1 ? firstEntered : secondEntered).TrySetResult();
                await (index == 1 ? finishFirst.Task : finishSecond.Task);
            }
            finally { trace.Add(name + ".exit"); active--; }
        }
        using var scope = form.OverrideStopCommandsForUiTest(() => Stop("block"), () => Stop("release"));
        try
        {
            async Task Owner()
            {
                Require(++active == 1, "Owner overlapped a prior command.");
                trace.Add("owner.enter"); ownerEntered.TrySetResult();
                try
                {
                    await finishOwner.Task;
                    if (failOwner) throw new IOException("QA synthetic connect/retry failure before queued stop");
                }
                finally
                {
                    cleanupEntered.TrySetResult();
                    await finishCleanup.Task;
                    trace.Add("owner.exit"); active--;
                }
            }
            owner = retry ? form.RunRetryForUiTestAsync(Owner) : form.RunCommandForUiTestAsync(Owner);
            await Await(ownerEntered.Task);
            BusyControls(form);
            capture?.Invoke("ui-stop-" + prefix + "-busy.png");
            Click(form, firstRelease, firstTray);
            Click(form, !firstRelease, !firstTray);
            Task drain = form.WaitForCommandsForUiTestAsync();
            Require(!drain.IsCompleted && callbacks == 0 && connectWanted,
                "A click mutated state before the current attempt and cleanup completed.");
            // These all traverse the real background scheduler. No timer delay
            // or external network timing participates in the starvation check.
            for (int tick = 0; tick < 100; tick++)
                await Await(form.RunRetryForUiTestAsync(() => { retryOvertakes++; return Task.CompletedTask; }));
            Require(retryOvertakes == 0 && callbacks == 0 && active == 1,
                "Repeated retry ticks overtook pending user commands.");
            BusyControls(form);
            capture?.Invoke("ui-stop-" + prefix + "-queued.png");
            finishOwner.TrySetResult();
            await Await(cleanupEntered.Task);
            Require(callbacks == 0 && connectWanted && active == 1,
                "A user command ran before the current attempt's awaited cleanup completed.");
            finishCleanup.TrySetResult();
            await Await(firstEntered.Task);
            await Await(owner);
            Require(callbacks == 1 && !connectWanted && !secondEntered.Task.IsCompleted,
                "First queued click was starved, duplicated, or overlapped by the second.");
            BusyControls(form);
            for (int tick = 0; tick < 100; tick++)
                await Await(form.RunRetryForUiTestAsync(() => { retryOvertakes++; return Task.CompletedTask; }));
            Require(retryOvertakes == 0, "Retry entered between queued stop/release commands.");
            finishFirst.TrySetResult();
            await Await(secondEntered.Task);
            BusyControls(form);
            finishSecond.TrySetResult();
            await Await(drain);
            string first = firstRelease ? "release" : "block", second = firstRelease ? "block" : "release";
            Require(trace.SequenceEqual(new[] { "owner.enter", "owner.exit", first + ".enter", first + ".exit", second + ".enter", second + ".exit" }),
                "Actual window/tray clicks did not preserve FIFO execution order.");
            Require(callbacks == 2 && active == 0, "The command queue did not fully drain.");
            IdleControls(form);
        }
        finally
        {
            finishOwner.TrySetResult(); finishCleanup.TrySetResult(); finishFirst.TrySetResult(); finishSecond.TrySetResult();
            if (owner != null) await Await(owner);
            await Await(form.WaitForCommandsForUiTestAsync());
        }
    }

    static async Task RepeatedClicksAreNotCoalesced(MainForm form)
    {
        var entered = Signal(); var finish = Signal();
        int blocks = 0;
        using var scope = form.OverrideStopCommandsForUiTest(
            () => { blocks++; return Task.CompletedTask; }, () => Task.CompletedTask);
        Task owner = form.RunRetryForUiTestAsync(async () => { entered.TrySetResult(); await finish.Task; });
        try
        {
            await Await(entered.Task);
            Click(form, release: false, tray: false);
            Click(form, release: false, tray: false);
            Click(form, release: false, tray: true);
            Require(blocks == 0, "Repeated stop clicks bypassed the active retry.");
            finish.TrySetResult();
            await Await(form.WaitForCommandsForUiTestAsync());
            Require(blocks == 3, "Repeated stop clicks were dropped or coalesced.");
            IdleControls(form);
        }
        finally { finish.TrySetResult(); await Await(owner); await Await(form.WaitForCommandsForUiTestAsync()); }
    }

    static async Task FailedStopDoesNotPoisonQueue(MainForm form)
    {
        var entered = Signal(); var finish = Signal();
        var trace = new List<string>();
        using var scope = form.OverrideStopCommandsForUiTest(
            () => { trace.Add("block"); throw new IOException("QA synthetic queued block failure"); },
            () => { trace.Add("release"); return Task.CompletedTask; });
        Task owner = form.RunCommandForUiTestAsync(async () => { entered.TrySetResult(); await finish.Task; });
        try
        {
            await Await(entered.Task);
            Click(form, release: false, tray: false);
            Click(form, release: true, tray: false);
            finish.TrySetResult();
            await Await(form.WaitForCommandsForUiTestAsync());
            Require(trace.SequenceEqual(new[] { "block", "release" }), "Failed queued stop blocked or reordered the following release.");
            IdleControls(form);
        }
        finally { finish.TrySetResult(); await Await(owner); await Await(form.WaitForCommandsForUiTestAsync()); }
    }

    static async Task ScopeRetainsQueuedCallback(MainForm form)
    {
        var entered = Signal(); var finish = Signal();
        int blocks = 0, releases = 0;
        IDisposable? scope = form.OverrideStopCommandsForUiTest(
            () => { blocks++; return Task.CompletedTask; }, () => { releases++; return Task.CompletedTask; });
        Task owner = form.RunCommandForUiTestAsync(async () => { entered.TrySetResult(); await finish.Task; });
        try
        {
            await Await(entered.Task);
            bool nestedRejected = false;
            try
            {
                using var nested = form.OverrideStopCommandsForUiTest(() => Task.CompletedTask, () => Task.CompletedTask);
            }
            catch (InvalidOperationException) { nestedRejected = true; }
            Require(nestedRejected, "Nested synthetic callback scopes were accepted.");
            Click(form, release: false, tray: false);
            Task accepted = form.WaitForCommandsForUiTestAsync();
            scope.Dispose(); scope = null;
            Click(form, release: true, tray: false);
            Require(ReferenceEquals(accepted, form.WaitForCommandsForUiTestAsync()), "A click after scope disposal entered the queue.");
            finish.TrySetResult();
            await Await(accepted);
            Require(blocks == 1 && releases == 0, "Scope disposal lost the captured callback or enabled a production fallback.");
        }
        finally { scope?.Dispose(); finish.TrySetResult(); await Await(owner); await Await(form.WaitForCommandsForUiTestAsync()); }
    }

    static async Task CloseToTrayKeepsPendingStop(MainForm form)
    {
        var entered = Signal(); var finish = Signal();
        int calls = 0;
        using var scope = form.OverrideStopCommandsForUiTest(() => { calls++; return Task.CompletedTask; }, () => Task.CompletedTask);
        Task owner = form.RunCommandForUiTestAsync(async () => { entered.TrySetResult(); await finish.Task; });
        try
        {
            await Await(entered.Task);
            Click(form, release: false, tray: false);
            form.Close();
            Require(!form.Visible && !form.IsDisposed && calls == 0, "Close-to-tray disposed the form or bypassed the gate.");
            finish.TrySetResult();
            await Await(form.WaitForCommandsForUiTestAsync());
            Require(calls == 1, "Hiding to tray discarded the accepted stop command.");
        }
        finally
        {
            finish.TrySetResult(); await Await(owner); await Await(form.WaitForCommandsForUiTestAsync());
            form.Show(); form.NavigateTo("overview");
        }
    }

    static async Task DeferredRecoveryDoesNotRearmAfterRelease(MainForm form)
    {
        var pending = typeof(MainForm).GetField("pendingConnectionFailure", Instance)!;
        var recover = typeof(MainForm).GetMethod("RecoverPendingConnectionFailure", Instance)
            ?? throw new InvalidOperationException("Deferred recovery helper is missing.");
        var protection = (ProtectionController)typeof(MainForm).GetField("protection", Instance)!.GetValue(form)!;
        Require(!protection.ProtectionRequired && !protection.ConnectWanted, "Synthetic released-state prerequisite is not satisfied.");
        object? previousFailure = pending.GetValue(form);
        var visual = form.VisualState;
        var status = Named(form, "connectionStatus");
        string statusText = status.Text;
        var log = Named(form, "startupLog");
        var entered = Signal(); var finish = Signal();
        var order = new List<string>();
        Task? owner = null, recovery = null;
        using var scope = form.OverrideStopCommandsForUiTest(() => Task.CompletedTask,
            () => { order.Add("release"); pending.SetValue(form, null); return Task.CompletedTask; });
        Task Recover() => (Task)recover.Invoke(form, null)!;
        void RequireUnchanged(string logBefore)
        {
            Require(!protection.ProtectionRequired && !protection.ConnectWanted,
                "A stale deferred recovery rearmed protection after release.");
            Require(form.VisualState == visual && status.Text == statusText,
                "A stale deferred recovery changed the released presentation.");
            Require(log.Text == logBefore, "A stale deferred recovery produced connection/recovery UI log entries.");
        }
        try
        {
            pending.SetValue(form, new IOException("QA synthetic stale engine notification"));
            owner = form.RunCommandForUiTestAsync(async () => { entered.TrySetResult(); await finish.Task; });
            await Await(entered.Task);
            Click(form, release: true, tray: false);
            recovery = form.RunCommandForUiTestAsync(async () => { order.Add("recovery-check"); await Recover(); });
            Require(order.Count == 0, "Release/recovery executed before the active command completed.");
            string beforeDrain = log.Text; // Includes the allowed queue notice.
            finish.TrySetResult();
            await Await(recovery); await Await(owner);
            Require(order.SequenceEqual(new[] { "release", "recovery-check" }) && pending.GetValue(form) == null,
                "Deferred recovery did not observe the state cleared by the preceding release.");
            RequireUnchanged(beforeDrain);

            var stale = new IOException("QA synthetic late engine notification after release");
            pending.SetValue(form, stale);
            string beforeStale = log.Text;
            await Await(form.RunCommandForUiTestAsync(Recover));
            Require(ReferenceEquals(pending.GetValue(form), stale), "Inactive protection consumed a stale failure as a recovery request.");
            RequireUnchanged(beforeStale);
        }
        finally
        {
            finish.TrySetResult();
            if (owner != null) await Await(owner);
            if (recovery != null) await Await(recovery);
            pending.SetValue(form, previousFailure);
        }
    }

    static async Task DisposeDropsPendingCommands(MainForm ownerForm)
    {
        using var form = new MainForm(false, startup: false, observeOnly: true);
        Tray(form).Visible = false;
        form.Show(ownerForm);
        form.NavigateTo("overview");
        var entered = Signal(); var finish = Signal();
        int calls = 0;
        using var scope = form.OverrideStopCommandsForUiTest(() => { calls++; return Task.CompletedTask; }, () => { calls++; return Task.CompletedTask; });
        Task owner = form.RunCommandForUiTestAsync(async () => { entered.TrySetResult(); await finish.Task; });
        Task? drain = null;
        try
        {
            await Await(entered.Task);
            Click(form, release: false, tray: false);
            Click(form, release: true, tray: true);
            drain = form.WaitForCommandsForUiTestAsync();
            form.Dispose();
            finish.TrySetResult();
            await Await(owner); await Await(drain);
            Require(calls == 0 && form.IsDisposed, "A queued command mutated state after form disposal.");
        }
        finally
        {
            finish.TrySetResult(); await Await(owner);
            if (drain != null) await Await(drain);
        }
    }
}
