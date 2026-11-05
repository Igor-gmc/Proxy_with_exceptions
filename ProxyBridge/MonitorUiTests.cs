namespace ProxyBridge;

// Observe-only UI harness: every action is synthetic. No Guard, Engine or network calls.
internal static class MonitorUiTests
{
    static void Require(bool value, string message)
    {
        if (!value) throw new InvalidOperationException(message);
    }
    static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    static Task Await(Task task) => task.WaitAsync(TimeSpan.FromSeconds(10));
    static IEnumerable<Control> Descendants(Control parent)
    {
        foreach (Control child in parent.Controls) {
            yield return child;
            foreach (var nested in Descendants(child)) yield return nested;
        }
    }

    internal static async Task RunAsync(MainForm form, Action<string>? capture = null)
    {
        string[] names = ["connect", "apply", "block", "release", "speed", "host", "port", "username", "password",
            "protocol", "exclusions", "addExclusion", "removeExclusion", "autoStart"];
        var all = Descendants(form).ToArray();
        var controls = names.Select(name => all.Single(c => c.Name == name)).ToArray();
        Require(controls.All(c => c.Enabled), "UI scheduler test requires initially enabled controls.");
        var initialVisual = form.VisualState;
        var status = all.Single(c => c.Name == "connectionStatus");
        string initialStatus = status.Text;
        int changes = 0;
        bool expectDisabled = false, prematureEnable = false;
        void EnabledChanged(object? sender, EventArgs args)
        {
            changes++;
            if (expectDisabled && sender is Control { Enabled: true }) prematureEnable = true;
        }
        foreach (var control in controls) control.EnabledChanged += EnabledChanged;
        try {
            // Exercise the production command gate with a harmless callback.
            // A broken guard cannot start a real connection in this regression.
            int rejectedCallbackCalls = 0;
            var execute = typeof(MainForm).GetMethod("Execute",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic,
                null, [typeof(Func<Task>), typeof(string), typeof(bool), typeof(bool)], null)
                ?? throw new InvalidOperationException("Observe-only command gate is missing.");
            Func<Task> rejectedCallback = () => { rejectedCallbackCalls++; return Task.CompletedTask; };
            var rejected = execute.Invoke(form, [rejectedCallback, "ui-test.rejected", false, false]) as Task
                ?? throw new InvalidOperationException("Observe-only command gate returned no task.");
            await Await(rejected);
            Require(rejectedCallbackCalls == 0, "Observe-only UI accepted a non-synthetic command.");
            Require(changes == 0 && controls.All(c => c.Enabled), "Rejected command changed control availability.");
            Require(form.VisualState == initialVisual && status.Text == initialStatus,
                "Rejected command changed connection presentation.");
            capture?.Invoke("ui-monitor-before.png");
            for (int i = 0; i < 2; i++) {
                var entered = Signal(); var finish = Signal();
                var monitor = form.RunMonitorForUiTestAsync(async token => {
                    entered.SetResult();
                    await finish.Task.WaitAsync(token);
                });
                try {
                    await Await(entered.Task);
                    Require(controls.All(c => c.Enabled), "Healthy monitor disabled controls during its await.");
                    if (i == 0) capture?.Invoke("ui-monitor-during.png");
                } finally { finish.TrySetResult(); await Await(monitor); }
            }
            Require(changes == 0 && controls.All(c => c.Enabled), "Healthy monitor caused EnabledChanged flicker.");
            Require(form.VisualState == initialVisual, "Healthy monitor changed connection visual state.");
            capture?.Invoke("ui-monitor-after.png");

            var probeEntered = Signal(); var cancellationObserved = Signal(); var allowProbeFinally = Signal();
            var firstEntered = Signal(); var finishFirst = Signal(); var secondEntered = Signal(); var finishSecond = Signal();
            bool probeFinallyCompleted = false;
            int activeCommands = 0, executedCommands = 0;
            Task? first = null, second = null;
            var background = form.RunMonitorForUiTestAsync(async token => {
                try {
                    probeEntered.SetResult();
                    await Task.Delay(Timeout.Infinite, token);
                } catch (OperationCanceledException) when (token.IsCancellationRequested) {
                    cancellationObserved.TrySetResult();
                    throw;
                } finally {
                    await allowProbeFinally.Task;
                    probeFinallyCompleted = true;
                }
            });
            try {
                await Await(probeEntered.Task);
                capture?.Invoke("ui-command-before.png");
                expectDisabled = true;
                first = form.RunCommandForUiTestAsync(async () => {
                    Require(probeFinallyCompleted, "Manual command ran before the canceled probe finally completed.");
                    Require(++activeCommands == 1, "Manual commands overlapped.");
                    executedCommands++;
                    try { firstEntered.SetResult(); await finishFirst.Task; }
                    finally { activeCommands--; }
                });
                await Await(cancellationObserved.Task);
                Require(!firstEntered.Task.IsCompleted, "Cancellation request was mistaken for probe completion.");
                Require(controls.All(c => !c.Enabled), "Pending manual command did not disable controls.");
                Require(form.VisualState == initialVisual, "User cancellation was reported as a connection failure.");

                form.NavigateTo("overview");
                form.PerformLayout();
                capture?.Invoke("ui-command-cancel-pending.png");
                if (capture != null) capture("ui-disabled.png");
                else using (var bitmap = new Bitmap(form.Width, form.Height)) {
                    form.DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size));
                    bitmap.Save(Path.Combine(AppContext.BaseDirectory, "ui-disabled.png"));
                }

                allowProbeFinally.TrySetResult();
                await Await(firstEntered.Task);
                await Await(background);
                Require(status.Text == initialStatus, "Caller cancellation was displayed as an operation error.");
                capture?.Invoke("ui-command-executing.png");
                second = form.RunCommandForUiTestAsync(async () => {
                    Require(++activeCommands == 1, "Queued manual commands overlapped.");
                    executedCommands++;
                    try { secondEntered.SetResult(); await finishSecond.Task; }
                    finally { activeCommands--; }
                });
                Require(!secondEntered.Task.IsCompleted, "Second manual command bypassed the active command.");
                capture?.Invoke("ui-command-queued.png");
                finishFirst.TrySetResult();
                await Await(secondEntered.Task);
                await Await(first);
                Require(controls.All(c => !c.Enabled) && !prematureEnable,
                    "Controls were enabled between pending manual commands.");
                capture?.Invoke("ui-command-second-executing.png");
                expectDisabled = false;
                finishSecond.TrySetResult();
                await Await(second);
                Require(executedCommands == 2 && activeCommands == 0, "Queued manual command was rejected or duplicated.");
                Require(controls.All(c => c.Enabled), "Controls were not restored after the final command.");
                Require(form.VisualState == initialVisual, "Canceled monitor changed connection state after joining.");
                capture?.Invoke("ui-command-after.png");
            } finally {
                expectDisabled = false;
                allowProbeFinally.TrySetResult(); finishFirst.TrySetResult(); finishSecond.TrySetResult();
                await Await(background);
                if (first != null) await Await(first);
                if (second != null) await Await(second);
            }

            bool failingActionRan = false, followingActionRan = false;
            Exception? captureFailure = null;
            capture?.Invoke("ui-failure-before.png");
            await Await(form.RunCommandForUiTestAsync(() => {
                failingActionRan = true;
                try { capture?.Invoke("ui-failure-during.png"); }
                catch (Exception error) { captureFailure = error; throw; }
                throw new IOException("QA synthetic command failure");
            }));
            if (captureFailure != null) throw new IOException("UI failure-state capture failed.", captureFailure);
            Require(failingActionRan && controls.All(c => c.Enabled), "Failed command retained the UI lock.");
            capture?.Invoke("ui-failure-after.png");
            await Await(form.RunCommandForUiTestAsync(() => { followingActionRan = true; return Task.CompletedTask; }));
            Require(followingActionRan && controls.All(c => c.Enabled), "Failed command retained the scheduler gate.");
            Require(form.VisualState == initialVisual, "Unrelated command failure changed connection state.");
            capture?.Invoke("ui-followup-after.png");
        } finally {
            foreach (var control in controls) control.EnabledChanged -= EnabledChanged;
        }
    }
}
