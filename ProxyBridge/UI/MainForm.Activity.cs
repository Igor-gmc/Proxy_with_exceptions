using System.Diagnostics;

namespace ProxyBridge;

internal sealed partial class MainForm
{
    readonly ActivityMonitor activityMonitor = new();
    readonly SemaphoreSlim activityGate = new(1, 1);
    bool changingActivityCheck, activitySettingsUsable;
    int pendingActivityChanges;
    string? activityOperationError, displayedActivityError;
    string? displayedLogError;
    bool writingUserNote;

    void WireActivityEvents()
    {
        activityLogging.CheckedChanged += OnActivityLoggingChanged;
        openActivityLog.Click += (_, _) => OpenActivityLog();
        activityMonitor.StateChanged += ActivityStateChanged;
    }

    async void OnActivityLoggingChanged(object? sender, EventArgs e)
    {
        if (changingActivityCheck || OperationsClosed || observeOnly)
        {
            return;
        }

        await ChangeActivityLoggingAsync(activityLogging.Checked, savePreference: true);
    }

    void ActivityStateChanged()
    {
        try
        {
            if (!OperationsClosed && IsHandleCreated)
            {
                BeginInvoke(() => { if (!OperationsClosed) { RefreshActivityStatus(); } });
            }
        }
        catch (InvalidOperationException) { }
    }
    void RefreshActivityStatus()
    {
        if (OperationsClosed)
        {
            return;
        }

        activityLogging.Enabled = !observeOnly && activitySettingsUsable && pendingActivityChanges == 0;
        openActivityLog.Enabled = !observeOnly;
        string? error = activityOperationError ?? activityMonitor.LastError;
        if (observeOnly)
        {
            activityStatus.Text = "Предпросмотр · запись не запускается";
            activityStatus.ForeColor = AppTheme.Muted;
        }
        else if (!activitySettingsUsable)
        {
            activityStatus.Text = "Сначала сохраните исправленные настройки";
            activityStatus.ForeColor = AppTheme.Amber;
        }
        else if (error != null)
        {
            activityStatus.Text = activityMonitor.Running ? "Ошибка журнала · мониторинг работает" : "Ошибка журнала активности";
            activityStatus.ForeColor = AppTheme.Red;
            if (displayedActivityError != error)
            {
                displayedActivityError = error;
                AppLog.Write("ACTIVITY error: " + error);
            }
        }
        else if (pendingActivityChanges != 0)
        {
            activityStatus.Text = activityLogging.Checked ? "Включение записи…" : "Остановка записи…";
            activityStatus.ForeColor = AppTheme.Amber;
        }
        else
        {
            activityStatus.Text = activityMonitor.Running ? "Запись включена · процессы и подключения" : "Запись выключена";
            activityStatus.ForeColor = activityMonitor.Running ? AppTheme.Green : AppTheme.Muted;
            displayedActivityError = null;
        }
        hints.SetToolTip(activityStatus, error == null ? activityMonitor.FilePath : error);
    }
    async Task ChangeActivityLoggingAsync(bool requested, bool savePreference)
    {
        if (observeOnly || OperationsClosed || !activitySettingsUsable)
        {
            return;
        }

        bool entered = false;
        pendingActivityChanges++;
        RefreshActivityStatus();
        try
        {
            await activityGate.WaitAsync();
            entered = true;
            if (OperationsClosed)
            {
                return;
            }

            activityOperationError = null;
            if (savePreference)
            {
                // Persist only the metadata preference. Unsaved proxy fields
                // and exclusions stay untouched; no protection operation runs.
                var next = settings with
                {
                    ActivityLoggingEnabled = requested
                };
                next.Save();
                settings = next;
            }
            if (requested)
            {
                await activityMonitor.StartAsync();
            }
            else
            {
                await activityMonitor.StopAsync();
            }

            if (OperationsClosed)
            {
                return;
            }

            AppLog.Write($"ACTIVITY preference={settings.ActivityLoggingEnabled}; running={activityMonitor.Running}");
        }
        catch (Exception ex)
        {
            activityOperationError = AppLog.ExceptionCodes(ex);
            if (!OperationsClosed)
            {
                changingActivityCheck = true;
                try
                {
                    activityLogging.Checked = settings.ActivityLoggingEnabled;
                }
                finally { changingActivityCheck = false; }
            }
        }
        finally
        {
            pendingActivityChanges--;
            if (entered)
            {
                activityGate.Release();
            }

            if (!OperationsClosed)
            {
                RefreshActivityStatus();
            }
        }
    }
    void ActivitySettingsSaved()
    {
        if (activitySettingsUsable)
        {
            return;
        }

        activitySettingsUsable = true;
        // This path follows first-time setup or a previously failed settings load. The method
        // contains its own error handling and does not touch the network gate.
        _ = ChangeActivityLoggingAsync(settings.ActivityLoggingEnabled, savePreference: false);
        RefreshActivityStatus();
    }
    void OpenActivityLog()
    {
        if (observeOnly || OperationsClosed)
        {
            return;
        }

        try
        {
            if (!File.Exists(activityMonitor.FilePath))
            {
                activityOperationError = "Журнал активности ещё не создан.";
                RefreshActivityStatus();
                return;
            }
            using var viewer = Process.Start(new ProcessStartInfo(activityMonitor.FilePath) { UseShellExecute = true });
            activityOperationError = null;
        }
        catch (Exception ex) { activityOperationError = AppLog.ExceptionCodes(ex); }
        RefreshActivityStatus();
    }
    async Task WriteUserNoteAsync()
    {
        if (writingUserNote || OperationsClosed)
        {
            return;
        }

        string original = userLogNote.Text;
        string note = original;
        if (string.IsNullOrWhiteSpace(note))
        {
            return;
        }

        note = AppLog.Redact(note, password.Text, settings.Password);
        string normalized = note.Replace("\r\n", "\n").Replace('\r', '\n').Replace('\u0085', '\n').Replace('\u2028', '\n').Replace('\u2029', '\n');
        string entry = string.Join(Environment.NewLine, normalized.Split('\n').Select(line => "Заметка пользователя: " + line));
        entry = AppLog.Redact(entry, password.Text, settings.Password);
        writingUserNote = true;
        writeLogNote.Enabled = false;
        try
        {
            bool saved = await AppLog.WriteConfirmedAsync(entry);
            if (OperationsClosed)
            {
                return;
            }

            Append(entry, false);
            // Edits made while the writer was pending belong to the user and
            // must survive confirmation of the older submitted text.
            if (saved && userLogNote.Text == original)
            {
                userLogNote.Clear();
            }
            else if (!saved)
            {
                Append("Заметка не подтверждена в файле журнала. Текст оставлен в поле для повторной записи.", false);
            }
        }
        catch (Exception ex)
        {
            if (!OperationsClosed)
            {
                Append("Заметка не записана: " + AppLog.ExceptionCodes(ex), false);
            }
        }
        finally
        {
            writingUserNote = false;
            if (!OperationsClosed)
            {
                writeLogNote.Enabled = true;
            }
        }
    }
    void Append(string text) => Append(text, true);
    void Append(string text, bool persist) => AppendAt(DateTimeOffset.Now, Stopwatch.GetTimestamp(), text, persist);
    void AppendAt(DateTimeOffset eventTime, long monoTicks, string text, bool persist)
    {
        text = AppLog.Redact(text, password.Text, settings.Password);
        if (persist)
        {
            AppLog.WriteAt(eventTime, monoTicks, text);
        }

        if (IsDisposed || log.IsDisposed)
        {
            return;
        }

        if (log.TextLength > 24000)
        {
            log.Clear();
        }

        log.AppendText($"{eventTime:HH:mm:ss}  {text}{Environment.NewLine}");
        string? writeError = AppLog.LastError;
        if (writeError != null && writeError != displayedLogError)
        {
            log.AppendText($"{DateTime.Now:HH:mm:ss}  Не удалось записать журнал на диск ({writeError}). Файл: {AppLog.FilePath}{Environment.NewLine}");
        }

        displayedLogError = writeError;
        RefreshOverviewSummary();
    }
}
