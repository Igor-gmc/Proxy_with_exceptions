using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ProxyBridge;

internal sealed record EngineLogObservation(DateTimeOffset EventTime, long MonoTicks, long EngineGeneration, string Message);
internal sealed class Engine : IDisposable
{
    public static string Executable => Path.Combine(BundledAssets.DirectoryPath, "core", "sing-box.exe");
    public static string ConfigPath => RuntimeStorage.ConfigPath;
    Process? process;
    DateTimeOffset? processStartedUtc;
    EngineConsole.OwnedChild? child;
    IntPtr job;
    long generation, stoppingGeneration = -1;
    public long Generation => Interlocked.Read(ref generation);
    public event Action<long>? Exited;
    public bool Running => process is { HasExited: false };
    public int? ProcessId
    {
        get
        {
            try
            {
                return process?.Id;
            }
            catch (InvalidOperationException) { return null; }
        }
    }
    public DateTimeOffset? ProcessStartedUtc => process == null ? null : processStartedUtc;
    public bool LastStopForced
    { get; private set; }
    public event Action<string>? Log;
    public event Action<EngineLogObservation>? ObservedLog;
    void EmitLog(string message, long? sourceGeneration = null, bool engineOutput = false, int? sourcePid = null)
    {
        var eventTime = DateTimeOffset.Now;
        long mono = Stopwatch.GetTimestamp();
        long observedGeneration = sourceGeneration ?? Generation;
        if (engineOutput)
        {
            bool expectedStop = Interlocked.Read(ref stoppingGeneration) == observedGeneration;
            string category = EngineOutputClassifier.Classify(message);
            try
            {
                var evidence = new
                {
                    EngineGeneration = observedGeneration,
                    EnginePid = sourcePid,
                    Category = category,
                    ExpectedStop = expectedStop
                };
                DiagnosticJournal.Record("engine.output", evidence, eventTime, mono);
                if (EngineOutputClassifier.ShouldTrigger(category, expectedStop))
                {
                    DiagnosticJournal.Trigger(category, evidence);
                }
            }
            catch { /* Ring diagnostics cannot interfere with draining stdout. */ }
            message = $"[generation={observedGeneration}] " + message;
        }
        // The production subscriber uses bounded AppLog.WriteAt, so stdout
        // draining never waits for its disk writer or the UI dispatcher.
        try
        {
            ObservedLog?.Invoke(new(eventTime, mono, observedGeneration, message));
        }
        catch { }
        try
        {
            Log?.Invoke(message);
        }
        catch { }
    }
    [DllImport("ProxyGuard.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)] static extern IntPtr CreateEngineJob();
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
    public static string Configuration(Settings settings) => EngineConfiguration.Create(settings);

    public async Task Check(Settings s)
    {
        var elapsed = Stopwatch.StartNew();
        bool completed = false;
        string failure = "none";
        AppLog.Write($"ENGINE check.begin generation={Generation}");
        try
        {
            await CheckCore(s);
            completed = true;
        }
        catch (Exception ex) { failure = ex.GetType().Name; throw; }
        finally { AppLog.Write($"ENGINE check.end succeeded={completed} elapsedMs={elapsed.ElapsedMilliseconds} errorType={failure} generation={Generation}"); }
    }
    async Task CheckCore(Settings s)
    {
        s.Validate();
        RuntimeStorage.Prepare();
        try
        {
            File.WriteAllText(ConfigPath, Configuration(s));
            using var check = new Process { StartInfo = StartInfo("check") };
            check.Start();
            AppLog.Write($"ENGINE check.process-start pid={check.Id} generation={Generation}");
            var error = check.StandardError.ReadToEndAsync();
            var output = check.StandardOutput.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            try
            {
                await check.WaitForExitAsync(timeout.Token);
            }
            catch
            {
                try
                {
                    if (!check.HasExited)
                    {
                        check.Kill(true);
                    }
                }
                catch (InvalidOperationException) when (check.HasExited) { }
                throw;
            }
            await output;
            string details = await error;
            AppLog.Write($"ENGINE check.process-exit pid={check.Id} exitCode={check.ExitCode} generation={Generation}");
            if (check.ExitCode != 0)
            {
                throw new InvalidOperationException("Конфигурация sing-box: " + details);
            }
        }
        catch
        {
            DeleteConfig();
            throw;
        }
    }
    static ProcessStartInfo StartInfo(string verb)
    {
        var info = new ProcessStartInfo(Executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = Path.GetDirectoryName(Executable)! };
        info.ArgumentList.Add(verb);
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add(ConfigPath);
        return info;
    }
    public void Start()
    {
        if (Running)
        {
            throw new InvalidOperationException("Туннель уже запущен.");
        }

        if (child != null || job != IntPtr.Zero)
        {
            throw new InvalidOperationException("Сначала завершите очистку предыдущего движка.");
        }

        var nextJob = CreateEngineJob();
        if (nextJob == IntPtr.Zero)
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }

        long nextGeneration = Interlocked.Increment(ref generation);
        processStartedUtc = null;
        long startedAt = Stopwatch.GetTimestamp();
        EngineConsole.OwnedChild? next = null;
        try
        {
            int? outputPid = null;
            next = EngineConsole.Start(Executable, ["run", "-c", ConfigPath], Path.GetDirectoryName(Executable)!,
                nextJob, message => EmitLog(message, nextGeneration, engineOutput: true, sourcePid: outputPid));
            var startedProcess = next.Process;
            // Capture identity once from the owned process. Reading diagnostic
            // context later is memory-only and cannot reopen a reused PID.
            try
            {
                processStartedUtc = new DateTimeOffset(startedProcess.StartTime.ToUniversalTime());
            }
            catch { /* Missing process metadata must not change startup. */ }
            int startedPid = startedProcess.Id;
            outputPid = startedPid;
            next.Process.Exited += (_, _) => ObserveProcessExit(startedProcess, startedPid, nextGeneration, startedAt);
            next.Process.EnableRaisingEvents = true;
            process = next.Process;
            child = next;
            job = nextJob;
            LastStopForced = false;
            next.Resume();
            EmitLog($"Движок запущен в отдельной скрытой консоли: PID {process.Id}, поколение {nextGeneration}.");
        }
        catch
        {
            Interlocked.Exchange(ref stoppingGeneration, nextGeneration);
            // Retain failed cleanup for Stop to retry; no running process starts
            // before it belongs to the kill-on-close job.
            if (CloseHandle(nextJob))
            {
                job = IntPtr.Zero;
                if (next != null)
                {
                    try
                    {
                        if (next.Process.WaitForExit(10000))
                        {
                            next.Dispose();
                            child = null;
                            process = null;
                        }
                        else
                        {
                            child = next;
                            process = next.Process;
                        }
                    }
                    catch { child = next; process = next.Process; }
                }
            }
            else
            {
                job = nextJob;
                child = next;
                process = next?.Process;
            }
            if (process == null)
            {
                DeleteConfig();
            }

            throw;
        }
    }

    void ObserveProcessExit(Process startedProcess, int startedPid, long nextGeneration, long startedAt)
    {
        bool expected = Interlocked.Read(ref stoppingGeneration) == nextGeneration;
        string exitCode;
        try
        {
            exitCode = startedProcess.ExitCode.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        catch (Exception ex) { exitCode = "unavailable:" + ex.GetType().Name; }
        try
        {
            var evidence = new
            {
                EnginePid = startedPid,
                EngineGeneration = nextGeneration,
                ExpectedStop = expected,
                ExitCode = exitCode
            };
            DiagnosticJournal.Record("engine.exit", evidence);
            if (!expected)
            {
                DiagnosticJournal.Trigger("unexpected-engine-exit", evidence);
            }
        }
        catch { }
        AppLog.Write($"ENGINE process-exit pid={startedPid} generation={nextGeneration} currentGeneration={Generation} " +
            $"expectedStop={expected} exitCode={exitCode} lifetimeMs={Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds:F0}");
        if (!expected)
        {
            Exited?.Invoke(nextGeneration);
        }
    }

    async Task<int> RequestGracefulStop(Process current)
    {
        string helperPath = Environment.ProcessPath ?? throw new IOException("Не найден EXE для сигнала остановки.");
        var info = new ProcessStartInfo(helperPath) { UseShellExecute = false, CreateNoWindow = true };
        info.ArgumentList.Add("--signal-engine");
        info.ArgumentList.Add(current.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
        info.ArgumentList.Add(current.StartTime.ToUniversalTime().Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture));
        info.ArgumentList.Add(Executable);
        using var helper = new Process { StartInfo = info };
        if (!helper.Start())
        {
            throw new IOException("Не удалось запустить помощник остановки.");
        }

        try
        {
            await helper.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (Exception signalError)
        {
            var failures = new List<Exception> { signalError };
            try
            {
                if (!helper.HasExited)
                {
                    helper.Kill();
                }
            }
            catch (Exception ex) { failures.Add(ex); }
            try
            {
                await helper.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (Exception ex) { failures.Add(ex); }
            throw new AggregateException("Ошибка помощника штатной остановки.", failures);
        }
        return helper.ExitCode;
    }

    public async Task Stop()
    {
        var elapsed = Stopwatch.StartNew();
        long currentGeneration = Generation;
        bool completed = false;
        string failure = "none";
        AppLog.Write($"ENGINE stop.begin generation={currentGeneration} processPresent={process != null} jobPresent={job != IntPtr.Zero}");
        try
        {
            await StopCore();
            completed = true;
        }
        catch (Exception ex) { failure = ex.GetType().Name; throw; }
        finally
        {
            AppLog.Write($"ENGINE stop.end generation={currentGeneration} succeeded={completed} elapsedMs={elapsed.ElapsedMilliseconds} " +
                $"forced={LastStopForced} processRetained={process != null} jobRetained={job != IntPtr.Zero} errorType={failure}");
        }
    }
    async Task StopCore()
    {
        Interlocked.Exchange(ref stoppingGeneration, Generation);
        var errors = new List<Exception>();
        var current = process;
        bool exited = current == null;
        if (current != null)
        {
            try
            {
                if (!current.HasExited)
                {
                    await StopProcess(current);
                }
                exited = current.HasExited;
            }
            catch (Exception ex) { errors.Add(new InvalidOperationException("Остановка процесса движка: " + ex.Message, ex)); }
            if (exited && child != null)
            {
                try
                {
                    await child.DrainAsync().WaitAsync(TimeSpan.FromSeconds(5));
                }
                catch (Exception ex) { errors.Add(new InvalidOperationException("Чтение завершающих сообщений движка: " + ex.Message, ex)); }
            }
        }
        // Keep the job alive during graceful cleanup. Closing it earlier kills
        // sing-box before its route, adapter and WeakHostSend restoration runs.
        if (!exited && current != null && !LastStopForced)
        {
            LastStopForced = true;
            EmitLog("ПРЕДУПРЕЖДЕНИЕ: аварийное закрытие job движка. Восстановление сетевого окружения не подтверждено.");
        }
        if (job != IntPtr.Zero)
        {
            if (CloseHandle(job))
            {
                job = IntPtr.Zero;
            }
            else
            {
                errors.Add(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Не удалось закрыть job движка."));
            }
        }
        if (!exited && current != null)
        {
            // Job closure is a final kill fallback; still confirm termination
            // independently, even when the earlier Kill call or wait failed.
            LastStopForced = true;
            try
            {
                await current.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
                exited = current.HasExited;
                if (child != null)
                {
                    await child.DrainAsync().WaitAsync(TimeSpan.FromSeconds(5));
                }
            }
            catch (Exception ex) { errors.Add(new InvalidOperationException("Ожидание выхода после закрытия job: " + ex.Message, ex)); }
        }
        if (exited && current != null)
        {
            EmitLog($"Движок завершён: PID {current.Id}, код {current.ExitCode}, принудительно={LastStopForced}.");
            child?.Dispose();
            child = null;
            current.Dispose();
            process = null;
        }
        if (process == null)
        {
            try
            {
                DeleteConfig();
            }
            catch (Exception ex) { errors.Add(new InvalidOperationException("Удаление конфигурации движка: " + ex.Message, ex)); }
        }
        if (errors.Count != 0)
        {
            throw new AggregateException("Не удалось полностью остановить движок.", errors);
        }
    }
    async Task StopProcess(Process current)
    {
        EmitLog($"Штатная остановка движка: PID {current.Id}, ожидание Ctrl+C.");
        try
        {
            int result = await RequestGracefulStop(current);
            AppLog.Write($"ENGINE stop.signal generation={Generation} pid={current.Id} helperExitCode={result}");
            if (result == 0)
            {
                await current.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            }
            else
            {
                EmitLog($"Помощник штатной остановки вернул код {result}.");
            }
        }
        catch (Exception ex)
        {
            EmitLog("Штатная остановка не завершена: " + ex.Message);
        }
        if (!current.HasExited)
        {
            LastStopForced = true;
            EmitLog("ПРЕДУПРЕЖДЕНИЕ: принудительная остановка движка. Восстановление сетевого окружения движком не подтверждено.");
            // A failed kill must never skip the independent exit wait.
            try
            {
                current.Kill(true);
            }
            catch (Exception ex) { EmitLog("Запрос принудительной остановки: " + ex.Message); }
            await current.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    static void DeleteConfig()
    {
        if (File.Exists(ConfigPath))
        {
            File.Delete(ConfigPath);
        }
    }
    public void Dispose()
    {
        if (job != IntPtr.Zero)
        {
            CloseHandle(job);
            job = IntPtr.Zero;
        }
        child?.Dispose();
        child = null;
        process?.Dispose();
        process = null;
        try
        {
            DeleteConfig();
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
