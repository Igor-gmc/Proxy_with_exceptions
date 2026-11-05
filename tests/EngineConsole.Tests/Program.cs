using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using ProxyBridge;

internal static class Program
{
    static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
    static string Self => Environment.ProcessPath ?? throw new InvalidOperationException("No process path");

    static async Task<int> Main(string[] args)
    {
        if (args.Length == 4 && args[0] == "--signal")
        {
            return EngineConsole.Signal(int.Parse(args[1]), long.Parse(args[2]), args[3]);
        }

        if (args.Length >= 2 && args[0] == "--child")
        {
            return Child(args[1], args.Skip(2).ToArray());
        }

        if (!OperatingSystem.IsWindows())
        { Console.WriteLine("SKIP: Windows required"); return 2; }
        if (!Path.GetFileName(Self).Equals("EngineConsole.Tests.exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Run the generated apphost or dotnet run, not dotnet <dll>.");
        }

        string directory = Path.GetFullPath(args.Length == 1 ? args[0] : Path.Combine("artifacts", "engine-console-" + Guid.NewGuid().ToString("N")));
        Directory.CreateDirectory(directory);
        var results = new List<string>();
        int failures = 0;
        async Task Test(string name, Func<Task> test)
        {
            try
            { await test(); results.Add("PASS: " + name); }
            catch (Exception ex) { failures++; results.Add("FAIL: " + name + " (" + ex.GetType().Name + "): " + ex.Message); }
            Console.WriteLine(results[^1]);
            File.WriteAllLines(Path.Combine(directory, "results.txt"), results, new UTF8Encoding(false));
        }

        await Test("Private console receives CTRL+C, drains Unicode output and exits gracefully", async () =>
        {
            using var target = new OwnedTestChild("graceful");
            await target.Ready();
            await ExpectSignal(target, 0);
            await target.WaitForExit();
            Require(target.Process.ExitCode == 0, $"Graceful exit code={target.Process.ExitCode}, expected=0");
            Require(target.Lines.Contains("SIGNAL-SEEN") && target.Lines.Contains("CLEANUP-DONE"), "Cleanup marker missing");
            Require(target.Lines.Contains("STDOUT: Проверка 🦔") && target.Lines.Contains("STDERR: Завершено ё"), "Redirected Unicode output lost");
            File.WriteAllLines(Path.Combine(directory, "graceful-output.txt"), target.Lines, new UTF8Encoding(false));
        });
        await Test("Signal delivery does not claim an ignoring child has exited", async () =>
        {
            using var target = new OwnedTestChild("ignore");
            await target.Ready();
            await ExpectSignal(target, 0);
            await target.WaitForLine("SIGNAL-SEEN");
            await Task.Delay(250);
            Require(!target.Process.HasExited && !target.Lines.Contains("CLEANUP-DONE"), "Ignoring child was treated as graceful");
        });
        await Test("Early exit is rejected without signalling another private console", async () =>
        {
            using var sentinel = new OwnedTestChild("ignore");
            await sentinel.Ready();
            using var target = new OwnedTestChild("early-exit");
            await target.WaitForExit();
            Require(target.Process.ExitCode == 17, $"Early exit code={target.Process.ExitCode}, expected=17");
            await ExpectSignal(target, 10);
            Require(!sentinel.Process.HasExited && !sentinel.Lines.Contains("SIGNAL-SEEN"), "Sentinel was signalled");
        });
        await Test("A second private console is unaffected by the target shutdown", async () =>
        {
            using var sentinel = new OwnedTestChild("ignore");
            using var target = new OwnedTestChild("graceful");
            await sentinel.Ready();
            await target.Ready();
            await ExpectSignal(target, 0);
            await target.WaitForExit();
            await Task.Delay(250);
            Require(target.Process.ExitCode == 0 && target.Lines.Contains("CLEANUP-DONE"), "Target cleanup failed");
            Require(!sentinel.Process.HasExited && !sentinel.Lines.Contains("SIGNAL-SEEN"), "Unrelated private console affected");
        });
        await Test("Wrong creation time and executable identity are rejected before signalling", async () =>
        {
            using var target = new OwnedTestChild("ignore");
            await target.Ready();
            await ExpectSignal(target, 10, target.CreationTicks + 1);
            await ExpectSignal(target, 10, expectedPath: Path.Combine(Path.GetDirectoryName(Self)!, "not-the-child.exe"));
            Require(!target.Process.HasExited && !target.Lines.Contains("SIGNAL-SEEN"), "Identity rejection sent a signal");
        });
        await Test("Unexpected members in the private test console prevent broadcast", async () =>
        {
            using var target = new OwnedTestChild("shared");
            await target.Ready();
            await ExpectSignal(target, 12);
            Require(!target.Process.HasExited && !target.Lines.Any(line => line.Contains("SIGNAL-SEEN")), "Rejected console received a signal");
        });
        await Test("Launcher preserves quoted, empty and Unicode arguments", async () =>
        {
            string[] arguments = ["space value", "quote\"value", "trailing\\", "", "Кириллица 🦔"];
            using var target = new OwnedTestChild("arguments", arguments);
            await target.WaitForExit();
            Require(target.Process.ExitCode == 0, "Argument child failed");
            string expected = "ARGS=" + JsonSerializer.Serialize(arguments);
            Require(target.Lines.Contains(expected), "CreateProcess argument quoting changed data");
        });

        Console.WriteLine($"RESULT: {results.Count - failures} PASS, {failures} FAIL");
        Console.WriteLine("Artifacts: " + directory);
        return failures == 0 ? 0 : 1;
    }

    static void Require(bool condition, string reason)
    {
        if (!condition)
        {
            throw new InvalidOperationException(reason);
        }
    }

    static int Child(string mode, string[] arguments)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        if (mode == "arguments")
        { Console.WriteLine("ARGS=" + JsonSerializer.Serialize(arguments)); return 0; }
        if (mode == "early-exit")
        { Console.WriteLine("EARLY-EXIT"); return 17; }
        using var signalled = new ManualResetEventSlim();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("SIGNAL-SEEN");
            signalled.Set();
        };
        if (mode == "shared")
        {
            // This peer inherits ONLY the newly created private test console and job.
            // It never attaches to the runner or PowerShell console.
            var info = new ProcessStartInfo(Self)
            {
                UseShellExecute = false,
                CreateNoWindow = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            info.ArgumentList.Add("--child");
            info.ArgumentList.Add("ignore");
            using var ready = new ManualResetEventSlim();
            using var peer = new Process { StartInfo = info };
            peer.OutputDataReceived += (_, e) =>
            {
                if (e.Data == "READY")
                {
                    ready.Set();
                }

                if (e.Data != null)
                {
                    Console.WriteLine("PEER:" + e.Data);
                }
            };
            peer.ErrorDataReceived += (_, e) => { if (e.Data != null) { Console.Error.WriteLine("PEER:" + e.Data); } };
            if (!peer.Start())
            {
                return 91;
            }

            peer.BeginOutputReadLine();
            peer.BeginErrorReadLine();
            if (!ready.Wait(TimeSpan.FromSeconds(10)))
            {
                return 92;
            }

            Console.WriteLine("READY");
            Thread.Sleep(TimeSpan.FromSeconds(60));
            return 88;
        }
        Console.WriteLine("STDOUT: Проверка 🦔");
        Console.WriteLine("READY");
        if (mode == "ignore")
        { Thread.Sleep(TimeSpan.FromSeconds(60)); return 88; }
        if (mode != "graceful")
        {
            return 89;
        }

        if (!signalled.Wait(TimeSpan.FromSeconds(30)))
        {
            return 90;
        }

        Console.WriteLine("CLEANUP-DONE");
        Console.Error.WriteLine("STDERR: Завершено ё");
        return 0;
    }

    static async Task ExpectSignal(OwnedTestChild target, int expected, long? creationTicks = null, string? expectedPath = null)
    {
        int actual = await Signal(target, creationTicks, expectedPath);
        Require(actual == expected, $"Signal helper result={actual}, expected={expected}");
    }

    static async Task<int> Signal(OwnedTestChild target, long? creationTicks = null, string? expectedPath = null)
    {
        var info = new ProcessStartInfo(Self)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (string value in new[] { "--signal", target.Id.ToString(), (creationTicks ?? target.CreationTicks).ToString(), expectedPath ?? Self })
        {
            info.ArgumentList.Add(value);
        }

        using var helper = Process.Start(info) ?? throw new InvalidOperationException("Helper did not start");
        Task<string> stdout = helper.StandardOutput.ReadToEndAsync(), stderr = helper.StandardError.ReadToEndAsync();
        try
        { await helper.WaitForExitAsync().WaitAsync(Timeout); }
        catch
        {
            if (!helper.HasExited)
            {
                helper.Kill(true);
            }

            await helper.WaitForExitAsync().WaitAsync(Timeout);
            throw;
        }
        await Task.WhenAll(stdout, stderr).WaitAsync(Timeout);
        return helper.ExitCode;
    }

    sealed class OwnedTestChild : IDisposable
    {
        readonly IntPtr job;
        readonly EngineConsole.OwnedChild child;
        public ConcurrentQueue<string> Lines { get; } = new();
        public Process Process => child.Process;
        public int Id { get; }
        public long CreationTicks { get; }
        public OwnedTestChild(string mode, params string[] arguments)
        {
            job = Native.CreateKillJob();
            EngineConsole.OwnedChild? pending = null;
            try
            {
                child = pending = EngineConsole.Start(Self, new[] { "--child", mode }.Concat(arguments).ToArray(), Path.GetDirectoryName(Self)!, job, Lines.Enqueue);
                Id = Process.Id;
                CreationTicks = Process.StartTime.ToUniversalTime().Ticks;
                Process.EnableRaisingEvents = true;
                child.Resume();
            }
            catch { Native.CloseHandle(job); pending?.Dispose(); throw; }
        }
        public Task Ready() => WaitForLine("READY");
        public async Task WaitForLine(string line)
        {
            var clock = Stopwatch.StartNew();
            while (!Lines.Contains(line))
            {
                if (Process.HasExited)
                {
                    throw new InvalidOperationException("Child exited before " + line);
                }

                if (clock.Elapsed > Timeout)
                {
                    throw new TimeoutException("Missing child marker: " + line);
                }

                await Task.Delay(20);
            }
        }
        public async Task WaitForExit()
        {
            await Process.WaitForExitAsync().WaitAsync(Timeout);
            await child.DrainAsync().WaitAsync(Timeout);
        }
        public void Dispose()
        {
            // This handle owns only test-created children; never enumerate or kill by name.
            Native.CloseHandle(job);
            try
            {
                if (!Process.WaitForExit(5000))
                {
                    throw new TimeoutException("Owned child survived job cleanup");
                }

                child.DrainAsync().WaitAsync(Timeout).GetAwaiter().GetResult();
            }
            finally { child.Dispose(); }
        }
    }

    static class Native
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateJobObject(IntPtr attributes, string? name);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetInformationJobObject(IntPtr job, int informationClass, ref ExtendedLimits limits, uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);
        [StructLayout(LayoutKind.Sequential)]
        struct BasicLimits
        {
            public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass, SchedulingClass;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct IoCounters { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
        [StructLayout(LayoutKind.Sequential)]
        struct ExtendedLimits
        {
            public BasicLimits Basic;
            public IoCounters Io;
            public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
        }
        public static IntPtr CreateKillJob()
        {
            IntPtr handle = CreateJobObject(IntPtr.Zero, null);
            if (handle == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var limits = new ExtendedLimits { Basic = new BasicLimits { LimitFlags = 0x2000 } };
            if (!SetInformationJobObject(handle, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()))
            {
                int error = Marshal.GetLastWin32Error();
                CloseHandle(handle);
                throw new Win32Exception(error);
            }
            return handle;
        }
    }
}
