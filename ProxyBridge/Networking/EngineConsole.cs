using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProxyBridge;

// Each engine has a private hidden console. Only the short-lived signal helper
// attaches to it; the GUI never changes its own console or control handlers.
internal static class EngineConsole
{
    const uint CreateNewConsole = 0x10, CreateSuspended = 0x4, ExtendedStartupInfoPresent = 0x80000;
    const uint StartfUseShowWindow = 0x1, StartfUseStdHandles = 0x100;
    const uint HandleFlagInherit = 0x1;
    static readonly IntPtr HandleListAttribute = new(0x20002);

    public sealed class OwnedChild : IDisposable
    {
        readonly SafeFileHandle thread;
        readonly StreamReader reader;
        readonly Task drain;
        bool resumed, disposed;
        public Process Process
        {
            get;
        }

        internal OwnedChild(Process process, SafeFileHandle primaryThread, SafeFileHandle outputRead, Action<string> output)
        {
            Process = process;
            thread = primaryThread;
            reader = new StreamReader(new FileStream(outputRead, FileAccess.Read, 4096, false), Encoding.UTF8, true);
            drain = Task.Run(async () =>
            {
                while (await reader.ReadLineAsync().ConfigureAwait(false) is string line)
                {
                    output(line);
                }
            });
        }

        public void Resume()
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (resumed)
            {
                throw new InvalidOperationException("Engine thread was already resumed.");
            }

            if (ResumeThread(thread) == uint.MaxValue)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            resumed = true;
            thread.Dispose();
        }

        public Task DrainAsync() => drain;

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            // Caller must stop and await the process before disposing its pipes.
            thread.Dispose();
            if (drain.IsCompleted)
            {
                _ = drain.Exception;
                reader.Dispose();
            }
            else
            {
                _ = drain.ContinueWith(task => { _ = task.Exception; reader.Dispose(); }, TaskScheduler.Default);
            }

            Process.Dispose();
        }
    }

    public static OwnedChild Start(string executable, IReadOnlyList<string> arguments, string workingDirectory,
        IntPtr job, Action<string> output)
    {
        ArgumentNullException.ThrowIfNull(output);
        if (job == IntPtr.Zero)
        {
            throw new ArgumentException("An owning job is required.", nameof(job));
        }

        executable = Path.GetFullPath(executable);
        var security = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), InheritHandle = true };
        if (!CreatePipe(out var read, out var write, ref security, 0))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        using (write)
        {
            SafeFileHandle? thread = null;
            Process? process = null;
            IntPtr attributes = IntPtr.Zero, inheritedHandles = IntPtr.Zero;
            bool attributesInitialized = false;
            var information = new ProcessInformation();
            try
            {
                if (!SetHandleInformation(read, HandleFlagInherit, 0))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                using var input = CreateFileW("NUL", 0x80000000, 3, ref security, 3, 0, IntPtr.Zero);
                if (input.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                nuint size = 0;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                if (size == 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                attributes = Marshal.AllocHGlobal(checked((nint)size));
                if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref size))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                attributesInitialized = true;
                inheritedHandles = Marshal.AllocHGlobal(2 * IntPtr.Size);
                Marshal.Copy(new[] { input.DangerousGetHandle(), write.DangerousGetHandle() }, 0, inheritedHandles, 2);
                if (!UpdateProcThreadAttribute(attributes, 0, HandleListAttribute, inheritedHandles,
                    (nuint)(2 * IntPtr.Size), IntPtr.Zero, IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                var startup = new StartupInfoEx
                {
                    StartupInfo = new StartupInfo
                    {
                        Size = Marshal.SizeOf<StartupInfoEx>(),
                        Flags = StartfUseShowWindow | StartfUseStdHandles,
                        ShowWindow = 0,
                        StandardInput = input.DangerousGetHandle(),
                        StandardOutput = write.DangerousGetHandle(),
                        StandardError = write.DangerousGetHandle()
                    },
                    AttributeList = attributes
                };
                var command = new StringBuilder(string.Join(" ", new[] { executable }.Concat(arguments).Select(QuoteArgument)));
                bool created = CreateProcessW(executable, command, IntPtr.Zero, IntPtr.Zero, true,
                    CreateNewConsole | CreateSuspended | ExtendedStartupInfoPresent, IntPtr.Zero,
                    workingDirectory, ref startup, out information);
                int createError = Marshal.GetLastWin32Error();
                GC.KeepAlive(input);
                GC.KeepAlive(write);
                if (!created)
                {
                    throw new Win32Exception(createError);
                }

                if (!AssignProcessToJobObject(job, information.Process))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                process = Process.GetProcessById(checked((int)information.ProcessId));
                _ = process.Handle; // Retain identity before releasing CreateProcess's process handle.
                thread = new SafeFileHandle(information.Thread, true);
                information.Thread = IntPtr.Zero;
                var child = new OwnedChild(process, thread, read, output);
                process = null;
                thread = null;
                return child;
            }
            catch
            {
                if (information.Process != IntPtr.Zero)
                {
                    TerminateProcess(information.Process, 1);
                    WaitForSingleObject(information.Process, 10000);
                }
                process?.Dispose();
                thread?.Dispose();
                read.Dispose();
                throw;
            }
            finally
            {
                if (information.Thread != IntPtr.Zero)
                {
                    CloseHandle(information.Thread);
                }

                if (information.Process != IntPtr.Zero)
                {
                    CloseHandle(information.Process);
                }

                if (attributesInitialized)
                {
                    DeleteProcThreadAttributeList(attributes);
                }

                if (attributes != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(attributes);
                }

                if (inheritedHandles != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(inheritedHandles);
                }
            }
        }
    }

    // Invoke only in a dedicated helper process. Path trust is checked by its CLI
    // dispatcher; this primitive checks that the selected process is that image.
    public static int Signal(int processId, long creationUtcTicks, string expectedExecutablePath)
    {
        bool attached = false;
        try
        {
            if (processId <= 0 || processId == Environment.ProcessId || creationUtcTicks <= 0)
            {
                return 10;
            }

            using var target = Process.GetProcessById(processId);
            var handle = target.SafeHandle; // Keep the original process identity alive through signalling.
            if (target.HasExited || !GetProcessTimes(handle, out long created, out _, out _, out _)
                || DateTime.FromFileTimeUtc(created).Ticks != creationUtcTicks)
            {
                return 10;
            }

            var image = new StringBuilder(32768);
            uint length = (uint)image.Capacity;
            if (!QueryFullProcessImageNameW(handle, 0, image, ref length)
                || !string.Equals(Path.GetFullPath(image.ToString()), Path.GetFullPath(expectedExecutablePath), StringComparison.OrdinalIgnoreCase))
            {
                return 10;
            }
            // Even a CreateNoWindow CUI helper may own a headless console.
            // Detach only this dedicated helper before attaching to the target;
            // this neither detaches the parent nor signals its console.
            FreeConsole();
            if (!AttachConsole((uint)processId))
            {
                return 11;
            }

            attached = true;
            // AttachConsole resets the handler table, so ignore our own Ctrl+C afterwards.
            if (!SetConsoleCtrlHandler(IntPtr.Zero, true))
            {
                return 13;
            }

            var members = new uint[3];
            uint count = GetConsoleProcessList(members, (uint)members.Length);
            if (count != 2 || !members.Take(2).Contains((uint)processId)
                || !members.Take(2).Contains((uint)Environment.ProcessId) || target.HasExited)
            {
                return 12;
            }

            return GenerateConsoleCtrlEvent(0, 0) ? 0 : 14;
        }
        catch (ArgumentException) { return 10; }
        catch (InvalidOperationException) { return 10; }
        catch (Exception) { return 15; }
        finally
        {
            if (attached)
            {
                FreeConsole();
            }
        }
    }

    static string QuoteArgument(string value)
    {
        var result = new StringBuilder("\"");
        int slashes = 0;
        foreach (char character in value)
        {
            if (character == '\\')
            {
                slashes++;
                continue;
            }
            result.Append('\\', character == '"' ? slashes * 2 + 1 : slashes);
            result.Append(character);
            slashes = 0;
        }
        return result.Append('\\', slashes * 2).Append('"').ToString();
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct StartupInfo
    {
        public int Size;
        public string? Reserved, Desktop, Title;
        public uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        public ushort ShowWindow, ReservedLength;
        public IntPtr ReservedBytes, StandardInput, StandardOutput, StandardError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct StartupInfoEx
    {
        public StartupInfo StartupInfo; public IntPtr AttributeList;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInformation
    {
        public IntPtr Process, Thread; public uint ProcessId, ThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref SecurityAttributes attributes, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafeFileHandle CreateFileW(string name, uint access, uint share, ref SecurityAttributes attributes, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref nuint size);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, nuint size, IntPtr previous, IntPtr returnedSize);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInformation process);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(SafeFileHandle thread);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, StringBuilder image, ref uint length);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AttachConsole(uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint GetConsoleProcessList([Out] uint[] processes, uint count);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GenerateConsoleCtrlEvent(uint signal, uint group);
}
