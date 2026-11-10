using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

// A fresh process loads the actual production managed declaration and native
// library. The ONLY invoked native export is GuardMatchesV5 with nonzero LUID.
// Since this process never configured a session, it returns after build(),
// before open()/BFE enumeration. App-id conversion is a read-only lookup.
// Never call Configure, Deactivate, Remove, Status, or use a zero LUID here.
if (args.Length > 2)
{
    throw new ArgumentException("Expected [native DLL path] [new artifacts output directory].");
}

string nativePath = Path.GetFullPath(args.Length > 0 ? args[0] : "dist/ProxyGuard.dll");
if (!File.Exists(nativePath))
{
    throw new FileNotFoundException("Build the production native DLL before running the ABI smoke.");
}

string artifacts = Path.GetFullPath("artifacts");
string output = Path.GetFullPath(args.Length > 1 ? args[1] :
    Path.Combine(artifacts, "guard-abi-" + Guid.NewGuid().ToString("N")));
if (!output.StartsWith(artifacts + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
    Directory.Exists(output) || File.Exists(output))
{
    throw new ArgumentException("Output must be a new directory under artifacts.");
}
Directory.CreateDirectory(output);

Assembly production = Assembly.Load("ProxyBridge");
Type guard = production.GetType("ProxyBridge.Guard", throwOnError: true)!;
Type settingsType = production.GetType("ProxyBridge.Settings", throwOnError: true)!;
Type entryType = guard.GetNestedType("NativeAddressExclusion", BindingFlags.Public | BindingFlags.NonPublic)!;
Type methods = guard.GetNestedType("NativeMethods", BindingFlags.NonPublic)!;
MethodInfo matches = methods.GetMethod("GuardMatchesV5", BindingFlags.Static | BindingFlags.NonPublic)!;
MethodInfo convert = guard.GetMethod("ToNativeAddressExclusions", BindingFlags.Static | BindingFlags.NonPublic)!;
string engine = Environment.ProcessPath ?? throw new InvalidOperationException("Missing test process executable.");
if (!Path.IsPathFullyQualified(engine) || !File.Exists(engine))
{
    throw new InvalidOperationException("Native app identity requires this existing test executable.");
}

IntPtr library = NativeLibrary.Load(nativePath);
NativeLibrary.SetDllImportResolver(production, (name, _, _) =>
    name.Equals("ProxyGuard.dll", StringComparison.OrdinalIgnoreCase) ? library : IntPtr.Zero);
var report = new List<string>();
int failures = 0;

void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

void Test(string name, Action action)
{
    try
    {
        action();
        report.Add("PASS: " + name);
    }
    catch (Exception error)
    {
        failures++;
        report.Add("FAIL: " + name + " (" + error.GetType().Name + ")");
    }
    Console.WriteLine(report[^1]);
    File.WriteAllLines(Path.Combine(output, "results.txt"), report, new UTF8Encoding(false));
}

Array Map(params string[] values)
{
    object settings = Activator.CreateInstance(settingsType,
        ["192.0.2.10", 1080, "", "", "http"])!;
    settingsType.GetProperty("ExcludedAddresses")!.SetValue(settings, values);
    return (Array)convert.Invoke(null, [settings])!;
}

object Entry(Array values, int index) => values.GetValue(index)!;
T Field<T>(object value, string name) => (T)entryType.GetField(name)!.GetValue(value)!;

Array MutateSecond(Array source, string field, object value)
{
    Array copy = (Array)source.Clone();
    object entry = Entry(copy, 1);
    entryType.GetField(field)!.SetValue(entry, value);
    copy.SetValue(entry, 1);
    return copy;
}

uint Call(Array addresses, uint? count = null)
{
    // Keep nonzero LUID fixed inside this helper: valid inputs return on the
    // process-local activeSession check and cannot enter the BFE read path.
    object?[] arguments = [0xc000020au, (ushort)1080, 1ul, engine,
        Array.Empty<string>(), 0u, addresses, count ?? checked((uint)addresses.Length), false, true];
    uint result = (uint)matches.Invoke(null, arguments)!;
    Require(arguments[9] is false, "Native matches output must be false.");
    return result;
}

try
{
    Test("actual managed V5 layout is 28 bytes with offsets 0/4/8/12", () =>
    {
        Require(Marshal.SizeOf(entryType) == 28, "Wrong native array stride.");
        foreach (var (name, offset) in new[] { ("Family", 0), ("PrefixLength", 4), ("Port", 8), ("Address", 12) })
        {
            Require(Marshal.OffsetOf(entryType, name).ToInt32() == offset, "Wrong field offset.");
        }
        var array = entryType.GetField("Address")!.GetCustomAttribute<MarshalAsAttribute>();
        Require(array?.Value == UnmanagedType.ByValArray && array.SizeConst == 16, "Wrong inline address layout.");
        Require(matches.GetCustomAttribute<DllImportAttribute>()?.CallingConvention == CallingConvention.Cdecl,
            "Unexpected calling convention.");
    });

    Test("fresh DLL contains V5 and legacy V4/V3 entry points", () =>
    {
        foreach (string name in new[] { "GuardConfigureV5", "GuardMatchesV5", "GuardConfigureV4",
            "GuardMatchesV4", "GuardConfigureV3", "GuardMatchesV3" })
        {
            Require(NativeLibrary.TryGetExport(library, name, out IntPtr address) && address != IntPtr.Zero,
                "Missing ABI export.");
        }
    });

    Array mixed = Map("192.168.1.42/24:8080", "[2001:db8:abcd::1234/48]:443");
    Array reverse = Map("[2001:db8:abcd::1234/48]:443", "192.168.1.42/24:8080");
    Test("production mapper masks mixed-family addresses and preserves their ports", () =>
    {
        Require(mixed.Length == 2, "Mapping lost entries.");
        object v4 = Entry(mixed, 0), v6 = Entry(mixed, 1);
        Require(Field<uint>(v4, "Family") == 4 && Field<uint>(v4, "PrefixLength") == 24 &&
            Field<uint>(v4, "Port") == 8080, "Wrong IPv4 fields.");
        Require(Field<byte[]>(v4, "Address").SequenceEqual(new byte[] { 192, 168, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }),
            "Wrong IPv4 network bytes or tail.");
        Require(Field<uint>(v6, "Family") == 6 && Field<uint>(v6, "PrefixLength") == 48 &&
            Field<uint>(v6, "Port") == 443, "Wrong IPv6 fields.");
        Require(Field<byte[]>(v6, "Address").SequenceEqual(new byte[] { 0x20, 1, 0x0d, 0xb8, 0xab, 0xcd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }),
            "Wrong IPv6 network bytes.");
    });
    Test("real V5 accepts mixed-family arrays in both orders and returns false", () =>
        Require(Call(mixed) == 0 && Call(reverse) == 0, "Valid mixed array rejected."));
    Test("real V5 accepts empty address array", () =>
        Require(Call(Map()) == 0, "Empty array rejected."));
    Test("real V5 accepts all-port entries and prefix boundaries", () =>
        Require(Call(Map("0.0.0.0/0", "::/0", "192.168.1.10", "2001:db8::10")) == 0,
            "Valid port/prefix boundary rejected."));

    var invalidFields = new (string Name, Array Values)[]
    {
        ("second entry family", MutateSecond(mixed, "Family", 9u)),
        ("second IPv6 prefix", MutateSecond(mixed, "PrefixLength", 129u)),
        ("second IPv4 prefix", MutateSecond(reverse, "PrefixLength", 33u)),
        ("second DNS port", MutateSecond(mixed, "Port", 53u)),
        ("second overflowing port", MutateSecond(mixed, "Port", 65536u))
    };
    foreach (var (name, values) in invalidFields)
    {
        Test("real V5 rejects " + name, () => Require(Call(values) == 87, "Malformed entry not rejected."));
    }

    byte[] v6Host = (byte[])Field<byte[]>(Entry(mixed, 1), "Address").Clone();
    v6Host[15] = 1;
    byte[] v4Host = (byte[])Field<byte[]>(Entry(reverse, 1), "Address").Clone();
    v4Host[3] = 1;
    byte[] v4Tail = (byte[])Field<byte[]>(Entry(reverse, 1), "Address").Clone();
    v4Tail[15] = 1;
    Test("real V5 rejects second-entry IPv6 host bits", () =>
        Require(Call(MutateSecond(mixed, "Address", v6Host)) == 87, "IPv6 host bits accepted."));
    Test("real V5 rejects second-entry IPv4 host bits", () =>
        Require(Call(MutateSecond(reverse, "Address", v4Host)) == 87, "IPv4 host bits accepted."));
    Test("real V5 rejects second-entry IPv4 tail bytes", () =>
        Require(Call(MutateSecond(reverse, "Address", v4Tail)) == 87, "IPv4 tail bytes accepted."));
    Test("real V5 rejects a mapped IPv6 address in the second entry", () =>
    {
        byte[] mapped = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1];
        Array fullPrefix = MutateSecond(mixed, "PrefixLength", 128u);
        Require(Call(MutateSecond(fullPrefix, "Address", mapped)) == 87, "Mapped IPv6 address accepted.");
    });
    Test("real V5 uses the transmitted count at the second-entry boundary", () =>
    {
        Array invalidSecond = MutateSecond(mixed, "Family", 9u);
        Require(Call(invalidSecond, 1) == 0 && Call(invalidSecond, 2) == 87, "Array count/stride mismatch.");
    });
    Test("real V5 enforces maximum count on a fully allocated 65-entry array", () =>
    {
        Array oversized = Array.CreateInstance(entryType, 65);
        for (int i = 0; i < oversized.Length; i++)
        {
            oversized.SetValue(Entry(mixed, 0), i);
        }
        Require(Call(oversized) == 87, "Oversized count accepted.");
    });
}
finally
{
    // No process-owned WFP session was created; freeing this DLL needs no cleanup call.
    NativeLibrary.Free(library);
}

string hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(nativePath)));
File.WriteAllText(Path.Combine(output, "native-sha256.txt"), hash + Environment.NewLine, new UTF8Encoding(false));
string summary = $"SUMMARY: {report.Count - failures} PASS, {failures} FAIL; GuardMatchesV5 only, no WFP policy/session mutation.";
Console.WriteLine(summary);
File.WriteAllText(Path.Combine(output, "summary.txt"), summary + Environment.NewLine, new UTF8Encoding(false));
return failures == 0 ? 0 : 1;
