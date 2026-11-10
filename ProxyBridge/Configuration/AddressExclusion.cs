using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace ProxyBridge;

/// <summary>A destination network and optional TCP/UDP port, normalized before use by either policy engine.</summary>
internal sealed record AddressExclusion
{
    public IPAddress Address { get; }
    public int PrefixLength { get; }
    public int? Port { get; }
    public bool IsIPv6 => Address.AddressFamily == AddressFamily.InterNetworkV6;
    public string Cidr => $"{Address}/{PrefixLength}";
    public string Value
    {
        get
        {
            string address = PrefixLength == (IsIPv6 ? 128 : 32) ? Address.ToString() : Cidr;
            return Port is int port ? (IsIPv6 ? $"[{address}]:{port}" : $"{address}:{port}") : address;
        }
    }

    AddressExclusion(IPAddress address, int prefixLength, int? port)
    {
        Address = address;
        PrefixLength = prefixLength;
        Port = port;
    }

    public static AddressExclusion Parse(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw InvalidAddress();
        }

        string network = value.Trim();
        int? port = null;
        bool bracketed = network.StartsWith('[');
        if (bracketed)
        {
            int close = network.IndexOf(']');
            if (close < 0 || close + 1 >= network.Length || network[close + 1] != ':')
            {
                throw InvalidAddress();
            }

            port = ParsePort(network[(close + 2)..]);
            network = network[1..close];
        }
        else if (network.Count(c => c == ':') == 1)
        {
            int colon = network.IndexOf(':');
            port = ParsePort(network[(colon + 1)..]);
            network = network[..colon];
        }

        string[] parts = network.Split('/');
        if (parts.Length > 2 || parts[0].Contains('%') || parts[0].Contains('[') || parts[0].Contains(']'))
        {
            throw InvalidAddress();
        }

        string literal = parts[0];
        bool ipv6 = literal.Contains(':');
        if (bracketed && !ipv6)
        {
            throw InvalidAddress();
        }

        if (!ipv6)
        {
            string[] octets = literal.Split('.');
            if (octets.Length != 4 || octets.Any(o => o.Length is < 1 or > 3 ||
                (o.Length > 1 && o[0] == '0') || !o.All(char.IsAsciiDigit) ||
                !byte.TryParse(o, NumberStyles.None, CultureInfo.InvariantCulture, out _)))
            {
                throw InvalidAddress();
            }
        }

        if (!IPAddress.TryParse(literal, out var address) || address.IsIPv4MappedToIPv6 ||
            address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            throw InvalidAddress();
        }

        int width = ipv6 ? 128 : 32;
        int prefix = width;
        if (parts.Length == 2 && (!TryNumber(parts[1], out prefix) || prefix > width))
        {
            throw new ArgumentException($"Префикс подсети должен быть от 0 до {width}.");
        }

        byte[] bytes = address.GetAddressBytes();
        for (int bit = prefix; bit < width; bit++)
        {
            bytes[bit / 8] &= (byte)~(1 << (7 - bit % 8));
        }

        return new(new IPAddress(bytes), prefix, port);
    }

    public static bool TryParse(string value, out AddressExclusion? result)
    {
        try
        {
            result = Parse(value);
            return true;
        }
        catch (ArgumentException)
        {
            result = null;
            return false;
        }
    }

    static int ParsePort(string value)
    {
        if (!TryNumber(value, out int port) || port is < 1 or > 65535)
        {
            throw new ArgumentException("Порт должен быть числом от 1 до 65535.");
        }
        if (port == 53)
        {
            throw new ArgumentException("Порт 53 используется DNS через прокси и не может быть исключением.");
        }
        return port;
    }

    static bool TryNumber(string value, out int number) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out number) && value.All(char.IsAsciiDigit);

    static ArgumentException InvalidAddress() => new(
        "Укажите IP-адрес или подсеть, например 192.168.1.0/24 или 192.168.1.10:8080. Для IPv6 с портом используйте [адрес]:порт.");
}
