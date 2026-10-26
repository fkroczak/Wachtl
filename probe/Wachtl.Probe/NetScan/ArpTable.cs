using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace Wachtl.Probe.NetScan;

/// <summary>
/// ARP-Tabelle des Betriebssystems lesen (IPv4 → MAC). Windows: <c>GetIpNetTable2</c>, ersatzweise <c>arp -a</c>;
/// Linux: <c>/proc/net/arp</c>. Unvollständige Einträge, Null-, Broadcast- und Multicast-MACs werden übergangen.
/// </summary>
public static class ArpTable
{
    private static readonly Regex ArpLine = new(
        @"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\b",
        RegexOptions.Multiline | RegexOptions.CultureInvariant);

    /// <summary>MAC als „AA:BB:CC:DD:EE:FF“; null bei ungültiger Länge, 00…00, Broadcast oder Multicast.</summary>
    public static string? FormatMac(ReadOnlySpan<byte> mac)
    {
        if (mac.Length != 6)
        {
            return null;
        }

        var allZero = true;
        foreach (var b in mac)
        {
            allZero &= b == 0;
        }

        // Bit 0 des ersten Bytes = Gruppenadresse (Multicast, auch FF:FF:FF:FF:FF:FF)
        if (allZero || (mac[0] & 0x01) != 0)
        {
            return null;
        }

        return string.Join(":", mac.ToArray().Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
    }

    /// <summary>„aa-bb-cc-dd-ee-ff“ oder „aa:bb:…“ in das Ausgabeformat bringen (null, wenn unbrauchbar).</summary>
    public static string? NormalizeMac(string? raw)
    {
        var parts = (raw ?? string.Empty).Trim().Split('-', ':');
        if (parts.Length != 6)
        {
            return null;
        }

        var bytes = new byte[6];
        for (var i = 0; i < 6; i++)
        {
            if (parts[i].Length is < 1 or > 2 ||
                !byte.TryParse(parts[i], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out bytes[i]))
            {
                return null;
            }
        }

        return FormatMac(bytes);
    }

    /// <summary>Ausgabe von <c>arp -a</c> (Windows, deutsch oder englisch): IP → MAC.</summary>
    public static Dictionary<string, string> ParseArpOutput(string text)
    {
        var table = new Dictionary<string, string>();
        foreach (Match m in ArpLine.Matches(text))
        {
            if (IPAddress.TryParse(m.Groups[1].Value, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork &&
                NormalizeMac(m.Groups[2].Value) is { } mac)
            {
                table[ip.ToString()] = mac;
            }
        }

        return table;
    }

    /// <summary>Inhalt von <c>/proc/net/arp</c> (Linux): nur vollständige Einträge (Flag 0x2).</summary>
    public static Dictionary<string, string> ParseProcNetArp(string text)
    {
        var table = new Dictionary<string, string>();
        foreach (var line in text.Split('\n').Skip(1))
        {
            var cols = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (cols.Length < 4 || !IPAddress.TryParse(cols[0], out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            {
                continue;
            }

            int flags;
            try
            {
                flags = Convert.ToInt32(cols[2], 16);
            }
            catch (FormatException)
            {
                continue;
            }
            catch (OverflowException)
            {
                continue;
            }

            if ((flags & 0x2) != 0 && NormalizeMac(cols[3]) is { } mac)
            {
                table[ip.ToString()] = mac;
            }
        }

        return table;
    }

    /// <summary>Aktuelle ARP-Tabelle: IPv4 (als Zahl) → MAC. Fehler ergeben eine leere Tabelle.</summary>
    public static async Task<Dictionary<uint, string>> ReadAsync(ILogger logger, CancellationToken ct)
    {
        Dictionary<string, string> raw;
        if (OperatingSystem.IsWindows())
        {
            try
            {
                raw = ReadNative();
            }
            catch (Exception ex) when (ex is Win32Exception or DllNotFoundException or EntryPointNotFoundException or InvalidOperationException)
            {
                logger.LogDebug("GetIpNetTable2 nicht nutzbar ({Message}), lese „arp -a“", ex.Message);
                raw = ParseArpOutput(await RunArpAsync(logger, ct).ConfigureAwait(false));
            }
        }
        else if (File.Exists("/proc/net/arp"))
        {
            try
            {
                raw = ParseProcNetArp(await File.ReadAllTextAsync("/proc/net/arp", ct).ConfigureAwait(false));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                logger.LogDebug("/proc/net/arp nicht lesbar: {Message}", ex.Message);
                raw = new Dictionary<string, string>();
            }
        }
        else
        {
            raw = new Dictionary<string, string>();
        }

        var result = new Dictionary<uint, string>();
        foreach (var (ip, mac) in raw)
        {
            result[SubnetPlanner.ToUInt(IPAddress.Parse(ip))] = mac;
        }

        return result;
    }

    // -- Windows: GetIpNetTable2 --------------------------------------------
    // MIB_IPNET_TABLE2 { ULONG NumEntries; MIB_IPNET_ROW2 Table[]; } – Table wegen NET_LUID 8-Byte-ausgerichtet ab Offset 8.
    // MIB_IPNET_ROW2 (88 Byte): SOCKADDR_INET Address @0 (28 Byte; si_family @0, sin_addr @4), InterfaceIndex @28,
    // InterfaceLuid @32, PhysicalAddress[32] @40, PhysicalAddressLength @72, State @76, Flags @80, ReachabilityTime @84.
    private const ushort AfInet = 2;
    private const int TableOffset = 8;
    private const int RowSize = 88;
    private const int OffsetFamily = 0;
    private const int OffsetIpv4 = 4;
    private const int OffsetPhysical = 40;
    private const int OffsetPhysicalLength = 72;
    private const int OffsetState = 76;
    private const int NlnsIncomplete = 1;   // 0 = Unreachable, 1 = Incomplete, danach Probe/Delay/Stale/Reachable/Permanent

    [DllImport("iphlpapi.dll")]
    private static extern uint GetIpNetTable2(ushort family, out IntPtr table);

    [DllImport("iphlpapi.dll")]
    private static extern void FreeMibTable(IntPtr memory);

    [SupportedOSPlatform("windows")]
    private static Dictionary<string, string> ReadNative()
    {
        var rc = GetIpNetTable2(AfInet, out var table);
        if (rc != 0)
        {
            throw new Win32Exception((int)rc);
        }

        if (table == IntPtr.Zero)
        {
            throw new InvalidOperationException("leere Tabelle");
        }

        try
        {
            var count = Marshal.ReadInt32(table);
            if (count is < 0 or > 1_000_000)
            {
                throw new InvalidOperationException($"unplausible Anzahl {count}");
            }

            var result = new Dictionary<string, string>();
            var address = new byte[4];
            var mac = new byte[6];
            for (var i = 0; i < count; i++)
            {
                var row = table + TableOffset + i * RowSize;
                if ((ushort)Marshal.ReadInt16(row, OffsetFamily) != AfInet ||
                    Marshal.ReadInt32(row, OffsetPhysicalLength) != 6 ||
                    Marshal.ReadInt32(row, OffsetState) <= NlnsIncomplete)
                {
                    continue;
                }

                Marshal.Copy(row + OffsetIpv4, address, 0, 4);
                Marshal.Copy(row + OffsetPhysical, mac, 0, 6);
                if (FormatMac(mac) is { } formatted)
                {
                    result[new IPAddress(address).ToString()] = formatted;
                }
            }

            return result;
        }
        finally
        {
            FreeMibTable(table);
        }
    }

    private static async Task<string> RunArpAsync(ILogger logger, CancellationToken ct)
    {
        var exe = Path.Combine(Environment.SystemDirectory, "arp.exe");
        try
        {
            var psi = new ProcessStartInfo(exe)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("-a");
            using var process = Process.Start(psi);
            if (process is null)
            {
                return string.Empty;
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
                await stderr.ConfigureAwait(false);
                return await stdout.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                }

                logger.LogDebug("„arp -a“ antwortet nicht");
                return string.Empty;
            }
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException)
        {
            logger.LogDebug("„arp -a“ nicht ausführbar: {Message}", ex.Message);
            return string.Empty;
        }
    }
}
