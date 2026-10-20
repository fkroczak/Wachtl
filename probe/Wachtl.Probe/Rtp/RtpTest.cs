using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Wachtl.Probe.Rtp;

public sealed record RtpOptions(string Host, int Port, string Codec, int PtimeMs, int DurationS, int Dscp);

/// <summary>
/// Ein Sprachtest: RTP-Strom im Takt des Codecs senden, Antworten des Reflektors mit genauer Empfangszeit
/// aufzeichnen, am Ende den Zähler des Reflektors abfragen und auswerten (wie server/wachtl/rtp/stream.py).
/// </summary>
public static class RtpTest
{
    private const int QueryTries = 3;

    [DllImport("winmm.dll")]
    private static extern uint timeBeginPeriod(uint period);

    [DllImport("winmm.dll")]
    private static extern uint timeEndPeriod(uint period);

    public static async Task<RtpMeasurement> RunAsync(RtpOptions o, CancellationToken ct)
    {
        var codec = RtpCodec.Get(o.Codec);
        var m = new RtpMeasurement { Peer = $"{o.Host}:{o.Port}", Codec = codec.Key, PtimeMs = o.PtimeMs, DurationS = o.DurationS };
        IPAddress address;
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(o.Host, ct).ConfigureAwait(false);
            address = addresses.OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).First();
        }
        catch (Exception ex) when (ex is SocketException or InvalidOperationException or ArgumentException)
        {
            m.Error = $"Gegenstelle {o.Host} nicht auflösbar: {ex.Message}";
            return m;
        }

        // eigener Thread: genaue Zeitstempel, unabhängig vom Thread-Pool
        return await Task.Factory.StartNew(() => Exchange(new IPEndPoint(address, o.Port), o, codec, m, ct), ct,
            TaskCreationOptions.LongRunning, TaskScheduler.Default).ConfigureAwait(false);
    }

    private static RtpMeasurement Exchange(IPEndPoint peer, RtpOptions o, RtpCodec codec, RtpMeasurement m, CancellationToken ct)
    {
        var clock = Stopwatch.StartNew();
        long NowUs() => clock.Elapsed.Ticks / 10;
        var ssrc = (uint)Random.Shared.NextInt64(0, uint.MaxValue);
        var firstSeq = Random.Shared.Next(0, 65536);
        var total = Math.Max(1, o.DurationS * 1000 / o.PtimeMs);
        var records = new Dictionary<int, RtpRecord>();
        uint? finalCount = null;
        var refused = 0;
        var done = false;
        var sync = new object();
        var timerRaised = OperatingSystem.IsWindows() && TryTimerPeriod(true);

        using var socket = new Socket(peer.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            if (o.Dscp > 0)
            {
                try
                {
                    // Windows übernimmt die Markierung nur mit QoS-Richtlinie (GPO); ohne sie bleibt das Paket unmarkiert
                    socket.SetSocketOption(peer.AddressFamily == AddressFamily.InterNetworkV6 ? SocketOptionLevel.IPv6 : SocketOptionLevel.IP,
                        SocketOptionName.TypeOfService, o.Dscp << 2);
                }
                catch (SocketException)
                {
                }
            }

            socket.Connect(peer);
            socket.ReceiveTimeout = 200;
            var receiver = new Thread(() =>
            {
                var buffer = new byte[2048];
                while (!Volatile.Read(ref done))
                {
                    int n;
                    try
                    {
                        n = socket.Receive(buffer);
                    }
                    catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                    {
                        continue;
                    }
                    catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused)
                    {
                        Interlocked.Increment(ref refused);   // ICMP „Port unreachable“
                        continue;
                    }
                    catch (Exception) when (Volatile.Read(ref done))
                    {
                        return;
                    }
                    catch (SocketException)
                    {
                        continue;
                    }

                    var t4 = NowUs();
                    if (RtpProtocol.Parse(buffer.AsSpan(0, n)) is not { } reply || reply.Ssrc != ssrc)
                    {
                        continue;
                    }

                    lock (sync)
                    {
                        if (reply.Query)
                        {
                            finalCount = Math.Max(finalCount ?? 0, reply.Count);
                            continue;
                        }

                        var index = (reply.Seq - firstSeq) & 0xFFFF;
                        if (index < total && !records.ContainsKey(index))
                        {
                            records[index] = new RtpRecord(reply.T1Us, reply.T2Us, reply.Count, t4);
                        }
                    }
                }
            }) { IsBackground = true, Name = "rtp-receive", Priority = ThreadPriority.AboveNormal };
            receiver.Start();

            var sent = 0;
            try
            {
                for (var i = 0; i < total && !ct.IsCancellationRequested; i++)
                {
                    var dueUs = (long)i * o.PtimeMs * 1000;
                    while (true)
                    {
                        var remaining = dueUs - NowUs();
                        if (remaining <= 0)
                        {
                            break;
                        }

                        if (remaining > 2000)
                        {
                            Thread.Sleep(1);
                        }
                        else
                        {
                            Thread.SpinWait(50);
                        }
                    }

                    var seq = (firstSeq + i) & 0xFFFF;
                    try
                    {
                        socket.Send(RtpProtocol.Build(codec, o.PtimeMs, seq, ssrc, NowUs(), first: i == 0));
                    }
                    catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused)
                    {
                        Interlocked.Increment(ref refused);
                    }

                    sent++;
                }

                // Nachzügler abwarten, dann den Zähler des Reflektors abfragen
                ct.WaitHandle.WaitOne(1000);
                for (var attempt = 0; attempt < QueryTries && !ct.IsCancellationRequested; attempt++)
                {
                    lock (sync)
                    {
                        if (finalCount is not null || records.Count == 0)
                        {
                            break;
                        }
                    }

                    try
                    {
                        socket.Send(RtpProtocol.Build(codec, o.PtimeMs, (firstSeq + total + attempt) & 0xFFFF, ssrc, NowUs(), query: true));
                    }
                    catch (SocketException)
                    {
                    }

                    ct.WaitHandle.WaitOne(500);
                }
            }
            finally
            {
                Volatile.Write(ref done, true);
                receiver.Join(2000);
            }

            lock (sync)
            {
                RtpAnalysis.Analyze(m, sent, records, finalCount, codec, o.PtimeMs);
            }

            if (records.Count == 0 && refused > 0)
            {
                m.Error = "Gegenstelle lehnt ab (UDP-Port geschlossen – Reflektor aus?)";
            }

            if (ct.IsCancellationRequested)
            {
                m.Error = "Test abgebrochen";
            }
        }
        catch (SocketException ex)
        {
            m.Error = $"Senden an {o.Host}:{o.Port} fehlgeschlagen: {ex.Message}";
        }
        finally
        {
            if (timerRaised)
            {
                TryTimerPeriod(false);
            }
        }

        return m;
    }

    /// <summary>Windows-Timer für die Dauer des Tests auf 1 ms, damit die Pakete im 20-ms-Takt rausgehen.</summary>
    private static bool TryTimerPeriod(bool begin)
    {
        try
        {
            return (begin ? timeBeginPeriod(1) : timeEndPeriod(1)) == 0;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }
}
