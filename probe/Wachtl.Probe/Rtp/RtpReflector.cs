using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace Wachtl.Probe.Rtp;

/// <summary>
/// Zustand des Reflektors ohne Socket (testbar): zählt je Strom (Absender + SSRC), begrenzt die Rate je Absender
/// und antwortet nur auf Wachtl-RTP-Pakete in gleicher Größe – wie server/wachtl/rtp/reflector.py.
/// </summary>
public sealed class RtpReflectorState
{
    public const int PerSourcePps = 2000;
    public const int TotalPps = 20000;
    public const int SessionIdleS = 120;
    public const int MaxSessions = 50000;

    private readonly Dictionary<(string Ip, int Port, uint Ssrc), (uint Count, double Seen)> _sessions = new();
    private readonly Dictionary<string, Bucket> _sources = new();
    private readonly Bucket _total;
    private double _nextCleanup;

    public RtpReflectorState(double now)
    {
        _total = new Bucket(TotalPps, now);
        _nextCleanup = now + 10;
    }

    public int Sessions => _sessions.Count;

    /// <summary>Paket prüfen und in <paramref name="data"/> die Antwort eintragen. false = nicht antworten.</summary>
    public bool Handle(Span<byte> data, string ip, int port, double now)
    {
        if (RtpProtocol.Parse(data) is not { } packet)
        {
            return false;
        }

        if (!_sources.TryGetValue(ip, out var bucket))
        {
            bucket = _sources[ip] = new Bucket(PerSourcePps, now);
        }

        if (!bucket.Take(now) || !_total.Take(now))
        {
            return false;
        }

        var key = (ip, port, packet.Ssrc);
        if (!_sessions.TryGetValue(key, out var session))
        {
            if (_sessions.Count >= MaxSessions)
            {
                return false;
            }

            session = (0, now);
        }

        session = (packet.Query ? session.Count : session.Count + 1, now);
        _sessions[key] = session;
        if (now >= _nextCleanup)
        {
            Cleanup(now);
        }

        RtpProtocol.Reflect(data, (long)(now * 1_000_000), session.Count);
        return true;
    }

    private void Cleanup(double now)
    {
        _nextCleanup = now + 10;
        foreach (var key in _sessions.Where(s => now - s.Value.Seen > SessionIdleS).Select(s => s.Key).ToList())
        {
            _sessions.Remove(key);
        }

        foreach (var ip in _sources.Where(s => now - s.Value.At > SessionIdleS).Select(s => s.Key).ToList())
        {
            _sources.Remove(ip);
        }
    }

    private sealed class Bucket
    {
        private readonly double _rate;
        private double _tokens;

        public Bucket(double rate, double now)
        {
            _rate = rate;
            _tokens = rate;
            At = now;
        }

        public double At { get; private set; }

        public bool Take(double now)
        {
            _tokens = Math.Min(_rate, _tokens + (now - At) * _rate);
            At = now;
            if (_tokens < 1)
            {
                return false;
            }

            _tokens -= 1;
            return true;
        }
    }
}

/// <summary>RTP-Reflektor auf der Probe, wenn sie im Web-UI als Gegenstelle für andere Probes eingerichtet ist.</summary>
public sealed class RtpReflector : IAsyncDisposable
{
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _cts = new();
    private readonly Thread _thread;
    private readonly Socket _socket;

    public RtpReflector(int port, ILogger logger)
    {
        Port = port;
        _logger = logger;
        _socket = Bind(port);

        if (OperatingSystem.IsWindows())
        {
            // ICMP „Port unreachable“ einer früheren Antwort darf den Empfang nicht abbrechen (SIO_UDP_CONNRESET aus)
            _socket.IOControl(unchecked((int)0x9800000C), new byte[4], null);
        }

        _socket.ReceiveTimeout = 1000;
        _thread = new Thread(Run) { IsBackground = true, Name = "rtp-reflector", Priority = ThreadPriority.AboveNormal };
        _thread.Start();
        _logger.LogInformation("RTP-Reflektor lauscht auf UDP-Port {Port}", port);
    }

    public int Port { get; }

    /// <summary>IPv6-Socket, der auch IPv4 annimmt; ohne IPv6 (abgeschaltet) nur IPv4.</summary>
    private static Socket Bind(int port)
    {
        if (Socket.OSSupportsIPv6)
        {
            Socket? dual = null;
            try
            {
                dual = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
                dual.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
                return dual;
            }
            catch (SocketException ex) when (ex.SocketErrorCode != SocketError.AddressAlreadyInUse)
            {
                dual?.Dispose();
            }
        }

        var v4 = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            v4.Bind(new IPEndPoint(IPAddress.Any, port));
            return v4;
        }
        catch
        {
            v4.Dispose();
            throw;
        }
    }

    private void Run()
    {
        var clock = Stopwatch.StartNew();
        var state = new RtpReflectorState(clock.Elapsed.TotalSeconds);
        var buffer = new byte[2048];
        EndPoint remote = new IPEndPoint(_socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
        while (!_cts.IsCancellationRequested)
        {
            int n;
            try
            {
                n = _socket.ReceiveFrom(buffer, ref remote);
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.TimedOut or SocketError.ConnectionReset or SocketError.MessageSize)
            {
                continue;
            }
            catch (Exception ex) when (ex is ObjectDisposedException or SocketException && _cts.IsCancellationRequested)
            {
                return;
            }
            catch (SocketException ex)
            {
                _logger.LogDebug("RTP-Reflektor: {Message}", ex.Message);
                continue;
            }

            var source = (IPEndPoint)remote;
            var ip = source.Address.IsIPv4MappedToIPv6 ? source.Address.MapToIPv4().ToString() : source.Address.ToString();
            if (!state.Handle(buffer.AsSpan(0, n), ip, source.Port, clock.Elapsed.TotalSeconds))
            {
                continue;
            }

            try
            {
                _socket.SendTo(buffer.AsSpan(0, n), SocketFlags.None, source);
            }
            catch (SocketException ex)
            {
                _logger.LogDebug("RTP-Reflektor: Antwort an {Ip} nicht gesendet: {Message}", ip, ex.Message);
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _socket.Dispose();
        _thread.Join(3000);
        _cts.Dispose();
        _logger.LogInformation("RTP-Reflektor gestoppt");
        return ValueTask.CompletedTask;
    }
}
