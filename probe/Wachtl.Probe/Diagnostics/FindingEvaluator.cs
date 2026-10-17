using System.Globalization;
using System.Net.NetworkInformation;

namespace Wachtl.Probe.Diagnostics;

/// <summary>Schwellen der Client-Diagnose.</summary>
public sealed record EvaluatorOptions
{
    /// <summary>So viele Abfragen in Folge muss ein Zustand bestehen, bevor ein Hinweis entsteht.</summary>
    public int DebouncePolls { get; init; } = 2;

    /// <summary>… und mindestens so lange (Abfragen nach Netzwerkereignissen kommen schneller als alle 5 s).</summary>
    public TimeSpan DebounceMin { get; init; } = TimeSpan.FromSeconds(4);

    /// <summary>
    /// So lange darf eine Karte ohne Link sein, bevor „Kabel getrennt“ kritisch bzw. „WLAN getrennt“ gemeldet wird:
    /// Aufwachen aus dem Standby, Abdocken (WLAN übernimmt erst nach einigen Sekunden), Deaktivieren der Karte.
    /// </summary>
    public TimeSpan LinkDownGrace { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>Nach dem Erledigen derselbe Hinweis für dieselbe Karte frühestens nach dieser Zeit (außer er wird schwerer).</summary>
    public TimeSpan Suppress { get; init; } = TimeSpan.FromMinutes(30);

    /// <summary>Liegen zwischen zwei Abfragen mehr als so viel, war der PC im Standby bzw. Ruhezustand.</summary>
    public TimeSpan ResumeGap { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// So lange nach dem Aufwachen zählen Link-Abbrüche nicht als „wackelt“, NDIS-Zurücksetzen nicht als Fehler und
    /// die Geschwindigkeit wird nicht bewertet (Karte handelt sie neu aus, Wake-on-LAN läuft mit 10/100 Mbit/s).
    /// </summary>
    public TimeSpan ResumeGrace { get; init; } = TimeSpan.FromSeconds(60);

    public long LowSpeedBps { get; init; } = 1_000_000_000;
    public long CriticalSpeedBps { get; init; } = 100_000_000;
    public TimeSpan SpeedLowAfter { get; init; } = TimeSpan.FromSeconds(30);

    public TimeSpan FlapWindow { get; init; } = TimeSpan.FromMinutes(10);
    public int FlapCount { get; init; } = 3;

    public TimeSpan ResetWindow { get; init; } = TimeSpan.FromMinutes(15);
    public int ResetCount { get; init; } = 2;

    public TimeSpan ErrorWindow { get; init; } = TimeSpan.FromMinutes(1);
    public long ErrorMin { get; init; } = 50;
    public double ErrorRatio { get; init; } = 0.005;
}

/// <summary>
/// Bewertet Momentaufnahmen der Netzwerkkarten und liefert Hinweise, die neu entstanden, schwerer geworden
/// oder erledigt sind. Rein rechnerisch – keine Windows-Aufrufe, die Zeit kommt aus der Momentaufnahme.
/// </summary>
public sealed class FindingEvaluator
{
    /// <summary>Geräte-Manager-Codes ohne Handlungsbedarf: 21 wird gerade entfernt (Abdocken, Treiberupdate), 22 deaktiviert,
    /// 24/45 nicht angeschlossen, 47 zum Entfernen vorbereitet.</summary>
    private static readonly HashSet<int> IgnoredPnpCodes = new() { 0, 21, 22, 24, 45, 47 };

    /// <summary>Hinweise, die an einer bestimmten (verbundenen) Karte hängen und mit ihr verschwinden.</summary>
    private static readonly string[] LinkKinds =
    {
        FindingKinds.CableUnplugged, FindingKinds.WifiDisconnected, FindingKinds.LinkSpeedChanged, FindingKinds.LinkSpeedLow,
        FindingKinds.LinkFlapping, FindingKinds.Apipa, FindingKinds.NicErrors,
    };

    private readonly EvaluatorOptions _o;
    private readonly Dictionary<string, Track> _tracks = new(StringComparer.Ordinal);
    private readonly Dictionary<string, AdapterTrack> _adapters = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Standby-Zeiträume (Beginn bis Ende der Schonfrist nach dem Aufwachen), für NDIS-Ereignisse.</summary>
    private readonly List<(DateTimeOffset From, DateTimeOffset To)> _sleeps = new();
    private DateTimeOffset? _lastAt;
    private DateTimeOffset _graceUntil = DateTimeOffset.MinValue;

    public FindingEvaluator(EvaluatorOptions? options = null)
    {
        _o = options ?? new EvaluatorOptions();
    }

    private enum Cond
    {
        Unknown,
        Present,
        Absent,
    }

    private sealed record Candidate(FindingSeverity Severity, string Adapter, string Description, FindingText Text,
        Dictionary<string, string> Details);

    private sealed class Track
    {
        public int Streak;
        public DateTimeOffset FirstSeen;
        public int ClearStreak;
        public DateTimeOffset ClearSince;
        public ClientFinding? Active;
        public FindingSeverity ActiveSeverity;
        public DateTimeOffset? ResolvedAt;
        public FindingSeverity ResolvedSeverity;
    }

    private sealed class AdapterTrack
    {
        public string Name = string.Empty;
        public bool EverUp;
        public LinkStatus? LastStatus;
        public DateTimeOffset? DownSince;
        public readonly List<DateTimeOffset> Downs = new();
        public long CandSpeed = -1;
        public int CandCount;
        public DateTimeOffset CandSince;
        public long StableSpeed = -1;
        public DateTimeOffset StableSince;
        public long SpeedRef = -1;
        public long LowNotified = -1;
        public readonly List<(DateTimeOffset At, long Errors, long Packets)> Counters = new();
    }

    /// <summary>Alle zurzeit aktiven Hinweise.</summary>
    public IReadOnlyList<ClientFinding> Active => _tracks.Values.Where(t => t.Active is not null).Select(t => t.Active!).ToList();

    public void Reset()
    {
        _tracks.Clear();
        _adapters.Clear();
        _sleeps.Clear();
        _lastAt = null;
        _graceUntil = DateTimeOffset.MinValue;
    }

    /// <summary>Nach dem Aufwachen aus Standby/Ruhezustand (siehe <see cref="EvaluatorOptions.ResumeGrace"/>).</summary>
    private bool InResumeGrace(DateTimeOffset now) => now < _graceUntil;

    public IReadOnlyList<ClientFinding> Evaluate(AdapterSnapshot snapshot)
    {
        var now = snapshot.At;
        var output = new List<ClientFinding>();
        if (_lastAt is { } last && now - last > _o.ResumeGap)
        {
            // PC hat geschlafen: Abbrüche ab der letzten Abfrage davor gehören zum Einschlafen
            _graceUntil = now + _o.ResumeGrace;
            _sleeps.Add((last, _graceUntil));
            foreach (var at in _adapters.Values)
            {
                at.Downs.RemoveAll(d => d >= last);
                at.DownSince = null; // die 15 s für „Kabel getrennt“/„WLAN getrennt“ zählen ab dem Aufwachen
            }
        }

        _lastAt = now;
        _sleeps.RemoveAll(s => now - s.To > _o.ResetWindow);
        var physical = snapshot.Adapters
            .Where(a => a.IsPhysical && !string.IsNullOrEmpty(a.Id))
            .GroupBy(a => a.Id, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();
        var linked = physical.Where(a => a.Status is LinkStatus.Up or LinkStatus.Down).ToList();

        foreach (var adapter in linked)
        {
            EvaluateLink(adapter, linked, now, output);
        }

        // Karten, die verschwunden oder deaktiviert sind: zugehörige Hinweise erledigen, nichts Neues melden
        var linkedIds = linked.Select(a => a.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var (id, track) in _adapters.Where(p => !linkedIds.Contains(p.Key)).ToList())
        {
            foreach (var kind in LinkKinds)
            {
                if (_tracks.TryGetValue(Key(kind, id), out var t))
                {
                    if (t.Active is not null)
                    {
                        Resolve(t, now, FindingTexts.AdapterGone(track.Name), output);
                    }

                    t.Streak = 0;
                    t.ClearStreak = 0;
                }
            }

            _adapters.Remove(id);
        }

        EvaluateDrivers(physical, now, output);
        EvaluateGateway(snapshot, linked, now, output);
        EvaluateResets(snapshot, physical, now, output);
        return output;
    }

    // -- Karte mit Link-Zustand ---------------------------------------------

    private void EvaluateLink(AdapterState a, List<AdapterState> linked, DateTimeOffset now, List<ClientFinding> output)
    {
        if (!_adapters.TryGetValue(a.Id, out var at))
        {
            at = _adapters[a.Id] = new AdapterTrack();
        }

        at.Name = a.Name;
        var up = a.Status == LinkStatus.Up;
        if (up)
        {
            at.EverUp = true;
        }
        else if (at.LastStatus == LinkStatus.Up && !InResumeGrace(now))
        {
            at.Downs.Add(now);
        }

        at.DownSince = up ? null : at.DownSince ?? now;
        var downLong = !up && now - at.DownSince >= _o.LinkDownGrace;
        at.LastStatus = a.Status;
        at.Downs.RemoveAll(d => now - d > _o.FlapWindow);

        var fallback = linked.FirstOrDefault(o => !ReferenceEquals(o, a) && o.Status == LinkStatus.Up && o.HasRoutableIpv4 && o.HasGateway)?.Name;

        if (a.IsEthernet)
        {
            // Läuft die Verbindung über eine andere Karte weiter (Laptop abgedockt, WLAN übernimmt), nur „info“:
            // der Server erfährt es, eine Sprechblase gibt es erst, wenn auch die andere Verbindung wegfällt.
            // Kritisch erst nach LinkDownGrace – vorher ist es oft Standby, Abdocken oder Deaktivieren.
            var cond = up ? Cond.Absent : at.EverUp ? Cond.Present : Cond.Unknown;
            Step(FindingKinds.CableUnplugged, a.Id, cond,
                () => new Candidate(fallback is null && downLong ? FindingSeverity.Critical : FindingSeverity.Info, a.Name, a.Description,
                    FindingTexts.CableUnplugged(a, fallback), new()),
                now, firePolls: 1, resolvePolls: 2, f => FindingTexts.CableReconnected(a.Name, Since(f, now)), output);

            var flapCond = at.Downs.Count >= _o.FlapCount ? Cond.Present : at.Downs.Count == 0 && up ? Cond.Absent : Cond.Unknown;
            Step(FindingKinds.LinkFlapping, a.Id, flapCond,
                () => new Candidate(FindingSeverity.Warning, a.Name, a.Description, FindingTexts.Flapping(a, at.Downs.Count),
                    new() { ["count"] = Str(at.Downs.Count), ["window_min"] = Str((long)_o.FlapWindow.TotalMinutes) }),
                now, firePolls: 1, resolvePolls: 1, _ => FindingTexts.FlappingResolved(a.Name), output);

            EvaluateSpeed(a, at, up, now, output);
        }
        else if (a.IsWifi)
        {
            // WLAN getrennt, während ein Kabel verbunden ist, ist normal (z. B. Dockingstation) – kein Hinweis
            // erst nach LinkDownGrace: Roaming, Aufwachen aus dem Standby
            var cond = up ? Cond.Absent : at.EverUp && fallback is null && downLong ? Cond.Present : Cond.Unknown;
            Step(FindingKinds.WifiDisconnected, a.Id, cond,
                () => new Candidate(FindingSeverity.Warning, a.Name, a.Description, FindingTexts.WifiDisconnected(a, fallback), new()),
                now, firePolls: 1, 2, f => FindingTexts.WifiReconnected(a.Name, Since(f, now)), output);
        }

        // DHCP: nur 169.254.x.x – läuft die Verbindung über eine andere Karte (Zweitkarte an Gerät ohne DHCP), nur „info“
        var apipa = !up ? Cond.Unknown
            : a.HasRoutableIpv4 ? Cond.Absent
            : a.Ipv4.Count > 0 ? Cond.Present
            : Cond.Unknown;
        Step(FindingKinds.Apipa, a.Id, apipa,
            () => new Candidate(fallback is null ? FindingSeverity.Critical : FindingSeverity.Info, a.Name, a.Description, FindingTexts.Apipa(a),
                new() { ["ip"] = a.Ipv4.FirstOrDefault() ?? string.Empty }),
            now, _o.DebouncePolls, 1, _ => FindingTexts.ApipaResolved(a.Name, a.Ipv4.FirstOrDefault(ip => !AdapterClassifier.IsApipa(ip))), output);

        EvaluateErrors(a, at, up, now, output);
    }

    private void EvaluateSpeed(AdapterState a, AdapterTrack at, bool up, DateTimeOffset now, List<ClientFinding> output)
    {
        if (InResumeGrace(now))
        {
            // nach dem Aufwachen nicht bewerten; danach gilt die dann stabile Geschwindigkeit als Ausgangswert
            at.CandSpeed = -1;
            at.CandCount = 0;
            at.StableSpeed = -1;
            return;
        }

        if (!up)
        {
            at.CandSpeed = -1;
            at.CandCount = 0;
        }
        else if (a.SpeedBps > 0)
        {
            if (a.SpeedBps == at.CandSpeed)
            {
                at.CandCount++;
            }
            else
            {
                at.CandSpeed = a.SpeedBps;
                at.CandCount = 1;
                at.CandSince = now;
            }

            if (at.CandCount >= _o.DebouncePolls && now - at.CandSince >= _o.DebounceMin && at.CandSpeed != at.StableSpeed)
            {
                var previous = at.StableSpeed;
                at.StableSpeed = at.CandSpeed;
                at.StableSince = at.CandSince;
                at.LowNotified = -1;
                // previous <= 0 nach dem Aufwachen: nur einen schon gemeldeten Abfall prüfen, nichts Neues melden
                if (previous > 0 || Get(FindingKinds.LinkSpeedChanged, a.Id).Active is not null)
                {
                    SpeedChanged(a, at, previous, at.StableSpeed, now, output);
                }
            }
        }

        // dauerhaft unter 1 Gbit/s – nur einmal je Geschwindigkeit
        var low = Get(FindingKinds.LinkSpeedLow, a.Id);
        Cond cond;
        if (!up || at.StableSpeed <= 0)
        {
            cond = Cond.Unknown;
        }
        else if (at.StableSpeed >= _o.LowSpeedBps)
        {
            cond = Cond.Absent;
        }
        else if (low.Active is not null)
        {
            cond = Cond.Present;
        }
        else if (now - at.StableSince >= _o.SpeedLowAfter && at.LowNotified != at.StableSpeed)
        {
            if (Get(FindingKinds.LinkSpeedChanged, a.Id).Active is not null)
            {
                at.LowNotified = at.StableSpeed; // der Abfall wurde schon gemeldet
                cond = Cond.Unknown;
            }
            else
            {
                cond = Cond.Present;
            }
        }
        else
        {
            cond = Cond.Unknown;
        }

        var speed = at.StableSpeed;
        Step(FindingKinds.LinkSpeedLow, a.Id, cond,
            // 100 Mbit/s (IP-Telefon, USB-2.0-Adapter) nur „info“ für den Server, keine Sprechblase; 10 Mbit/s kritisch
            () => new Candidate(speed < _o.CriticalSpeedBps ? FindingSeverity.Critical : FindingSeverity.Info, a.Name, a.Description,
                FindingTexts.SpeedLow(a, speed), new() { ["speed_mbps"] = FindingTexts.Mbps(speed) }),
            now, firePolls: 1, resolvePolls: 1, _ => FindingTexts.SpeedRestored(a.Name, speed), output);
        if (low.Active is not null)
        {
            at.LowNotified = at.StableSpeed;
        }
    }

    private void SpeedChanged(AdapterState a, AdapterTrack at, long previous, long current, DateTimeOffset now, List<ClientFinding> output)
    {
        var t = Get(FindingKinds.LinkSpeedChanged, a.Id);
        if (t.Active is null)
        {
            if (current < previous)
            {
                var c = SpeedCandidate(a, previous, current);
                if (TryFire(t, FindingKinds.LinkSpeedChanged, c, now, now, output) is not null)
                {
                    at.SpeedRef = previous;
                }
            }

            return;
        }

        if (current >= at.SpeedRef)
        {
            Resolve(t, now, FindingTexts.SpeedRestored(a.Name, current), output);
        }
        else
        {
            Update(t, SpeedCandidate(a, at.SpeedRef, current), output);
        }
    }

    private static Candidate SpeedCandidate(AdapterState a, long oldBps, long newBps) =>
        new(FindingSeverity.Warning, a.Name, a.Description, FindingTexts.SpeedChanged(a, oldBps, newBps),
            new() { ["old_mbps"] = FindingTexts.Mbps(oldBps), ["new_mbps"] = FindingTexts.Mbps(newBps) });

    private void EvaluateErrors(AdapterState a, AdapterTrack at, bool up, DateTimeOffset now, List<ClientFinding> output)
    {
        var cond = Cond.Unknown;
        long delta = 0;
        double ratio = 0;
        if (up && a.ErrorPackets is { } errors && a.TotalPackets is { } packets)
        {
            var samples = at.Counters;
            if (samples.Count > 0 && (errors < samples[^1].Errors || packets < samples[^1].Packets))
            {
                samples.Clear(); // Zähler zurückgesetzt (Treiber neu geladen, Neustart der Karte)
            }

            samples.Add((now, errors, packets));
            samples.RemoveAll(s => now - s.At > _o.ErrorWindow * 3);
            var reference = samples.LastOrDefault(s => now - s.At >= _o.ErrorWindow);
            if (reference != default)
            {
                delta = errors - reference.Errors;
                var dp = packets - reference.Packets;
                ratio = dp > 0 ? (double)delta / dp : delta > 0 ? 1 : 0;
                cond = delta > _o.ErrorMin && ratio > _o.ErrorRatio ? Cond.Present : Cond.Absent;
            }
        }

        Step(FindingKinds.NicErrors, a.Id, cond,
            () => new Candidate(FindingSeverity.Warning, a.Name, a.Description, FindingTexts.NicErrors(a, delta, Math.Min(100, ratio * 100)),
                new() { ["errors_per_min"] = Str(delta), ["error_pct"] = (Math.Min(100, ratio * 100)).ToString("0.00", CultureInfo.InvariantCulture) }),
            now, _o.DebouncePolls, 1, _ => FindingTexts.NicErrorsResolved(a.Name), output);
    }

    // -- Geräte-Manager, Gateway, Ereignisprotokoll -------------------------

    private void EvaluateDrivers(List<AdapterState> physical, DateTimeOffset now, List<ClientFinding> output)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var a in physical)
        {
            seen.Add(a.Id);
            var code = a.PnpErrorCode;
            var cond = IgnoredPnpCodes.Contains(code) ? Cond.Absent : Cond.Present;
            Step(FindingKinds.DriverError, a.Id, cond,
                () => new Candidate(FindingSeverity.Critical, a.Name, a.Description, FindingTexts.DriverError(a, code),
                    new() { ["error_code"] = Str(code) }),
                now, _o.DebouncePolls, 1, f => FindingTexts.DriverOk(Device(f)), output);
        }

        // Gerät ganz entfernt: Fehler erledigt
        var prefix = FindingKinds.DriverError + "|";
        foreach (var (key, t) in _tracks.Where(p => p.Key.StartsWith(prefix, StringComparison.Ordinal)).ToList())
        {
            if (!seen.Contains(key[prefix.Length..]) && t.Active is not null)
            {
                Resolve(t, now, FindingTexts.DriverOk(Device(t.Active)), output);
            }
        }
    }

    private void EvaluateGateway(AdapterSnapshot snapshot, List<AdapterState> linked, DateTimeOffset now, List<ClientFinding> output)
    {
        var withIp = linked.Where(a => a.Status == LinkStatus.Up && a.HasRoutableIpv4).ToList();
        // Gateway auf irgendeiner Schnittstelle (auch VPN, vEthernet) zählt – sonst Fehlalarm bei Hyper-V-Switch
        var anyGateway = snapshot.Adapters.Any(a => a.Status == LinkStatus.Up && a.HasGateway && a.Type != NetworkInterfaceType.Loopback);
        var cond = withIp.Count == 0 ? Cond.Unknown : anyGateway ? Cond.Absent : Cond.Present;
        Step(FindingKinds.NoGateway, string.Empty, cond,
            () => new Candidate(FindingSeverity.Warning, withIp[0].Name, withIp[0].Description, FindingTexts.NoGateway(withIp[0]),
                new() { ["ip"] = withIp[0].Ipv4.FirstOrDefault(ip => !AdapterClassifier.IsApipa(ip)) ?? string.Empty }),
            now, _o.DebouncePolls, 1, _ => FindingTexts.GatewayResolved(), output);
    }

    private void EvaluateResets(AdapterSnapshot snapshot, List<AdapterState> physical, DateTimeOffset now, List<ClientFinding> output)
    {
        if (snapshot.Resets is null)
        {
            return;
        }

        var recent = snapshot.Resets.Where(r => now - r.At <= _o.ResetWindow && r.At - now <= TimeSpan.FromMinutes(1)
                && !_sleeps.Any(s => r.At >= s.From && r.At <= s.To)) // Zurücksetzen beim Einschlafen/Aufwachen ist normal
            .ToList();
        var cond = recent.Count >= _o.ResetCount ? Cond.Present : recent.Count == 0 ? Cond.Absent : Cond.Unknown;
        Step(FindingKinds.NicReset, string.Empty, cond, () =>
            {
                var hint = recent.Where(r => !string.IsNullOrWhiteSpace(r.Adapter))
                    .GroupBy(r => r.Adapter!, StringComparer.OrdinalIgnoreCase)
                    .OrderByDescending(g => g.Count())
                    .Select(g => g.Key)
                    .FirstOrDefault();
                var match = hint is null
                    ? null
                    : physical.FirstOrDefault(a => string.Equals(a.Description, hint, StringComparison.OrdinalIgnoreCase)
                                                   || string.Equals(a.Name, hint, StringComparison.OrdinalIgnoreCase));
                return new Candidate(FindingSeverity.Warning, match?.Name ?? hint ?? string.Empty, match?.Description ?? hint ?? string.Empty,
                    FindingTexts.NicReset(match?.Name ?? hint, recent.Count),
                    new() { ["count"] = Str(recent.Count), ["window_min"] = Str((long)_o.ResetWindow.TotalMinutes), ["event_id"] = "10400" });
            },
            now, firePolls: 1, resolvePolls: 1, _ => FindingTexts.NicResetResolved(), output);
    }

    // -- Zustandsmaschine je Art und Karte ----------------------------------

    private static string Key(string kind, string adapterId) => kind + "|" + adapterId.ToLowerInvariant();

    private Track Get(string kind, string adapterId)
    {
        var key = Key(kind, adapterId);
        if (!_tracks.TryGetValue(key, out var t))
        {
            t = _tracks[key] = new Track();
        }

        return t;
    }

    private void Step(string kind, string adapterId, Cond cond, Func<Candidate> candidate, DateTimeOffset now, int firePolls,
        int resolvePolls, Func<ClientFinding, FindingText> resolved, List<ClientFinding> output)
    {
        var t = Get(kind, adapterId);
        switch (cond)
        {
            case Cond.Present:
            {
                t.ClearStreak = 0;
                if (t.Streak == 0)
                {
                    t.FirstSeen = now;
                }

                t.Streak++;
                var c = candidate();
                if (t.Active is not null)
                {
                    if (c.Severity > t.ActiveSeverity)
                    {
                        Update(t, c, output);
                    }
                }
                else if (t.Streak >= firePolls && (firePolls <= 1 || now - t.FirstSeen >= _o.DebounceMin))
                {
                    TryFire(t, kind, c, t.FirstSeen, now, output);
                }

                break;
            }

            case Cond.Absent:
                t.Streak = 0;
                if (t.Active is null)
                {
                    break;
                }

                if (t.ClearStreak == 0)
                {
                    t.ClearSince = now;
                }

                t.ClearStreak++;
                if (t.ClearStreak >= resolvePolls && (resolvePolls <= 1 || now - t.ClearSince >= _o.DebounceMin))
                {
                    Resolve(t, now, resolved(t.Active), output);
                }

                break;
        }
    }

    private ClientFinding? TryFire(Track t, string kind, Candidate c, DateTimeOffset detected, DateTimeOffset now, List<ClientFinding> output)
    {
        if (t.ResolvedAt is { } resolvedAt && now - resolvedAt < _o.Suppress && c.Severity <= t.ResolvedSeverity)
        {
            return null; // eben erst erledigt – wiederholtes Kommen und Gehen meldet link_flapping
        }

        var finding = new ClientFinding
        {
            FindingId = Guid.NewGuid().ToString(),
            Kind = kind,
            Severity = ClientFinding.SeverityName(c.Severity),
            State = "active",
            Adapter = ClientFinding.Clamp(c.Adapter, 256),
            AdapterDescription = ClientFinding.Clamp(c.Description, 256),
            Title = ClientFinding.Clamp(c.Text.Title, ClientFinding.MaxTitle),
            Message = ClientFinding.Clamp(c.Text.Message, ClientFinding.MaxText),
            Solution = ClientFinding.Clamp(c.Text.Solution, ClientFinding.MaxText),
            Details = ClientFinding.ClampDetails(c.Details),
            DetectedAt = detected.ToUnixTimeSeconds(),
        };
        t.Active = finding;
        t.ActiveSeverity = c.Severity;
        output.Add(finding);
        return finding;
    }

    private static void Update(Track t, Candidate c, List<ClientFinding> output)
    {
        var old = t.Active!;
        var finding = new ClientFinding
        {
            FindingId = old.FindingId,
            Kind = old.Kind,
            Severity = ClientFinding.SeverityName(c.Severity),
            State = "active",
            Adapter = ClientFinding.Clamp(c.Adapter, 256),
            AdapterDescription = ClientFinding.Clamp(c.Description, 256),
            Title = ClientFinding.Clamp(c.Text.Title, ClientFinding.MaxTitle),
            Message = ClientFinding.Clamp(c.Text.Message, ClientFinding.MaxText),
            Solution = ClientFinding.Clamp(c.Text.Solution, ClientFinding.MaxText),
            Details = ClientFinding.ClampDetails(c.Details),
            DetectedAt = old.DetectedAt,
        };
        t.Active = finding;
        t.ActiveSeverity = c.Severity;
        output.Add(finding);
    }

    /// <summary>Erledigt: Titel und Text beschreiben die Lösung, „problem“ in details den ursprünglichen Titel.</summary>
    private static void Resolve(Track t, DateTimeOffset now, FindingText text, List<ClientFinding> output)
    {
        var old = t.Active!;
        var details = new Dictionary<string, string>(old.Details, StringComparer.Ordinal)
        {
            ["problem"] = old.Title,
            ["duration_s"] = Str(Math.Max(0, now.ToUnixTimeSeconds() - old.DetectedAt)),
        };
        var finding = new ClientFinding
        {
            FindingId = old.FindingId,
            Kind = old.Kind,
            Severity = old.Severity,
            State = "resolved",
            Adapter = old.Adapter,
            AdapterDescription = old.AdapterDescription,
            Title = ClientFinding.Clamp(text.Title, ClientFinding.MaxTitle),
            Message = ClientFinding.Clamp(text.Message, ClientFinding.MaxText),
            Solution = string.Empty,
            Details = ClientFinding.ClampDetails(details),
            DetectedAt = old.DetectedAt,
            ResolvedAt = now.ToUnixTimeSeconds(),
        };
        t.ResolvedAt = now;
        t.ResolvedSeverity = t.ActiveSeverity;
        t.Active = null;
        t.Streak = 0;
        t.ClearStreak = 0;
        output.Add(finding);
    }

    private static TimeSpan Since(ClientFinding f, DateTimeOffset now) =>
        TimeSpan.FromSeconds(Math.Max(0, now.ToUnixTimeSeconds() - f.DetectedAt));

    private static string Device(ClientFinding f) => string.IsNullOrEmpty(f.AdapterDescription) ? f.Adapter : f.AdapterDescription;

    private static string Str(long value) => value.ToString(CultureInfo.InvariantCulture);
}
