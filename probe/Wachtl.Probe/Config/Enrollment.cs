using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Config;

/// <summary>Registrierung am Server – gemeinsam für Setup (CLI) und Dienst (nachgeholte Registrierung).</summary>
public static class Enrollment
{
    /// <summary>
    /// Registriert die Probe über die erste erreichbare Adresse und speichert den Zustand
    /// (Token per DPAPI verschlüsselt, alle Adressen für spätere Ausweichversuche).
    /// </summary>
    public static async Task<(ProbeState State, EnrollResponse Response)> EnrollAsync(
        IReadOnlyList<Uri> servers, string pin, string enrollmentToken, string? proxy, string hostname, CancellationToken ct)
    {
        using var api = new ApiClient(servers, pin, proxy);
        var response = await api.EnrollAsync(new EnrollRequest
        {
            EnrollmentToken = enrollmentToken,
            Hostname = hostname,
            Os = AppInfo.OsDescription,
            Version = AppInfo.Version,
        }, ct).ConfigureAwait(false);

        var state = new ProbeState
        {
            ServerUrl = api.CurrentServer.ToString(),
            ServerUrls = servers.Select(s => s.ToString()).ToList(),
            SpkiPin = pin,
            ProbeId = response.ProbeId,
            ProtectedToken = StateStore.ProtectToken(response.Token),
            Proxy = proxy,
            SiteName = response.SiteName,
            EnrolledAt = DateTimeOffset.UtcNow,
        };
        StateStore.Save(state);
        StateStore.DeletePending();
        return (state, response);
    }

    /// <summary>Registrierung zum Nachholen merken (Server beim Setup nicht erreichbar).</summary>
    public static void Defer(IReadOnlyList<Uri> servers, string pin, string enrollmentToken, string? proxy, string hostname, string error)
    {
        StateStore.SavePending(new PendingEnrollment
        {
            ServerUrls = servers.Select(s => s.ToString()).ToList(),
            SpkiPin = pin,
            ProtectedEnrollmentToken = StateStore.ProtectToken(enrollmentToken),
            Proxy = proxy,
            Hostname = hostname,
            CreatedAt = DateTimeOffset.UtcNow,
            LastError = error,
        });
    }

    /// <summary>Adressliste aus „a,b;c d“ – ohne Schema wird https:// ergänzt.</summary>
    public static List<Uri> ParseServers(string value)
    {
        var list = new List<Uri>();
        foreach (var part in value.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var text = part.Contains("://", StringComparison.Ordinal) ? part : "https://" + part;
            if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            {
                throw new ArgumentException($"Die Server-Adresse muss mit https:// beginnen: {part}");
            }

            var normalized = new Uri(uri.GetLeftPart(UriPartial.Authority) + "/");
            if (!list.Contains(normalized))
            {
                list.Add(normalized);
            }
        }

        if (list.Count == 0)
        {
            throw new ArgumentException("--server fehlt");
        }

        return list;
    }
}
