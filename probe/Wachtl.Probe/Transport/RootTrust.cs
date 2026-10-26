using System.Security.Cryptography.X509Certificates;

namespace Wachtl.Probe.Transport;

/// <summary>
/// Legt das selbstsignierte Zertifikat des Wachtl-Servers unter „Vertrauenswürdige Stammzertifizierungsstellen“
/// (Computer) ab, damit Browser auf dem PC das Web-UI ohne Warnung öffnen. Die Probe selbst braucht das nicht –
/// sie prüft weiterhin nur den Pin. Schreiben darf nur ein Administrator (Setup), nicht der Dienst.
/// </summary>
public static class RootTrust
{
    /// <summary>
    /// Anzeigename im Zertifikatspeicher; daran erkennen Setup und Deinstallation „ihr“ Zertifikat. Bewusst anders
    /// als beim Server-Setup („Wachtl Server“): Liegt beides auf einem Rechner, entfernt keiner das des anderen.
    /// </summary>
    public const string FriendlyName = "Wachtl Server (Probe)";

    public enum Outcome
    {
        Added,
        AlreadyTrusted,
        NotSelfSigned,
    }

    /// <summary>Nur ein selbstsigniertes Zertifikat gehört in den Stammspeicher; eines von einer echten CA nicht.</summary>
    public static bool IsSelfSigned(X509Certificate2 certificate) =>
        certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);

    /// <summary>
    /// Was im Speicher zu tun ist: ältere Wachtl-Zertifikate (gleicher Anzeigename, anderer Fingerabdruck) entfernen,
    /// das aktuelle hinzufügen, falls es noch fehlt. Von Hand oder per GPO abgelegte Zertifikate bleiben unberührt.
    /// </summary>
    internal static (List<X509Certificate2> Remove, bool Add) Plan(IEnumerable<X509Certificate2> store, X509Certificate2 certificate)
    {
        var remove = new List<X509Certificate2>();
        var present = false;
        foreach (var existing in store)
        {
            if (string.Equals(existing.Thumbprint, certificate.Thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                present = true;
            }
            else if (existing.FriendlyName == FriendlyName)
            {
                remove.Add(existing);
            }
        }

        return (remove, !present);
    }

    public static Outcome Install(X509Certificate2 certificate)
    {
        if (!IsSelfSigned(certificate))
        {
            return Outcome.NotSelfSigned;
        }

        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        var (remove, add) = Plan(store.Certificates.Cast<X509Certificate2>(), certificate);
        foreach (var old in remove)
        {
            store.Remove(old);
        }

        if (!add)
        {
            return Outcome.AlreadyTrusted;
        }

        using var copy = new X509Certificate2(certificate.RawData) { FriendlyName = RootTrust.FriendlyName };
        store.Add(copy);
        return Outcome.Added;
    }

    /// <summary>Alle von Wachtl abgelegten Zertifikate entfernen (Deinstallation). Gibt die Anzahl zurück.</summary>
    public static int RemoveAll()
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        var ours = store.Certificates.Cast<X509Certificate2>().Where(c => c.FriendlyName == FriendlyName).ToList();
        foreach (var cert in ours)
        {
            store.Remove(cert);
        }

        return ours.Count;
    }
}
