using System.Security.Cryptography.X509Certificates;

namespace Wachtl.Probe.Transport;

/// <summary>
/// Legt die Wachtl-CA (bei älteren Servern deren selbstsigniertes Zertifikat) unter „Vertrauenswürdige Stammzertifizierungsstellen“
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
    /// Welches Zertifikat in den Stammspeicher gehört: die vom Server gelieferte Wachtl-CA, wenn das (gepinnte)
    /// Server-Zertifikat nachweislich von ihr ausgestellt ist und ihre Namensbeschränkung einhält. Ältere Server
    /// ohne CA: das selbstsignierte Server-Zertifikat. Sonst (Zertifikat einer fremden CA): nichts.
    /// </summary>
    public static X509Certificate2? SelectRoot(X509Certificate2 serverCertificate, X509Certificate2? downloadedCa)
    {
        if (downloadedCa is not null && IsSelfSigned(downloadedCa) && ChainsTo(serverCertificate, downloadedCa))
        {
            return downloadedCa;
        }

        return IsSelfSigned(serverCertificate) ? serverCertificate : null;
    }

    /// <summary>Baut die Kette Server-Zertifikat → CA mit genau dieser CA als einziger Vertrauensbasis.</summary>
    internal static bool ChainsTo(X509Certificate2 certificate, X509Certificate2 root)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(certificate);
    }

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
