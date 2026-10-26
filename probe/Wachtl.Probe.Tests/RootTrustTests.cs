using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Tests;

public class RootTrustTests
{
    private static X509Certificate2 SelfSigned(string name = "CN=wachtl.test")
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    [Fact]
    public void OnlySelfSignedCertificatesBelongIntoRootStore()
    {
        using var ca = SelfSigned("CN=Firmen-CA");
        Assert.True(RootTrust.IsSelfSigned(ca));

        var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=wachtl.firma.local", leafKey, HashAlgorithmName.SHA256);
        using var leaf = request.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(6), new byte[] { 1, 2, 3, 4 });
        Assert.False(RootTrust.IsSelfSigned(leaf));
    }

    private static X509Certificate2 IssuedBy(X509Certificate2 ca, string dnsName)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=" + dnsName, key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(dnsName);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        var serial = RandomNumberGenerator.GetBytes(8);
        using var withoutKey = request.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(90), serial);
        return withoutKey.CopyWithPrivateKey(key);
    }

    [Fact]
    public void SelectRootPrefersWachtlCaThatIssuedTheServerCertificate()
    {
        using var ca = SelfSigned("CN=Wachtl CA wachtl.test");
        using var server = IssuedBy(ca, "wachtl.test");
        using var root = RootTrust.SelectRoot(server, ca);
        Assert.Equal(ca.Thumbprint, root!.Thumbprint);
    }

    [Fact]
    public void SelectRootRejectsCaThatDidNotIssueTheServerCertificate()
    {
        using var ca = SelfSigned("CN=Wachtl CA wachtl.test");
        using var other = SelfSigned("CN=Untergeschoben");
        using var server = IssuedBy(ca, "wachtl.test");
        Assert.Null(RootTrust.SelectRoot(server, other));
        Assert.Null(RootTrust.SelectRoot(server, null));
    }

    [Fact]
    public void SelectRootFallsBackToSelfSignedServerCertificateOfOlderServers()
    {
        using var selfSigned = SelfSigned();
        Assert.Equal(selfSigned.Thumbprint, RootTrust.SelectRoot(selfSigned, null)!.Thumbprint);
    }

    [Fact]
    public void PlanAddsMissingCertificateAndReplacesOlderWachtlCertificate()
    {
        using var current = SelfSigned();
        using var older = SelfSigned();
        older.FriendlyName = RootTrust.FriendlyName;
        using var foreign = SelfSigned("CN=Andere CA");

        var (remove, add) = RootTrust.Plan(new[] { older, foreign }, current);

        Assert.True(add);
        Assert.Equal(new[] { older.Thumbprint }, remove.Select(c => c.Thumbprint));
    }

    [Fact]
    public void PlanKeepsCertificateAlreadyTrustedByHandOrPolicy()
    {
        using var current = SelfSigned();
        using var byPolicy = new X509Certificate2(current.RawData); // gleicher Fingerabdruck, ohne Wachtl-Anzeigenamen

        var (remove, add) = RootTrust.Plan(new[] { byPolicy }, current);

        Assert.False(add);
        Assert.Empty(remove);
    }
}
