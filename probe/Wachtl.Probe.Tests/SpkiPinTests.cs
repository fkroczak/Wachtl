using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Tests;

public class SpkiPinTests
{
    private static (X509Certificate2 Cert, ECDsa Key) CreateCert()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=wachtl.test", key, HashAlgorithmName.SHA256);
        var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return (cert, key);
    }

    [Fact]
    public void PinIsSha256OfSubjectPublicKeyInfo()
    {
        var (cert, key) = CreateCert();
        var expected = Convert.ToBase64String(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
        Assert.Equal(expected, SpkiPin.Compute(cert));
        Assert.True(SpkiPin.Matches(cert, expected));
    }

    [Fact]
    public void RejectsOtherKeyAndGarbage()
    {
        var (cert, _) = CreateCert();
        var (other, _) = CreateCert();
        Assert.False(SpkiPin.Matches(cert, SpkiPin.Compute(other)));
        Assert.False(SpkiPin.Matches(cert, "kein base64!"));
        Assert.False(SpkiPin.Matches(cert, Convert.ToBase64String(new byte[5])));
    }
}
