using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Wachtl.Probe.Transport;

/// <summary>
/// SHA-256 über den SubjectPublicKeyInfo des Server-Zertifikats, Base64-kodiert.
/// Entspricht: openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
/// </summary>
public static class SpkiPin
{
    public static string Compute(X509Certificate2 certificate) =>
        Convert.ToBase64String(SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo()));

    public static bool Matches(X509Certificate2 certificate, string expectedBase64)
    {
        byte[] expected;
        try
        {
            expected = Convert.FromBase64String(expectedBase64.Trim());
        }
        catch (FormatException)
        {
            return false;
        }

        var actual = SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo());
        return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
