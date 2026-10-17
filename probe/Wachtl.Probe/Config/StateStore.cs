using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Config;

/// <summary>
/// Dateien unter C:\ProgramData\Wachtl (oder WACHTL_DATA_DIR). Das Probe-Token
/// wird per DPAPI an den Rechner gebunden verschlüsselt.
/// </summary>
public static class StateStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Wachtl.Probe.v1");

    public static string DataDir { get; } =
        Environment.GetEnvironmentVariable("WACHTL_DATA_DIR") is { Length: > 0 } dir
            ? dir
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Wachtl");

    public static string StatePath => Path.Combine(DataDir, "state.json");
    public static string ConfigCachePath => Path.Combine(DataDir, "config.json");
    public static string PendingPath => Path.Combine(DataDir, "enroll-pending.json");
    public static string BufferPath => Path.Combine(DataDir, "buffer.db");
    public static string LogDir => Path.Combine(DataDir, "logs");

    public static ProbeState? Load() => Read<ProbeState>(StatePath);

    public static void Save(ProbeState state) => Write(StatePath, state);

    public static PendingEnrollment? LoadPending() => Read<PendingEnrollment>(PendingPath);

    public static void SavePending(PendingEnrollment pending) => Write(PendingPath, pending);

    public static void DeletePending()
    {
        foreach (var path in new[] { PendingPath, PendingPath + ".tmp" })
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    public static ProbeConfig? LoadCachedConfig() => Read<ProbeConfig>(ConfigCachePath);

    public static void SaveCachedConfig(ProbeConfig config) => Write(ConfigCachePath, config);

    public static string ProtectToken(string token) =>
        Convert.ToBase64String(ProtectedData.Protect(
            Encoding.UTF8.GetBytes(token), Entropy, DataProtectionScope.LocalMachine));

    public static string UnprotectToken(string protectedToken) =>
        Encoding.UTF8.GetString(ProtectedData.Unprotect(
            Convert.FromBase64String(protectedToken), Entropy, DataProtectionScope.LocalMachine));

    private static T? Read<T>(string path)
        where T : class
    {
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<T>(File.ReadAllText(path), ApiClient.JsonOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static void Write<T>(string path, T value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(value, ApiClient.JsonOptionsIndented));
        File.Move(tmp, path, overwrite: true);
    }
}
