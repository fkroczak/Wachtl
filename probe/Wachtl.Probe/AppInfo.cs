using System.Reflection;

namespace Wachtl.Probe;

public static class AppInfo
{
    public const string ServiceName = "Wachtl";

    public static string Version { get; } =
        typeof(AppInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            .Split('+')[0]
        ?? "0.0.0";

    public static string OsDescription => System.Runtime.InteropServices.RuntimeInformation.OSDescription;
}
