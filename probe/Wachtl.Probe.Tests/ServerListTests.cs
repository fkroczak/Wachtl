using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Wachtl.Probe.Config;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Tests;

public class ServerListTests
{
    [Fact]
    public void ParsesListWithNamesAndIps()
    {
        var list = Enrollment.ParseServers("https://wachtl.kunde.local:8443, 10.0.0.5:8443;https://wachtl.kunde.local:8443/login");
        Assert.Equal(new[] { "https://wachtl.kunde.local:8443/", "https://10.0.0.5:8443/" }, list.Select(u => u.ToString()));
        Assert.Throws<ArgumentException>(() => Enrollment.ParseServers("http://10.0.0.5"));
        Assert.Throws<ArgumentException>(() => Enrollment.ParseServers(" , "));
    }

    [Fact]
    public void StatePrefersLastWorkingAddress()
    {
        var state = new ProbeState
        {
            ServerUrl = "https://10.0.0.5:8443/",
            ServerUrls = new() { "https://wachtl:8443/", "https://10.0.0.5:8443/", "kaputt", "http://alt/" },
        };
        Assert.Equal(new[] { "https://10.0.0.5:8443/", "https://wachtl:8443/" }, state.AllServers().Select(u => u.ToString()));
    }

    [Fact]
    public void OldStateWithoutListStillWorks()
    {
        var state = JsonSerializer.Deserialize<ProbeState>("""{"server_url": "https://wachtl.local/", "probe_id": 3}""", ApiClient.JsonOptions)!;
        Assert.Equal(new[] { "https://wachtl.local/" }, state.AllServers().Select(u => u.ToString()));
    }

    [Fact]
    public void ConfigCarriesServerUrls()
    {
        var config = JsonSerializer.Deserialize<ProbeConfig>(
            """{"probe_id": 1, "etag": "e", "checks": [], "server_urls": ["https://a:8443", "https://10.0.0.5:8443"]}""",
            ApiClient.JsonOptions)!;
        Assert.Equal(2, config.ServerUrls.Count);
    }

    [Fact]
    public void ClientKeepsWorkingAddressFirstOnUpdate()
    {
        using var api = new ApiClient(new[] { new Uri("https://b:8443/x"), new Uri("https://a:8443") }, "PIN", null);
        Assert.Equal("https://b:8443/", api.CurrentServer.ToString());
        api.UpdateServers(new[] { new Uri("https://c"), new Uri("https://b:8443") });
        Assert.Equal(new[] { "https://b:8443/", "https://c/" }, api.Servers.Select(u => u.ToString()));
    }

    [Fact]
    public async Task FailsOverToNextAddress()
    {
        // erste Adresse: Name nicht auflösbar; zweite: lokaler Port ohne Dienst → beide schlagen fehl,
        // die Ausnahme kommt erst nach dem zweiten Versuch (kein Abbruch nach dem ersten Fehler)
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        using var api = new ApiClient(new[] { new Uri("https://wachtl-gibt-es-nicht.invalid"), new Uri($"https://127.0.0.1:{port}") }, "PIN", null, "1.x");
        await Assert.ThrowsAsync<HttpRequestException>(() => api.HeartbeatAsync(new HeartbeatRequest(), CancellationToken.None));
    }
}

public class DeferredEnrollmentTests
{
    [Fact]
    public async Task UnreachableServerIsDeferredNotFailed()
    {
        // Port 1 auf 127.0.0.1: Verbindung wird sofort abgelehnt → Registrierung für den Dienst vormerken
        var outFile = Path.GetTempFileName();
        try
        {
            var code = await Cli.RunAsync(new[] { "enroll", "--server", "https://127.0.0.1:1", "--pin", "PIN=", "--token", "wachtl-test",
                                                  "--hostname", "PC-01", "--defer-offline", "1", "--out", outFile });
            Assert.Equal(Cli.ExitDeferred, code);
            var pending = StateStore.LoadPending();
            Assert.NotNull(pending);
            Assert.Equal("PC-01", pending!.Hostname);
            Assert.Equal("wachtl-test", StateStore.UnprotectToken(pending.ProtectedEnrollmentToken));
            Assert.Contains("deferred=1", File.ReadAllText(outFile, System.Text.Encoding.Unicode));

            // ohne --defer-offline bleibt es ein Fehler
            Assert.Equal(Cli.ExitUnreachable, await Cli.RunAsync(new[] { "enroll", "--server", "https://127.0.0.1:1", "--pin", "PIN=",
                                                                          "--token", "t" }));
        }
        finally
        {
            StateStore.DeletePending();
            File.Delete(outFile);
        }
    }
}
