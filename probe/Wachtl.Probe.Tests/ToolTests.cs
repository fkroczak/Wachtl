using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Wachtl.Probe.Tools;
using Wachtl.Probe.Transport;

namespace Wachtl.Probe.Tests;

public class ToolTests
{
    private static ToolJob Job(string tool, object args) => new()
    {
        Id = 7, Tool = tool, Args = JsonSerializer.SerializeToElement(args, ApiClient.JsonOptions),
    };

    private static async Task<List<ToolUpdate>> Run(ToolJob job)
    {
        var updates = new List<ToolUpdate>();
        await new ToolRunner(u =>
        {
            updates.Add(u);
            return Task.CompletedTask;
        }).RunAsync(job, CancellationToken.None);
        return updates;
    }

    [Fact]
    public void DnsAnswerIsParsed()
    {
        var (id, query) = DnsClient.BuildQuery("kunde.de", 15);
        var msg = new List<byte>(query);
        BinaryPrimitives.WriteUInt16BigEndian(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(msg)[2..], 0x8180);
        msg[7] = 2;   // zwei Antworten
        // MX 10 mail.kunde.de (Name als Zeiger auf die Frage, Ziel teils komprimiert)
        msg.AddRange(new byte[] { 0xC0, 12, 0, 15, 0, 1, 0, 0, 0x0E, 0x10, 0, 9, 0, 10, 4 });
        msg.AddRange(Encoding.ASCII.GetBytes("mail"));
        msg.AddRange(new byte[] { 0xC0, 12 });
        // TXT "v=spf1 -all"
        var txt = Encoding.ASCII.GetBytes("v=spf1 -all");
        msg.AddRange(new byte[] { 0xC0, 12, 0, 16, 0, 1, 0, 0, 0, 60, 0, (byte)(txt.Length + 1), (byte)txt.Length });
        msg.AddRange(txt);

        var answer = DnsClient.Parse(msg.ToArray(), id);

        Assert.Equal("NOERROR", answer.Rcode);
        Assert.Equal(2, answer.Records.Count);
        Assert.Equal(new DnsRecord("answer", "kunde.de.", "MX", 3600, "10 mail.kunde.de."), answer.Records[0]);
        Assert.Equal("\"v=spf1 -all\"", answer.Records[1].Data);
        Assert.Throws<FormatException>(() => DnsClient.Parse(msg.ToArray(), (ushort)(id + 1)));
    }

    [Fact]
    public async Task PortShowsOpenAndClosed()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var open = ((IPEndPoint)listener.LocalEndpoint).Port;
        var closed = new TcpListener(IPAddress.Loopback, 0);
        closed.Start();
        var closedPort = ((IPEndPoint)closed.LocalEndpoint).Port;
        closed.Stop();
        try
        {
            var updates = await Run(Job("port", new { host = "127.0.0.1", ports = new[] { open, closedPort }, timeout = 2 }));
            var last = updates[^1];
            Assert.True(last.Done && last.Ok);
            Assert.Equal("1 von 2 Ports offen", last.Result!.Headline);
            Assert.Equal("offen", last.Result.Table!.Rows[0][2]);
            Assert.Equal("geschlossen", last.Result.Table.Rows[1][2]);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task HttpReadsStatusAndHeaders()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            var stream = client.GetStream();
            var buf = new byte[4096];
            await stream.ReadAsync(buf);
            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 301 Moved Permanently\r\nLocation: https://portal.kunde.de/\r\nServer: FortiGate\r\nContent-Length: 0\r\n\r\n"));
        });
        try
        {
            var updates = await Run(Job("http", new { url = $"http://127.0.0.1:{port}/login", method = "HEAD", insecure = false }));
            await server;
            var last = updates[^1];
            Assert.True(last.Ok, last.Error);
            Assert.Equal("HTTP 301 Dauerhaft verschoben", last.Result!.Headline);
            Assert.Contains(last.Result.Summary, r => r[0] == "Weiterleitung" && r[1] == "https://portal.kunde.de/");
            Assert.Contains(last.Result.Summary, r => r[0] == "Server" && r[1] == "FortiGate");
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task UnknownToolIsReportedAsError()
    {
        var last = (await Run(Job("rdp", new { host = "x" })))[^1];
        Assert.True(last.Done);
        Assert.False(last.Ok);
        Assert.Contains("nicht unterstützt", last.Error);
    }

    [Fact]
    public void UpdateUsesSnakeCaseLikeTheServer()
    {
        var json = JsonSerializer.Serialize(new ToolUpdate
        {
            Done = true, Ok = true,
            Result = new ToolResult { Headline = "x", Stats = new ToolStats { Sent = 1, Received = 1 } }.Add("Ziel", "a", "good"),
        }, ApiClient.JsonOptions);
        Assert.Contains("\"done\":true", json);
        Assert.Contains("\"summary\":[[\"Ziel\",\"a\",\"good\"]]", json);
        Assert.Contains("\"stats\":{\"sent\":1,\"received\":1", json);
        Assert.Equal("1,50", ToolArgs.Ms(1.5));
        Assert.Equal("12,3", ToolArgs.Ms(12.34));
    }
}
