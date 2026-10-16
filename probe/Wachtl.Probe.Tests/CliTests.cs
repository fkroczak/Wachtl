using System.Text;

namespace Wachtl.Probe.Tests;

public class CliTests
{
    [Theory]
    [InlineData("wachtl.kunde.local", "https://wachtl.kunde.local/")]
    [InlineData("https://wachtl.kunde.local:8443/login", "https://wachtl.kunde.local:8443/")]
    [InlineData(" https://10.0.0.5 ", "https://10.0.0.5/")]
    public void ParseServerNormalizes(string input, string expected) =>
        Assert.Equal(expected, Cli.ParseServer(input).ToString());

    [Fact]
    public void ParseServerRejectsHttp() =>
        Assert.Throws<ArgumentException>(() => Cli.ParseServer("http://wachtl.kunde.local"));

    [Fact]
    public void ParseOptionsRequiresValues()
    {
        Assert.Equal("x", Cli.ParseOptions(new[] { "--server", "x" })["server"]);
        Assert.Throws<ArgumentException>(() => Cli.ParseOptions(new[] { "--server" }));
    }

    [Fact]
    public void ResultFileIsUtf16IniWithEscapedNewlines()
    {
        var path = Path.GetTempFileName();
        try
        {
            var result = new CliResult(path);
            result.Set("error", "Zeile 1\nZeile ä");
            result.Write(3);
            var bytes = File.ReadAllBytes(path);
            Assert.Equal(new byte[] { 0xFF, 0xFE }, bytes[..2]);
            var text = File.ReadAllText(path, Encoding.Unicode);
            Assert.Contains("[result]\r\nok=0\r\ncode=3\r\n", text);
            Assert.Contains("error=Zeile 1\\nZeile ä", text);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
