using Microsoft.Extensions.Logging.Abstractions;
using Wachtl.Probe.Buffer;

namespace Wachtl.Probe.Tests;

public sealed class SampleBufferTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "wachtl-test-" + Guid.NewGuid().ToString("N"));

    private SampleBuffer Create() => new(Path.Combine(_dir, "buffer.db"), NullLogger.Instance);

    [Fact]
    public void KeepsOrderAndDeletesDeliveredRange()
    {
        var buffer = Create();
        for (var i = 0; i < 10; i++)
        {
            buffer.Add($"line {i}");
        }

        Assert.Equal(10, buffer.FlushPending());
        var first = buffer.Peek(4);
        Assert.Equal(new[] { "line 0", "line 1", "line 2", "line 3" }, first.Select(x => x.Line));

        buffer.DeleteThrough(first[0].Id, first[^1].Id);
        Assert.Equal(6, buffer.Count());
        Assert.Equal("line 4", buffer.Peek(1)[0].Line);
    }

    [Fact]
    public void SurvivesReopen()
    {
        var buffer = Create();
        buffer.Add("bleibt");
        buffer.FlushPending();

        var reopened = Create();
        Assert.Equal("bleibt", Assert.Single(reopened.Peek(10)).Line);
    }

    [Fact]
    public void PruneDropsOldestBeyondLimit()
    {
        var buffer = Create();
        for (var i = 0; i < 10; i++)
        {
            buffer.Add($"line {i}");
        }

        buffer.FlushPending();
        Assert.Equal(6, buffer.Prune(TimeSpan.FromDays(7), maxRows: 4));
        Assert.Equal("line 6", buffer.Peek(1)[0].Line);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
