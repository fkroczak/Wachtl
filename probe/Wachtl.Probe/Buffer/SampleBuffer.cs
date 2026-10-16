using System.Threading.Channels;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Wachtl.Probe.Checks;

namespace Wachtl.Probe.Buffer;

/// <summary>
/// Lokale Warteschlange für Messwerte. Neue Werte landen zuerst in einem
/// Speicher-Channel und werden einmal pro Sekunde gesammelt in SQLite geschrieben.
/// So überstehen Messwerte Netzwerk- und Serverausfälle sowie Neustarts.
/// </summary>
public sealed class SampleBuffer : ISampleSink
{
    private readonly string _connectionString;
    private readonly ILogger _logger;
    private readonly Channel<string> _pending = Channel.CreateBounded<string>(
        new BoundedChannelOptions(200_000) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });

    public SampleBuffer(string path, ILogger logger)
    {
        _logger = logger;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = true,
            DefaultTimeout = 30,
        }.ToString();

        using var conn = Open();
        Execute(conn, "PRAGMA journal_mode=WAL;");
        Execute(conn, "PRAGMA synchronous=NORMAL;");
        Execute(conn,
            "CREATE TABLE IF NOT EXISTS samples (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, created_ms INTEGER NOT NULL, line TEXT NOT NULL);");
        Execute(conn, "CREATE INDEX IF NOT EXISTS samples_created ON samples(created_ms);");
    }

    public void Add(string line) => _pending.Writer.TryWrite(line);

    /// <summary>Schreibt gesammelte Werte jede Sekunde in die Datenbank.</summary>
    public async Task RunWriterAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
                FlushPendingSafe();
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            FlushPendingSafe();
        }
    }

    private void FlushPendingSafe()
    {
        try
        {
            FlushPending();
        }
        catch (SqliteException ex)
        {
            _logger.LogError(ex, "Messwerte konnten nicht in den lokalen Puffer geschrieben werden");
        }
    }

    internal int FlushPending()
    {
        var lines = new List<string>();
        while (lines.Count < 50_000 && _pending.Reader.TryRead(out var line))
        {
            lines.Add(line);
        }

        if (lines.Count == 0)
        {
            return 0;
        }

        using var conn = Open();
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "INSERT INTO samples (created_ms, line) VALUES ($ts, $line)";
        var pTs = cmd.Parameters.Add("$ts", SqliteType.Integer);
        var pLine = cmd.Parameters.Add("$line", SqliteType.Text);
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        foreach (var l in lines)
        {
            pTs.Value = now;
            pLine.Value = l;
            cmd.ExecuteNonQuery();
        }

        tx.Commit();
        return lines.Count;
    }

    public IReadOnlyList<(long Id, string Line)> Peek(int max)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id, line FROM samples ORDER BY id LIMIT $max";
        cmd.Parameters.AddWithValue("$max", max);
        using var reader = cmd.ExecuteReader();
        var result = new List<(long, string)>();
        while (reader.Read())
        {
            result.Add((reader.GetInt64(0), reader.GetString(1)));
        }

        return result;
    }

    public int DeleteThrough(long firstId, long lastId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM samples WHERE id BETWEEN $a AND $b";
        cmd.Parameters.AddWithValue("$a", firstId);
        cmd.Parameters.AddWithValue("$b", lastId);
        return cmd.ExecuteNonQuery();
    }

    public long Count()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM samples";
        return (long)(cmd.ExecuteScalar() ?? 0L);
    }

    /// <summary>Verwirft zu alte Werte und begrenzt die Größe (älteste zuerst).</summary>
    public long Prune(TimeSpan maxAge, long maxRows)
    {
        using var conn = Open();
        long removed;
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "DELETE FROM samples WHERE created_ms < $cutoff";
            cmd.Parameters.AddWithValue("$cutoff", DateTimeOffset.UtcNow.Add(-maxAge).ToUnixTimeMilliseconds());
            removed = cmd.ExecuteNonQuery();
        }

        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText =
                "DELETE FROM samples WHERE id IN (SELECT id FROM samples ORDER BY id " +
                "LIMIT MAX(0, (SELECT COUNT(*) FROM samples) - $max))";
            cmd.Parameters.AddWithValue("$max", maxRows);
            removed += cmd.ExecuteNonQuery();
        }

        if (removed > 0)
        {
            _logger.LogWarning("Puffer bereinigt: {Count} alte Messwerte verworfen", removed);
        }

        return removed;
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }

    private static void Execute(SqliteConnection conn, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }
}
