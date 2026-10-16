using System.Text;
using Microsoft.Extensions.Logging;

namespace Wachtl.Probe.Logging;

/// <summary>Schreibt Logs täglich rotierend nach logs\probe-JJJJMMTT.log und behält 14 Tage.</summary>
public sealed class FileLoggerProvider : ILoggerProvider
{
    private const int KeepDays = 14;
    private readonly string _directory;
    private readonly LogLevel _minLevel;
    private readonly object _lock = new();
    private StreamWriter? _writer;
    private DateOnly _currentDay;

    public FileLoggerProvider(string directory, LogLevel minLevel)
    {
        _directory = directory;
        _minLevel = minLevel;
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, ShortName(categoryName));

    internal bool IsEnabled(LogLevel level) => level >= _minLevel && level != LogLevel.None;

    internal void Write(LogLevel level, string category, string message, Exception? exception)
    {
        var now = DateTime.Now;
        var sb = new StringBuilder()
            .Append(now.ToString("yyyy-MM-dd HH:mm:ss.fff"))
            .Append(" [").Append(LevelName(level)).Append("] ")
            .Append(category).Append(": ").Append(message);
        if (exception is not null)
        {
            sb.AppendLine().Append(exception);
        }

        lock (_lock)
        {
            try
            {
                EnsureWriter(DateOnly.FromDateTime(now));
                _writer!.WriteLine(sb.ToString());
                _writer.Flush();
            }
            catch (IOException)
            {
                // Logging darf den Dienst nie zum Absturz bringen.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private void EnsureWriter(DateOnly day)
    {
        if (_writer is not null && day == _currentDay)
        {
            return;
        }

        _writer?.Dispose();
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, $"probe-{day:yyyyMMdd}.log");
        _writer = new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite),
            new UTF8Encoding(false));
        _currentDay = day;
        DeleteOldFiles();
    }

    private void DeleteOldFiles()
    {
        var cutoff = DateTime.Now.AddDays(-KeepDays);
        foreach (var file in Directory.EnumerateFiles(_directory, "probe-*.log"))
        {
            if (File.GetLastWriteTime(file) < cutoff)
            {
                File.Delete(file);
            }
        }
    }

    private static string ShortName(string category)
    {
        var i = category.LastIndexOf('.');
        return i >= 0 ? category[(i + 1)..] : category;
    }

    private static string LevelName(LogLevel level) => level switch
    {
        LogLevel.Trace => "TRC",
        LogLevel.Debug => "DBG",
        LogLevel.Information => "INF",
        LogLevel.Warning => "WRN",
        LogLevel.Error => "ERR",
        LogLevel.Critical => "CRT",
        _ => "???",
    };

    public void Dispose()
    {
        lock (_lock)
        {
            _writer?.Dispose();
            _writer = null;
        }
    }

    private sealed class FileLogger : ILogger
    {
        private readonly FileLoggerProvider _provider;
        private readonly string _category;

        public FileLogger(FileLoggerProvider provider, string category)
        {
            _provider = provider;
            _category = category;
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => _provider.IsEnabled(logLevel);

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
            {
                _provider.Write(logLevel, _category, formatter(state, exception), exception);
            }
        }
    }
}
