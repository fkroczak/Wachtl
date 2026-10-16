using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Wachtl.Probe;
using Wachtl.Probe.Checks;
using Wachtl.Probe.Config;
using Wachtl.Probe.Logging;

if (Cli.IsCommand(args))
{
    return await Cli.RunAsync(args);
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = AppInfo.ServiceName);
builder.Services.Configure<HostOptions>(options => options.ShutdownTimeout = TimeSpan.FromSeconds(15));

builder.Logging.ClearProviders();
builder.Logging.SetMinimumLevel(LogLevel.Information);
builder.Logging.AddFilter("Microsoft", LogLevel.Warning);
builder.Logging.AddFilter("System.Net.Http", LogLevel.Warning);
builder.Logging.AddProvider(new FileLoggerProvider(StateStore.LogDir, LogLevel.Information));
if (!WindowsServiceHelpers.IsWindowsService())
{
    builder.Logging.AddSimpleConsole(o => o.TimestampFormat = "HH:mm:ss ");
}

builder.Services.AddSingleton<GatewayResolver>();
builder.Services.AddHostedService<ProbeWorker>();

await builder.Build().RunAsync();
return 0;
