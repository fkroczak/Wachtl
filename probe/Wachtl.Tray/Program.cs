using System;
using System.Threading;
using System.Windows.Forms;
using Wachtl.Tray.Core;

namespace Wachtl.Tray
{
    internal static class Program
    {
        /// <summary>Eine Instanz je Benutzersitzung.</summary>
        private const string MutexName = @"Local\WachtlTray";

        /// <summary>Ein zweiter Start mit --report bittet die laufende Instanz, das Meldefenster zu öffnen.</summary>
        private const string ReportSignalName = @"Local\WachtlTrayReport";

        [STAThread]
        private static int Main(string[] args)
        {
            var openReport = false;
            foreach (var arg in args)
            {
                if (string.Equals(arg, "--report", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(arg, "/report", StringComparison.OrdinalIgnoreCase))
                {
                    openReport = true;
                }
            }

            using (var mutex = new Mutex(true, MutexName, out var created))
            {
                if (!created)
                {
                    if (openReport)
                    {
                        SignalRunningInstance();
                    }

                    return 0;
                }

                using (var reportSignal = new EventWaitHandle(false, EventResetMode.AutoReset, ReportSignalName))
                {
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
                    Application.ThreadException += (s, e) => { /* das Symbol soll nie mit einer Fehlermeldung abstürzen */ };

                    using (var context = new TrayContext(TrayClient.FromEnvironment(), reportSignal, openReport))
                    {
                        Application.Run(context);
                    }
                }

                GC.KeepAlive(mutex);
            }

            return 0;
        }

        private static void SignalRunningInstance()
        {
            try
            {
                using (var signal = EventWaitHandle.OpenExisting(ReportSignalName))
                {
                    signal.Set();
                }
            }
            catch (Exception)
            {
                // Laufende Instanz startet gerade oder beendet sich – still beenden.
            }
        }
    }
}
