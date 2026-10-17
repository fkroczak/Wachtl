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
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                if (!created)
                {
                    // Symbol läuft schon: ein zweiter Start (Startmenü „Problem melden“) zeigt nur das Meldefenster.
                    if (openReport)
                    {
                        Application.Run(new ReportForm(TrayClient.FromEnvironment()));
                    }

                    return 0;
                }

                Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
                Application.ThreadException += (s, e) => { /* das Symbol soll nie mit einer Fehlermeldung abstürzen */ };

                using (var context = new TrayContext(TrayClient.FromEnvironment(), openReport))
                {
                    Application.Run(context);
                }

                GC.KeepAlive(mutex);
            }

            return 0;
        }
    }
}
