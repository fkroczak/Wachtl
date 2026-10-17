using System;
using System.Diagnostics;
using System.Drawing;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Wachtl.Tray.Core;

namespace Wachtl.Tray
{
    /// <summary>Symbol neben der Uhr mit Menü und Statusabfrage alle 30 s.</summary>
    internal sealed class TrayContext : ApplicationContext
    {
        private readonly TrayClient _client;
        private readonly NotifyIcon _icon;
        private readonly ContextMenuStrip _menu;
        private readonly ToolStripMenuItem _dashboardItem;
        private readonly System.Windows.Forms.Timer _pollTimer;
        private readonly System.Windows.Forms.Timer _clickTimer;
        private readonly SynchronizationContext _ui;
        private readonly RegisteredWaitHandle _signalWait;
        private readonly Icon _trayIcon;
        private TrayStatus? _status;
        private bool _polling;
        private ReportForm? _reportForm;
        private AboutForm? _aboutForm;

        public TrayContext(TrayClient client, WaitHandle reportSignal, bool openReport)
        {
            _client = client;
            _menu = new ContextMenuStrip();
            _ui = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();

            var reportItem = new ToolStripMenuItem("Problem melden …", null, (s, e) => OpenReport());
            reportItem.Font = new Font(_menu.Font, FontStyle.Bold);
            var aboutItem = new ToolStripMenuItem("Über Wachtl", null, (s, e) => OpenAbout());
            _dashboardItem = new ToolStripMenuItem("Dashboard öffnen", null, (s, e) => OpenDashboard()) { Visible = false };
            var exitItem = new ToolStripMenuItem("Beenden", null, (s, e) => ExitThread());
            _menu.Items.AddRange(new ToolStripItem[] { reportItem, aboutItem, _dashboardItem, new ToolStripSeparator(), exitItem });

            _trayIcon = AppIcons.Load(SystemInformation.SmallIconSize);
            _icon = new NotifyIcon
            {
                Icon = _trayIcon,
                Text = TrayTexts.Tooltip(TrayConnection.Unknown),
                ContextMenuStrip = _menu,
                Visible = true,
            };

            // Einfacher Linksklick öffnet das Menü – verzögert, damit ein Doppelklick („Problem melden“) es nicht aufblitzen lässt.
            _clickTimer = new System.Windows.Forms.Timer { Interval = Math.Max(100, SystemInformation.DoubleClickTime) };
            _clickTimer.Tick += (s, e) =>
            {
                _clickTimer.Stop();
                ShowMenu();
            };
            _icon.MouseClick += (s, e) =>
            {
                if (e.Button == MouseButtons.Left)
                {
                    _clickTimer.Start();
                }
            };
            _icon.MouseDoubleClick += (s, e) =>
            {
                if (e.Button == MouseButtons.Left)
                {
                    _clickTimer.Stop();
                    OpenReport();
                }
            };

            _pollTimer = new System.Windows.Forms.Timer { Interval = 30_000 };
            _pollTimer.Tick += (s, e) => RefreshStatus();
            _pollTimer.Start();
            RefreshStatus();

            _signalWait = ThreadPool.RegisterWaitForSingleObject(reportSignal,
                (state, timedOut) => _ui.Post(_ => OpenReport(), null), null, Timeout.Infinite, false);

            if (openReport)
            {
                _ui.Post(_ => OpenReport(), null);
            }
        }

        private void ShowMenu()
        {
            // NotifyIcon zeigt das Kontextmenü nur bei Rechtsklick; die interne Methode setzt es korrekt (Fokus, Position) ins Bild.
            var method = typeof(NotifyIcon).GetMethod("ShowContextMenu", BindingFlags.Instance | BindingFlags.NonPublic);
            if (method != null)
            {
                method.Invoke(_icon, null);
            }
            else
            {
                _menu.Show(Cursor.Position);
            }
        }

        public async void RefreshStatus()
        {
            if (_polling)
            {
                return;
            }

            _polling = true;
            try
            {
                var status = await Task.Run(() => _client.GetStatus());
                _status = status;
                var state = status?.Connection ?? TrayConnection.ServiceDown;
                _icon.Text = TrayTexts.Tooltip(state);
                _dashboardItem.Visible = status != null && status.IsServer && !string.IsNullOrEmpty(status.DashboardUrl);
            }
            catch (Exception)
            {
                _icon.Text = TrayTexts.Tooltip(TrayConnection.ServiceDown);
            }
            finally
            {
                _polling = false;
            }
        }

        private void OpenReport()
        {
            if (_reportForm != null && !_reportForm.IsDisposed)
            {
                BringToFront(_reportForm);
                return;
            }

            _reportForm = new ReportForm(_client);
            _reportForm.FormClosed += (s, e) =>
            {
                _reportForm = null;
                RefreshStatus();
            };
            _reportForm.Show();
            BringToFront(_reportForm);
        }

        private void OpenAbout()
        {
            if (_aboutForm != null && !_aboutForm.IsDisposed)
            {
                BringToFront(_aboutForm);
                return;
            }

            _aboutForm = new AboutForm(_client, _status);
            _aboutForm.FormClosed += (s, e) => _aboutForm = null;
            _aboutForm.Show();
            BringToFront(_aboutForm);
        }

        private static void BringToFront(Form form)
        {
            if (form.WindowState == FormWindowState.Minimized)
            {
                form.WindowState = FormWindowState.Normal;
            }

            form.Activate();
            form.BringToFront();
        }

        private void OpenDashboard()
        {
            var url = _status?.DashboardUrl;
            if (string.IsNullOrEmpty(url)
                || !(url!.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            try
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show("Das Dashboard konnte nicht geöffnet werden:\n" + ex.Message, TrayTexts.Title,
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        protected override void ExitThreadCore()
        {
            _icon.Visible = false;
            _reportForm?.Close();
            _aboutForm?.Close();
            base.ExitThreadCore();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _signalWait.Unregister(null);
                _pollTimer.Dispose();
                _clickTimer.Dispose();
                _icon.Visible = false;
                _icon.Dispose();
                _menu.Dispose();
                _trayIcon.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
