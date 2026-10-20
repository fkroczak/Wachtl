using System;
using System.Diagnostics;
using System.Drawing;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Wachtl.Tray.Core;

namespace Wachtl.Tray
{
    /// <summary>Symbol neben der Uhr mit Menü, Statusabfrage alle 30 s und Netzwerk-Hinweisen (Abfrage alle 10 s, Anzeige im eigenen Hinweisfenster).</summary>
    internal sealed class TrayContext : ApplicationContext
    {
        private readonly TrayClient _client;
        private readonly NotifyIcon _icon;
        private readonly ContextMenuStrip _menu;
        private readonly ToolStripMenuItem _dashboardItem;
        private readonly ToolStripMenuItem _findingsItem;
        private readonly ToolStripLabel[] _liveItems = new ToolStripLabel[LiveTexts.MaxLines];
        private readonly ToolStripSeparator _liveSeparator = new ToolStripSeparator { Visible = false };
        private readonly System.Windows.Forms.Timer _liveTimer;
        private readonly System.Windows.Forms.Timer _pollTimer;
        private readonly System.Windows.Forms.Timer _findingsTimer;
        private readonly System.Windows.Forms.Timer _balloonTimer;
        private readonly FindingNotifier _notifier = new FindingNotifier();
        private readonly System.Windows.Forms.Timer _clickTimer;
        private readonly SynchronizationContext _ui;
        private readonly Icon _trayIcon;
        private TrayStatus? _status;
        private bool _polling;
        private bool _findingsPolling;
        private bool _findingsUnsupported;
        private Balloon? _lastBalloon;
        private NoticeForm? _notice;
        private ReportForm? _reportForm;
        private AboutForm? _aboutForm;

        public TrayContext(TrayClient client, bool openReport)
        {
            _client = client;
            _menu = new ContextMenuStrip();
            _ui = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();

            var reportItem = new ToolStripMenuItem("Problem melden …", null, (s, e) => OpenReport());
            reportItem.Font = new Font(_menu.Font, FontStyle.Bold);
            _findingsItem = new ToolStripMenuItem("Netzwerk-Hinweise …", null, (s, e) => ShowFindings());
            var aboutItem = new ToolStripMenuItem("Über Wachtl", null, (s, e) => OpenAbout());
            _dashboardItem = new ToolStripMenuItem("Dashboard öffnen", null, (s, e) => OpenDashboard()) { Visible = false };
            var exitItem = new ToolStripMenuItem("Beenden", null, (s, e) => ExitThread());
            // Oben im Menü: Ping ins Internet, aktuelle Datenrate, letzter Speedtest – aktualisiert alle 2 s, solange es offen ist
            for (var i = 0; i < _liveItems.Length; i++)
            {
                _liveItems[i] = new ToolStripLabel { Visible = false, Padding = new Padding(22, 1, 8, 1), TextAlign = ContentAlignment.MiddleLeft };
                _menu.Items.Add(_liveItems[i]);
            }

            _menu.Items.Add(_liveSeparator);
            _menu.Items.AddRange(new ToolStripItem[] { reportItem, _findingsItem, aboutItem, _dashboardItem, new ToolStripSeparator(), exitItem });
            _liveTimer = new System.Windows.Forms.Timer { Interval = 2_000 };
            _liveTimer.Tick += (s, e) => RefreshStatus();
            _menu.Opening += (s, e) =>
            {
                UpdateLive();
                RefreshStatus();
                _liveTimer.Start();
            };
            _menu.Closed += (s, e) => _liveTimer.Stop();

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

            // Netzwerk-Hinweise getrennt vom Status: öfter abfragen, damit „Kabel getrennt“ schnell erscheint
            _findingsTimer = new System.Windows.Forms.Timer { Interval = 10_000 };
            _findingsTimer.Tick += (s, e) => RefreshFindings();
            _findingsTimer.Start();
            _balloonTimer = new System.Windows.Forms.Timer { Interval = 2_000 };
            _balloonTimer.Tick += (s, e) => ShowNextBalloon();
            _balloonTimer.Start();
            RefreshFindings();

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
                UpdateLive();
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

        private void UpdateLive()
        {
            var lines = LiveTexts.Lines(_status?.Internet, DateTime.Now);
            for (var i = 0; i < _liveItems.Length; i++)
            {
                var visible = i < lines.Count;
                _liveItems[i].Text = visible ? lines[i] : string.Empty;
                _liveItems[i].Visible = visible;
            }

            _liveSeparator.Visible = lines.Count > 0;
        }

        public async void RefreshFindings()
        {
            if (_findingsPolling || _findingsUnsupported)
            {
                return;
            }

            _findingsPolling = true;
            try
            {
                var since = _notifier.Cursor;
                var poll = await Task.Run(() => _client.GetFindings(since));
                switch (poll.Status)
                {
                    case FindingsPollStatus.Ok:
                        _notifier.Accept(poll.Response!, DateTime.UtcNow);
                        ShowNextBalloon();
                        break;
                    case FindingsPollStatus.NotSupported:
                        // Server-Probe oder ältere Probe: kein Endpunkt – bis zum Neustart des Tray nicht mehr fragen
                        _findingsUnsupported = true;
                        _findingsTimer.Stop();
                        _balloonTimer.Stop();
                        _findingsItem.Visible = false;
                        break;
                }
            }
            catch (Exception)
            {
                // Dienst nicht erreichbar oder Antwort unbrauchbar: still beim nächsten Mal erneut
            }
            finally
            {
                _findingsPolling = false;
            }
        }

        private void ShowNextBalloon()
        {
            if (!_notifier.HasQueued || UserIsPresenting())
            {
                return; // bleibt in der Warteschlange
            }

            var balloon = _notifier.Next(DateTime.UtcNow);
            if (balloon == null)
            {
                return;
            }

            _lastBalloon = balloon;

            // Eigenes Fenster statt _icon.ShowBalloonTip: Windows 11 verschluckt Sprechblasen bei „Nicht stören“ und
            // ausgeschalteten Benachrichtigungen, ohne dass das Programm davon erfährt.
            _notice?.Close();
            var notice = new NoticeForm(balloon, TimeSpan.FromSeconds(15));
            notice.Opened += (s, e) => ShowBalloonDetails();
            notice.FormClosed += (s, e) =>
            {
                if (_notice == notice)
                {
                    _notice = null;
                }
            };
            _notice = notice;
            notice.Show();
        }

        [DllImport("shell32.dll")]
        private static extern int SHQueryUserNotificationState(out int state);

        /// <summary>Spiel im Vollbild oder Präsentation: Hinweis zurückhalten, bis der Benutzer fertig ist.</summary>
        private static bool UserIsPresenting()
        {
            try
            {
                // 3 = QUNS_RUNNING_D3D_FULL_SCREEN, 4 = QUNS_PRESENTATION_MODE
                return SHQueryUserNotificationState(out var state) == 0 && (state == 3 || state == 4);
            }
            catch (Exception)
            {
                return false;
            }
        }

        private void ShowBalloonDetails()
        {
            var balloon = _lastBalloon;
            if (balloon == null)
            {
                return;
            }

            var icon = balloon.Icon == BalloonIcon.Error ? MessageBoxIcon.Error
                : balloon.Icon == BalloonIcon.Warning ? MessageBoxIcon.Warning
                : MessageBoxIcon.Information;
            MessageBox.Show(FindingNotifier.DetailText(balloon.Items), FindingNotifier.Caption, MessageBoxButtons.OK, icon);
        }

        private void ShowFindings()
        {
            var active = _notifier.Active;
            var icon = active.Count == 0 ? MessageBoxIcon.Information
                : active[0].Rank >= 2 ? MessageBoxIcon.Error
                : active[0].Rank >= 1 ? MessageBoxIcon.Warning
                : MessageBoxIcon.Information;
            MessageBox.Show(_notifier.ActiveSummary(), FindingNotifier.Caption, MessageBoxButtons.OK, icon);
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
            _notice?.Close();
            _reportForm?.Close();
            _aboutForm?.Close();
            base.ExitThreadCore();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _pollTimer.Dispose();
                _liveTimer.Dispose();
                _findingsTimer.Dispose();
                _balloonTimer.Dispose();
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
