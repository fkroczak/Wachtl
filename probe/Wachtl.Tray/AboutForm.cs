using System;
using System.Drawing;
using System.Globalization;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows.Forms;
using Wachtl.Tray.Core;

namespace Wachtl.Tray
{
    /// <summary>„Über Wachtl“: was Wachtl ist und misst, dazu der aktuelle Zustand aus /tray/v1/status.</summary>
    internal sealed class AboutForm : Form
    {
        private const int TextWidth = 440;

        internal const string Description =
            "Wachtl ist das Netzwerk-Monitoring Ihrer IT. Es misst im Hintergrund Latenz, Paketverlust, Jitter, " +
            "den Weg ins Internet und die Bandbreite und meldet die Werte an den Wachtl-Server der IT.\n\n" +
            "Über „Problem melden“ können Sie Störungen melden. Sie werden in den Messgraphen markiert, " +
            "damit die IT sieht, was zu diesem Zeitpunkt im Netzwerk los war.\n\n" +
            "Es werden keine Inhalte, Webseiten oder Dateien erfasst.";

        private readonly TrayClient _client;
        private readonly TableLayoutPanel _grid;
        private readonly Bitmap _logo;

        public AboutForm(TrayClient client, TrayStatus? lastStatus)
        {
            _client = client;
            SuspendLayout();
            Ui.SetupDialog(this, "Über Wachtl");

            _logo = AppIcons.LoadBitmap(64);
            var logo = new PictureBox
            {
                Image = _logo,
                SizeMode = PictureBoxSizeMode.Zoom,
                Size = new Size(56, 56),
                Margin = new Padding(0, 0, 12, 0),
                AccessibleName = "Wachtl-Logo",
            };
            var title = new Label
            {
                Text = "Wachtl",
                AutoSize = true,
                Font = new Font(SystemFonts.MessageBoxFont.FontFamily, SystemFonts.MessageBoxFont.SizeInPoints * 1.8f, FontStyle.Bold),
                Margin = new Padding(0, 2, 0, 0),
            };
            var subtitle = Ui.Text("Netzwerk-Monitoring");
            var titleColumn = Ui.Column();
            titleColumn.Dock = DockStyle.None;
            titleColumn.Controls.AddRange(new Control[] { title, subtitle });
            var header = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 6) };
            header.Controls.AddRange(new Control[] { logo, titleColumn });

            var description = Ui.Text(Description, TextWidth);

            _grid = new TableLayoutPanel
            {
                ColumnCount = 2,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Margin = new Padding(0, 6, 0, 0),
            };
            _grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            _grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            var close = Ui.Button("Schließen");
            close.Click += (s, e) => Close();
            AcceptButton = close;
            CancelButton = close;

            var layout = Ui.Column();
            layout.Controls.AddRange(new Control[]
            {
                header, description, Ui.Heading("Dieser PC"), _grid, Ui.ButtonRow(close),
            });
            Controls.Add(layout);

            ShowStatus(lastStatus, lastStatus == null);
            ResumeLayout(false);
            PerformLayout();
        }

        protected override async void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Activate();
            TrayStatus? status = null;
            try
            {
                status = await Task.Run(() => _client.GetStatus());
            }
            catch (Exception)
            {
            }

            if (!IsDisposed)
            {
                ShowStatus(status, false);
            }
        }

        internal static string TrayVersion
        {
            get
            {
                var info = typeof(AboutForm).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
                return info != null ? info.Split('+')[0] : typeof(AboutForm).Assembly.GetName().Version?.ToString(3) ?? "?";
            }
        }

        private void ShowStatus(TrayStatus? status, bool loading)
        {
            _grid.SuspendLayout();
            _grid.Controls.Clear();
            _grid.RowStyles.Clear();
            _grid.RowCount = 0;
            if (loading)
            {
                AddRow("Zustand", TrayTexts.Connection(TrayConnection.Unknown));
            }
            else if (status == null)
            {
                AddRow("Zustand", TrayTexts.Connection(TrayConnection.ServiceDown));
            }
            else
            {
                AddRow("Rolle", status.IsServer ? "Wachtl-Server" : "Client (Messpunkt)");
                AddRow("Name", Or(status.Name));
                AddRow("Standort", Or(status.Site));
                AddRow("Server", Or(status.ServerUrl));
                AddRow("Verbindung", TrayTexts.Connection(status.Connection));
                AddRow("Letzter Kontakt", status.LastContact > 0
                    ? ReportBuilder.FromUnixSecondsLocal(status.LastContact).ToString("dd.MM.yyyy HH:mm:ss", CultureInfo.InvariantCulture)
                    : "noch nie");
                AddRow("Offene Meldungen", status.PendingReports == 0
                    ? "keine"
                    : status.PendingReports.ToString(CultureInfo.InvariantCulture) + " (werden nachgeliefert)");
                AddRow("Version Dienst", Or(status.Version));
            }

            AddRow("Version Symbol", TrayVersion);
            _grid.ResumeLayout(true);
        }

        private static string Or(string value) => string.IsNullOrEmpty(value) ? "–" : value;

        private void AddRow(string name, string value)
        {
            var row = _grid.RowCount++;
            _grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            var label = Ui.Text(name + ":");
            label.ForeColor = SystemColors.GrayText;
            label.Margin = new Padding(0, 2, 12, 2);
            var text = Ui.Text(value, TextWidth - 140);
            text.Margin = new Padding(0, 2, 0, 2);
            text.AccessibleName = name;
            _grid.Controls.Add(label, 0, row);
            _grid.Controls.Add(text, 1, row);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _logo.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
