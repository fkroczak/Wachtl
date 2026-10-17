using System;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;
using Wachtl.Tray.Core;

namespace Wachtl.Tray
{
    /// <summary>„Problem melden“: Zeitpunkt, Art, Dauer, Beschreibung – Prüfung und JSON in <see cref="ReportBuilder"/>.</summary>
    internal sealed class ReportForm : Form
    {
        private const int FieldWidth = 360;

        private readonly TrayClient _client;
        private readonly string _user;
        private readonly RadioButton _now;
        private readonly RadioButton _at;
        private readonly DateTimePicker _time;
        private readonly ComboBox _category;
        private readonly ComboBox _duration;
        private readonly TextBox _description;
        private readonly Label _state;
        private readonly Button _send;
        private readonly Button _cancel;

        public ReportForm(TrayClient client)
        {
            _client = client;
            _user = ReportBuilder.FormatUser(Environment.UserDomainName, Environment.UserName);

            SuspendLayout();
            Ui.SetupDialog(this, "Wachtl – Problem melden");
            TopMost = true;

            var whenLabel = Ui.Heading("Wann trat das Problem auf?");
            whenLabel.Margin = new Padding(0, 0, 0, 3);
            _now = new RadioButton { Text = "&Jetzt", AutoSize = true, Checked = true, Margin = new Padding(0, 4, 16, 3) };
            _at = new RadioButton { Text = "&Um:", AutoSize = true, Margin = new Padding(0, 4, 4, 3) };
            var now = DateTime.Now;
            _time = new DateTimePicker
            {
                Format = DateTimePickerFormat.Custom,
                CustomFormat = "dd.MM.yyyy HH:mm",
                Width = 150,
                MinDate = now.AddDays(-7),
                MaxDate = now,
                Enabled = false,
                AccessibleName = "Uhrzeit des Problems",
                Margin = new Padding(0, 1, 0, 3),
            };
            _time.Value = new DateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, 0, DateTimeKind.Local);
            _now.AccessibleName = "Problem besteht jetzt";
            _at.AccessibleName = "Problem trat um eine bestimmte Uhrzeit auf";
            _now.CheckedChanged += (s, e) => _time.Enabled = _at.Checked;
            _at.CheckedChanged += (s, e) => _time.Enabled = _at.Checked;
            var whenRow = new FlowLayoutPanel
            {
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                WrapContents = false,
                Margin = Padding.Empty,
            };
            whenRow.Controls.AddRange(new Control[] { _now, _at, _time });

            var categoryLabel = Ui.Heading("Was ist &passiert?");
            _category = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Width = FieldWidth,
                AccessibleName = "Was ist passiert? (Pflichtfeld)",
                Margin = new Padding(0, 0, 0, 3),
            };
            foreach (var c in ReportCatalog.Categories)
            {
                _category.Items.Add(c);
            }

            var durationLabel = Ui.Heading("Wie &lange?");
            _duration = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Width = FieldWidth,
                AccessibleName = "Wie lange?",
                Margin = new Padding(0, 0, 0, 3),
            };
            foreach (var d in ReportCatalog.Durations)
            {
                _duration.Items.Add(d);
            }

            _duration.SelectedItem = ReportCatalog.Find(ReportCatalog.Durations, ReportCatalog.DefaultDuration);

            var descriptionLabel = Ui.Heading("&Beschreibung (optional)");
            _description = new TextBox
            {
                Multiline = true,
                AcceptsReturn = true,
                ScrollBars = ScrollBars.Vertical,
                MaxLength = ReportBuilder.MaxDescription,
                Size = new Size(FieldWidth, 90),
                AccessibleName = "Beschreibung (optional)",
                AccessibleDescription = "Zum Beispiel betroffene Anwendung oder was Sie gerade gemacht haben. Höchstens 1000 Zeichen.",
                Margin = new Padding(0, 0, 0, 3),
            };

            var userLabel = Ui.Text("Gemeldet als: " + _user, FieldWidth);
            userLabel.ForeColor = SystemColors.GrayText;
            _state = Ui.Text(string.Empty, FieldWidth);
            _state.Visible = false;

            _send = Ui.Button("Senden");
            _send.AccessibleName = "Meldung senden";
            _send.Click += OnSend;
            _cancel = Ui.Button("Abbrechen");
            _cancel.DialogResult = DialogResult.Cancel;
            _cancel.Click += (s, e) => Close();
            AcceptButton = _send;
            CancelButton = _cancel;
            var buttons = Ui.ButtonRow(_send, _cancel);

            var layout = Ui.Column();
            layout.Controls.AddRange(new Control[]
            {
                whenLabel, whenRow, categoryLabel, _category, durationLabel, _duration, descriptionLabel, _description,
                userLabel, _state, buttons,
            });
            Controls.Add(layout);

            Ui.TabOrder(layout);
            Ui.TabOrder(whenLabel, whenRow, categoryLabel, _category, durationLabel, _duration, descriptionLabel, _description,
                userLabel, _state, buttons);
            Ui.TabOrder(_now, _at, _time);
            Ui.TabOrder(_send, _cancel);

            ResumeLayout(false);
            PerformLayout();
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Activate();
            _category.Focus();
        }

        private ReportInput ReadInput() => new ReportInput
        {
            Now = _now.Checked,
            LocalTime = _time.Value,
            Category = (_category.SelectedItem as Choice)?.Value,
            Duration = (_duration.SelectedItem as Choice)?.Value ?? ReportCatalog.DefaultDuration,
            Description = _description.Text,
            User = _user,
        };

        private async void OnSend(object? sender, EventArgs e)
        {
            var input = ReadInput();
            var utcNow = DateTime.UtcNow;
            var error = ReportBuilder.Validate(input, utcNow);
            if (error != null)
            {
                Ui.Error(this, error);
                if (!ReportCatalog.IsCategory(input.Category))
                {
                    _category.Focus();
                }
                else if (!input.Now)
                {
                    _time.Focus();
                }

                return;
            }

            var json = ReportBuilder.ToJson(input, utcNow);
            SetBusy(true);
            ReportResult result;
            try
            {
                result = await Task.Run(() => _client.SendReport(json));
            }
            catch (Exception ex)
            {
                result = new ReportResult(ReportOutcome.Failed, "Die Meldung konnte nicht gesendet werden: " + ex.Message);
            }
            finally
            {
                SetBusy(false);
            }

            if (result.Outcome == ReportOutcome.Failed)
            {
                Ui.Error(this, result.Message);
                return;
            }

            MessageBox.Show(this, result.Message, "Wachtl – Problem melden", MessageBoxButtons.OK, MessageBoxIcon.Information);
            Close();
        }

        private void SetBusy(bool busy)
        {
            UseWaitCursor = busy;
            _send.Enabled = !busy;
            _category.Enabled = !busy;
            _duration.Enabled = !busy;
            _description.ReadOnly = busy;
            _now.Enabled = !busy;
            _at.Enabled = !busy;
            _time.Enabled = !busy && _at.Checked;
            _state.Text = busy ? "Meldung wird gesendet …" : string.Empty;
            _state.Visible = busy;
        }
    }
}
