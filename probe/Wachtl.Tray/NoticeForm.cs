using System;
using System.Drawing;
using System.Windows.Forms;
using Wachtl.Tray.Core;

namespace Wachtl.Tray
{
    /// <summary>
    /// Eigenes Hinweisfenster unten rechts über der Uhr – statt der Windows-Sprechblase. Windows 11 macht aus einer
    /// Sprechblase eine System-Benachrichtigung und verwirft sie still bei „Nicht stören“, ausgeschalteten
    /// App-Benachrichtigungen oder in der ersten Stunde nach der Anmeldung. Dieses Fenster erscheint immer,
    /// nimmt keinen Fokus, bleibt unter der Maus stehen und schließt sich sonst nach der angegebenen Zeit.
    /// Ein Klick öffnet die Details (<see cref="Opened"/>), ✕ schließt nur.
    /// </summary>
    internal sealed class NoticeForm : Form
    {
        private const int WsExTopmost = 0x00000008;
        private const int WsExToolWindow = 0x00000080;
        private const int WsExNoActivate = 0x08000000;
        private const int ScreenMargin = 12;
        private const int TextWidth = 320;

        private readonly System.Windows.Forms.Timer _timer;
        private readonly Button _close;
        private readonly TimeSpan _linger = TimeSpan.FromSeconds(4);
        private DateTime _hideAt;

        public NoticeForm(Balloon balloon, TimeSpan duration)
        {
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Font = SystemFonts.MessageBoxFont;
            Text = FindingNotifier.Caption;
            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            TopMost = true;
            StartPosition = FormStartPosition.Manual;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            BackColor = SystemColors.ControlDark; // 1 px Rahmen (Padding)
            Padding = new Padding(1);
            AccessibleName = balloon.Title;

            var layout = new TableLayoutPanel
            {
                ColumnCount = 4,
                RowCount = 1,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Dock = DockStyle.Fill,
                Margin = Padding.Empty,
                BackColor = SystemColors.Window,
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 5));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            var accent = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty, BackColor = AccentColor(balloon.Icon) };

            var picture = new PictureBox
            {
                Image = SystemIconFor(balloon.Icon).ToBitmap(),
                SizeMode = PictureBoxSizeMode.Zoom,
                Size = new Size(32, 32),
                Margin = new Padding(12, 14, 4, 12),
            };

            var texts = new TableLayoutPanel
            {
                ColumnCount = 1,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Margin = new Padding(6, 10, 0, 10),
                BackColor = SystemColors.Window,
            };
            texts.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            texts.Controls.Add(Label(balloon.Title, new Font(SystemFonts.MessageBoxFont, FontStyle.Bold), SystemColors.WindowText, new Padding(0, 0, 0, 4)));
            texts.Controls.Add(Label(balloon.Text, Font, SystemColors.WindowText, new Padding(0, 0, 0, 6)));
            texts.Controls.Add(Label("Klicken zeigt Details und Lösung", Font, SystemColors.GrayText, Padding.Empty));

            _close = new Button
            {
                Text = "✕",
                FlatStyle = FlatStyle.Flat,
                Size = new Size(28, 28),
                Margin = new Padding(4, 4, 4, 0),
                TabStop = false,
                BackColor = SystemColors.Window,
                ForeColor = SystemColors.GrayText,
                AccessibleName = "Schließen",
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
            };
            _close.FlatAppearance.BorderSize = 0;
            _close.Click += (s, e) => Close();

            layout.Controls.Add(accent, 0, 0);
            layout.Controls.Add(picture, 1, 0);
            layout.Controls.Add(texts, 2, 0);
            layout.Controls.Add(_close, 3, 0);
            Controls.Add(layout);
            WireClick(this);

            _hideAt = DateTime.UtcNow + duration;
            _timer = new System.Windows.Forms.Timer { Interval = 500 };
            _timer.Tick += (s, e) => Tick();
            _timer.Start();
        }

        /// <summary>Klick auf das Fenster (nicht auf ✕): Details zeigen.</summary>
        public event EventHandler? Opened;

        protected override bool ShowWithoutActivation => true;

        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                cp.ExStyle |= WsExTopmost | WsExToolWindow | WsExNoActivate;
                return cp;
            }
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            PlaceBottomRight();
        }

        protected override void OnSizeChanged(EventArgs e)
        {
            base.OnSizeChanged(e);
            if (IsHandleCreated)
            {
                PlaceBottomRight();
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _timer.Dispose();
            }

            base.Dispose(disposing);
        }

        private void Tick()
        {
            var now = DateTime.UtcNow;
            if (Bounds.Contains(Cursor.Position))
            {
                // Unter der Maus nicht verschwinden: erst kurz nach dem Wegbewegen schließen
                if (_hideAt < now + _linger)
                {
                    _hideAt = now + _linger;
                }

                return;
            }

            if (now >= _hideAt)
            {
                Close();
            }
        }

        private void PlaceBottomRight()
        {
            // Arbeitsbereich ohne Taskleiste – unten rechts, egal wo die Taskleiste sitzt
            var area = (Screen.PrimaryScreen ?? Screen.FromControl(this)).WorkingArea;
            Location = new Point(area.Right - Width - ScreenMargin, area.Bottom - Height - ScreenMargin);
        }

        private void WireClick(Control control)
        {
            if (control == _close)
            {
                return;
            }

            control.Click += (s, e) =>
            {
                Opened?.Invoke(this, EventArgs.Empty);
                Close();
            };
            control.Cursor = Cursors.Hand;
            foreach (Control child in control.Controls)
            {
                WireClick(child);
            }
        }

        private static Label Label(string text, Font font, Color color, Padding margin) => new Label
        {
            Text = text,
            Font = font,
            ForeColor = color,
            BackColor = SystemColors.Window,
            AutoSize = true,
            MaximumSize = new Size(TextWidth, 0),
            Margin = margin,
            UseMnemonic = false,
        };

        private static Color AccentColor(BalloonIcon icon) =>
            icon == BalloonIcon.Error ? Color.FromArgb(0xC4, 0x2B, 0x1C)
            : icon == BalloonIcon.Warning ? Color.FromArgb(0xE0, 0x9B, 0x00)
            : Color.FromArgb(0x0F, 0x6C, 0xBD);

        private static Icon SystemIconFor(BalloonIcon icon) =>
            icon == BalloonIcon.Error ? SystemIcons.Error
            : icon == BalloonIcon.Warning ? SystemIcons.Warning
            : SystemIcons.Information;
    }
}
