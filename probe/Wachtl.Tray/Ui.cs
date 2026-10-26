using System;
using System.Drawing;
using System.Windows.Forms;

namespace Wachtl.Tray
{
    /// <summary>Wachtl-Symbol aus der eingebetteten wachtl.ico in passender Größe.</summary>
    internal static class AppIcons
    {
        private const string ResourceName = "Wachtl.Tray.wachtl.ico";

        public static Icon Load(Size size)
        {
            using (var stream = typeof(AppIcons).Assembly.GetManifestResourceStream(ResourceName))
            {
                if (stream == null)
                {
                    return (Icon)SystemIcons.Information.Clone();
                }

                return new Icon(stream, size);
            }
        }

        /// <summary>
        /// Symbol mit farbigem Punkt unten rechts: rot = Störung, gelb = Warnung. So sieht man neben der Uhr sofort,
        /// dass gerade etwas nicht stimmt – auch wenn man die Sprechblase verpasst hat.
        /// </summary>
        public static Icon WithBadge(Size size, Color color)
        {
            using (var bitmap = LoadBitmap(Math.Max(size.Width, 16)))
            {
                using (var g = Graphics.FromImage(bitmap))
                {
                    g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                    var d = (int)Math.Round(bitmap.Width * 0.55);
                    var rect = new Rectangle(bitmap.Width - d, bitmap.Height - d, d - 1, d - 1);
                    using (var fill = new SolidBrush(color))
                    using (var ring = new Pen(Color.White, Math.Max(1f, bitmap.Width / 16f)))
                    {
                        g.FillEllipse(fill, rect);
                        g.DrawEllipse(ring, rect);
                    }
                }

                var handle = bitmap.GetHicon();
                try
                {
                    using (var temp = Icon.FromHandle(handle))
                    {
                        return (Icon)temp.Clone();
                    }
                }
                finally
                {
                    DestroyIcon(handle);
                }
            }
        }

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool DestroyIcon(IntPtr handle);

        public static Bitmap LoadBitmap(int size)
        {
            using (var icon = Load(new Size(size, size)))
            {
                var bitmap = new Bitmap(size, size);
                using (var g = Graphics.FromImage(bitmap))
                {
                    g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                    g.DrawIcon(icon, new Rectangle(0, 0, size, size));
                }

                return bitmap;
            }
        }
    }

    /// <summary>Gemeinsame Grundeinstellungen der kleinen Fenster (Schrift, DPI, fester Rahmen).</summary>
    internal static class Ui
    {
        public static void SetupDialog(Form form, string title)
        {
            form.AutoScaleDimensions = new SizeF(96F, 96F);
            form.AutoScaleMode = AutoScaleMode.Dpi;
            form.Font = SystemFonts.MessageBoxFont;
            form.Text = title;
            form.FormBorderStyle = FormBorderStyle.FixedDialog;
            form.MaximizeBox = false;
            form.MinimizeBox = false;
            form.StartPosition = FormStartPosition.CenterScreen;
            form.ShowInTaskbar = true;
            form.AutoSize = true;
            form.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            form.Padding = new Padding(12);
            form.Icon = AppIcons.Load(SystemInformation.IconSize);
        }

        public static TableLayoutPanel Column()
        {
            var panel = new TableLayoutPanel
            {
                ColumnCount = 1,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Dock = DockStyle.Fill,
                Margin = Padding.Empty,
            };
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            return panel;
        }

        public static Label Heading(string text) => new Label
        {
            Text = text,
            AutoSize = true,
            Font = new Font(SystemFonts.MessageBoxFont, FontStyle.Bold),
            Margin = new Padding(0, 10, 0, 3),
        };

        public static Label Text(string text, int maxWidth = 0) => new Label
        {
            Text = text,
            AutoSize = true,
            MaximumSize = new Size(maxWidth, 0),
            Margin = new Padding(0, 3, 0, 3),
            UseMnemonic = false,
        };

        public static FlowLayoutPanel ButtonRow(params Button[] buttons)
        {
            var row = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.RightToLeft,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 14, 0, 0),
                WrapContents = false,
            };
            for (var i = buttons.Length - 1; i >= 0; i--)
            {
                row.Controls.Add(buttons[i]);
            }

            return row;
        }

        public static Button Button(string text) => new Button
        {
            Text = text,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(92, 28),
            Padding = new Padding(6, 0, 6, 0),
            Margin = new Padding(8, 0, 0, 0),
            UseVisualStyleBackColor = true,
        };

        /// <summary>Vergibt TabIndex in der übergebenen Reihenfolge.</summary>
        public static void TabOrder(params Control[] controls)
        {
            for (var i = 0; i < controls.Length; i++)
            {
                controls[i].TabIndex = i;
            }
        }

        public static void Error(IWin32Window owner, string message) =>
            MessageBox.Show(owner, message, "Wachtl – Problem melden", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
