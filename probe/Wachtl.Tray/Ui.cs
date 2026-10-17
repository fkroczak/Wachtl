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
