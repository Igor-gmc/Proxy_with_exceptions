using System.ComponentModel;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace ProxyBridge;

internal static class AppTheme
{
    static Color Surface(int r, int g, int b, Color highContrast) =>
        SystemInformation.HighContrast ? highContrast : Color.FromArgb(r, g, b);

    public static Color Background => Surface(12, 12, 14, SystemColors.Window);
    public static Color Sidebar => Surface(20, 20, 22, SystemColors.Control);
    public static Color Card => Surface(27, 27, 30, SystemColors.Window);
    public static Color Raised => Surface(34, 34, 38, SystemColors.Control);
    public static Color Hover => Surface(43, 43, 48, SystemColors.ControlLight);
    public static Color Pressed => Surface(32, 32, 38, SystemColors.ControlDark);
    public static Color Input => Surface(17, 17, 19, SystemColors.Window);
    public static Color Border => Surface(83, 83, 91, SystemColors.WindowFrame);
    public static Color BorderHover => Surface(130, 130, 140, SystemColors.WindowFrame);
    public static Color CardBorder => Surface(41, 41, 46, SystemColors.WindowFrame);
    public static Color Text => Surface(242, 242, 245, SystemColors.WindowText);
    public static Color Muted => Surface(168, 168, 176, SystemColors.GrayText);
    public static Color Disabled => Surface(145, 145, 155, SystemColors.GrayText);
    public static Color Primary => Surface(20, 107, 195, SystemColors.Highlight);
    public static Color PrimaryText => Surface(255, 255, 255, SystemColors.HighlightText);
    public static Color PrimaryHover => Surface(33, 116, 201, SystemColors.Highlight);
    public static Color PrimaryPressed => Surface(16, 90, 167, SystemColors.Highlight);
    public static Color Accent => Surface(105, 179, 255, SystemColors.Highlight);
    public static Color Selection => Surface(25, 40, 61, SystemColors.Highlight);
    public static Color SelectionHover => Surface(34, 54, 80, SystemColors.Highlight);
    public static Color SelectionPressed => Surface(29, 47, 70, SystemColors.Highlight);
    public static Color Green => Surface(117, 220, 168, SystemColors.WindowText);
    public static Color Amber => Surface(239, 195, 120, SystemColors.WindowText);
    public static Color Red => Surface(245, 145, 151, SystemColors.WindowText);

    public static Label Label(string text, float size = 10.5f, bool bold = false, Color? color = null) => new()
    {
        Text = text,
        AutoSize = false,
        ForeColor = color ?? Text,
        BackColor = Color.Transparent,
        Font = new Font("Segoe UI", size, bold ? FontStyle.Bold : FontStyle.Regular),
        Dock = DockStyle.Fill,
        Margin = Padding.Empty,
        TextAlign = ContentAlignment.MiddleLeft
    };

    public static void Button(Button button, bool primary = false, Color? border = null)
    {
        button.AutoSize = false;
        button.Height = 40;
        button.FlatStyle = FlatStyle.Flat;
        button.UseVisualStyleBackColor = false;
        if (button is ThemeButton themed)
        {
            themed.IsPrimary = primary;
        }

        button.BackColor = primary ? Primary : Card;
        button.ForeColor = primary ? PrimaryText : Text;
        button.FlatAppearance.BorderSize = primary ? 0 : 1;
        button.FlatAppearance.BorderColor = border ?? (primary ? Primary : Border);
        button.FlatAppearance.MouseOverBackColor = primary ? PrimaryHover : Hover;
        button.FlatAppearance.MouseDownBackColor = primary ? PrimaryPressed : Pressed;
        button.Padding = new Padding(12, 3, 12, 3);
        button.Cursor = Cursors.Hand;
        button.AccessibleName = button.Text;
    }

    public static ThemeCard NewCard() => new()
    {
        BackColor = Card,
        ForeColor = Text,
        Dock = DockStyle.Fill,
        Padding = new Padding(18),
        Margin = Padding.Empty
    };

    internal static float Scale(Control control, float pixels) => pixels * control.DeviceDpi / 96f;

    // WinForms does not expose SPI_GETCLIENTAREAANIMATION. Read the Windows
    // accessibility preference without changing it or subscribing a static handler.
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SystemParametersInfo(uint action, uint parameter,
        [MarshalAs(UnmanagedType.Bool)] out bool value, uint flags);

    internal static bool AnimationsEnabled => !SystemInformation.HighContrast &&
        SystemParametersInfo(0x1042, 0, out bool enabled, 0) && enabled;

    internal static GraphicsPath Rounded(RectangleF bounds, float radius)
    {
        var path = new GraphicsPath();
        float diameter = Math.Min(radius * 2, Math.Min(bounds.Width, bounds.Height));
        if (diameter <= 0)
        {
            if (bounds.Width > 0 && bounds.Height > 0)
            {
                path.AddRectangle(bounds);
            }

            return path;
        }
        path.AddArc(bounds.Left, bounds.Top, diameter, diameter, 180, 90);
        path.AddArc(bounds.Right - diameter, bounds.Top, diameter, diameter, 270, 90);
        path.AddArc(bounds.Right - diameter, bounds.Bottom - diameter, diameter, diameter, 0, 90);
        path.AddArc(bounds.Left, bounds.Bottom - diameter, diameter, diameter, 90, 90);
        path.CloseFigure();
        return path;
    }

    internal static Color ParentBackground(Control control)
    {
        for (Control? parent = control.Parent; parent != null; parent = parent.Parent)
        {
            if (parent.BackColor.A == 255)
            {
                return parent.BackColor;
            }
        }

        return Background;
    }

    // Documented DWMWA_USE_IMMERSIVE_DARK_MODE=20, Windows 11 build 22000+.
    // Applies only to this HWND; unsupported/failed requests keep the native frame.
    // https://learn.microsoft.com/windows/win32/api/dwmapi/ne-dwmapi-dwmwindowattribute
    [DllImport("dwmapi.dll", ExactSpelling = true)]
    static extern int DwmSetWindowAttribute(IntPtr hwnd, uint attribute, ref int value, uint bytes);
    internal static void TryDarkTitleBar(Form form)
    {
        if (!form.IsHandleCreated || !OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000))
        {
            return;
        }

        try
        {
            int enabled = SystemInformation.HighContrast ? 0 : 1;
            _ = DwmSetWindowAttribute(form.Handle, 20, ref enabled, sizeof(int));
        }
        catch (DllNotFoundException) { }
        catch (EntryPointNotFoundException) { }
    }
}

internal sealed class ThemeCard : Panel
{
    [DefaultValue(18)]
    public int CornerRadius { get; set; } = 18;
    public ThemeCard()
    {
        DoubleBuffered = true;
        ResizeRedraw = true;
    }

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        if (SystemInformation.HighContrast)
        {
            base.OnPaintBackground(e);
            return;
        }
        e.Graphics.Clear(AppTheme.ParentBackground(this));
        if (Width < 2 || Height < 2)
        {
            return;
        }

        var saved = e.Graphics.Save();
        try
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var path = AppTheme.Rounded(new RectangleF(.5f, .5f, Width - 1, Height - 1), AppTheme.Scale(this, CornerRadius));
            using var brush = new SolidBrush(BackColor);
            e.Graphics.FillPath(brush, path);
        }
        finally { e.Graphics.Restore(saved); }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        if (Width < 2 || Height < 2)
        {
            return;
        }

        using var pen = new Pen(AppTheme.CardBorder, Math.Max(1, AppTheme.Scale(this, 1)));
        if (SystemInformation.HighContrast)
        {
            e.Graphics.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
            return;
        }
        var saved = e.Graphics.Save();
        try
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var path = AppTheme.Rounded(new RectangleF(.5f, .5f, Width - 1, Height - 1), AppTheme.Scale(this, CornerRadius));
            e.Graphics.DrawPath(pen, path);
        }
        finally { e.Graphics.Restore(saved); }
    }
}
