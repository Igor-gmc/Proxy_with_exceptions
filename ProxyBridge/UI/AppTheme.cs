using System.ComponentModel;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace ProxyBridge;

internal static class AppTheme
{
    static Color Surface(int r, int g, int b, Color highContrast) =>
        SystemInformation.HighContrast ? highContrast : Color.FromArgb(r, g, b);

    // Apple-style graphite palette (macOS System Settings, dark). Primary blue is
    // darker than system #0A84FF so white text stays >= 4.5:1; Red is the
    // accessible variant. Second arguments are the high-contrast colours.
    public static Color Background => Surface(28, 28, 30, SystemColors.Window);
    public static Color Sidebar => Surface(36, 36, 38, SystemColors.Control);
    public static Color Card => Surface(44, 44, 46, SystemColors.Window);
    public static Color Raised => Surface(58, 58, 60, SystemColors.Control);
    public static Color Hover => Surface(64, 64, 66, SystemColors.ControlLight);
    public static Color Pressed => Surface(50, 50, 52, SystemColors.ControlDark);
    public static Color Input => Surface(20, 20, 22, SystemColors.Window);
    public static Color Border => Surface(84, 84, 88, SystemColors.WindowFrame);
    public static Color BorderHover => Surface(124, 124, 128, SystemColors.WindowFrame);
    public static Color CardBorder => Surface(56, 56, 58, SystemColors.WindowFrame);
    public static Color Text => Surface(245, 245, 247, SystemColors.WindowText);
    public static Color Muted => Surface(174, 174, 178, SystemColors.GrayText);
    public static Color Disabled => Surface(128, 128, 133, SystemColors.GrayText);
    public static Color Primary => Surface(0, 106, 214, SystemColors.Highlight);
    public static Color PrimaryText => Surface(255, 255, 255, SystemColors.HighlightText);
    public static Color PrimaryHover => Surface(0, 113, 227, SystemColors.Highlight);
    public static Color PrimaryPressed => Surface(0, 92, 186, SystemColors.Highlight);
    public static Color Accent => Surface(100, 172, 255, SystemColors.Highlight);
    public static Color Selection => Surface(24, 52, 92, SystemColors.Highlight);
    public static Color SelectionHover => Surface(30, 62, 108, SystemColors.Highlight);
    public static Color SelectionPressed => Surface(20, 46, 82, SystemColors.Highlight);
    public static Color Green => Surface(50, 215, 150, SystemColors.WindowText);
    public static Color Amber => Surface(255, 204, 0, SystemColors.WindowText);
    public static Color Red => Surface(255, 105, 97, SystemColors.WindowText);

    // Semibold is a separate family on every supported Windows; it replaces
    // synthetic Bold as the Apple-style emphasis.
    public static Font Font(float size, bool semibold = false) =>
        semibold ? new Font("Segoe UI Semibold", size) : new Font("Segoe UI", size);

    // GDI+ silently substitutes a missing family, so check the resolved name.
    public static Font MonoFont(float size)
    {
        var font = new Font("Cascadia Mono", size);
        if (string.Equals(font.Name, "Cascadia Mono", StringComparison.OrdinalIgnoreCase))
        {
            return font;
        }

        font.Dispose();
        return new Font("Consolas", size);
    }

    public static Label Label(string text, float size = 10f, bool bold = false, Color? color = null) => new()
    {
        Text = text,
        AutoSize = false,
        ForeColor = color ?? Text,
        BackColor = Color.Transparent,
        Font = Font(size, bold),
        Dock = DockStyle.Fill,
        Margin = Padding.Empty,
        TextAlign = ContentAlignment.MiddleLeft
    };

    public static void Button(Button button, bool primary = false, Color? border = null)
    {
        button.AutoSize = false;
        button.Height = 32;
        button.FlatStyle = FlatStyle.Flat;
        button.UseVisualStyleBackColor = false;
        if (button is ThemeButton themed)
        {
            themed.IsPrimary = primary;
        }

        // Secondary buttons read by their fill; a hairline keeps them visible
        // on the window background. Primary buttons have no outline.
        button.BackColor = primary ? Primary : Raised;
        button.ForeColor = primary ? PrimaryText : Text;
        button.FlatAppearance.BorderSize = primary ? 0 : 1;
        button.FlatAppearance.BorderColor = border ?? (primary ? Primary : CardBorder);
        button.FlatAppearance.MouseOverBackColor = primary ? PrimaryHover : Hover;
        button.FlatAppearance.MouseDownBackColor = primary ? PrimaryPressed : Pressed;
        button.Padding = new Padding(14, 3, 14, 3);
        button.Cursor = Cursors.Hand;
        button.AccessibleName = button.Text;
    }

    public static ThemeCard NewCard() => new()
    {
        BackColor = Card,
        ForeColor = Text,
        Dock = DockStyle.Fill,
        Padding = new Padding(16),
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

    // Dark scroll bars and drop-downs for native controls. The theme names are
    // undocumented (stable since Windows 10 1809); on failure the control keeps
    // its current look. Never applied in high contrast.
    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    static extern int SetWindowTheme(IntPtr hwnd, string? subAppName, string? subIdList);
    internal static void DarkNative(Control control, string theme = "DarkMode_Explorer")
    {
        void Apply()
        {
            if (SystemInformation.HighContrast || !control.IsHandleCreated)
            {
                return;
            }

            try
            {
                _ = SetWindowTheme(control.Handle, theme, null);
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
        }
        control.HandleCreated += (_, _) => Apply();
        Apply();
    }

    // Documented DWMWA_USE_IMMERSIVE_DARK_MODE=20 and DWMWA_CAPTION_COLOR=35, Windows 11 build 22000+.
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
            // Caption in the window background (COLORREF 0x00BBGGRR);
            // DWMWA_COLOR_DEFAULT (0xFFFFFFFF) restores the system caption.
            Color caption = Background;
            int colorRef = SystemInformation.HighContrast ? unchecked((int)0xFFFFFFFF) : caption.R | caption.G << 8 | caption.B << 16;
            _ = DwmSetWindowAttribute(form.Handle, 35, ref colorRef, sizeof(int));
        }
        catch (DllNotFoundException) { }
        catch (EntryPointNotFoundException) { }
    }
}

internal enum ThemeCardBorder { Full, None, Right }

internal sealed class ThemeCard : Panel
{
    Color? emphasis;

    [DefaultValue(12)]
    public int CornerRadius { get; set; } = 12;

    // Right: a flat panel separated by a single vertical hairline (sidebar).
    [DefaultValue(ThemeCardBorder.Full)]
    public ThemeCardBorder BorderMode { get; set; } = ThemeCardBorder.Full;

    // 2 px focus (Accent) or error (Red) outline; null draws the hairline.
    [DefaultValue(null)]
    public Color? Emphasis
    {
        get => emphasis;
        set
        {
            if (emphasis == value)
            {
                return;
            }

            emphasis = value;
            Invalidate();
        }
    }
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

        bool emphasized = emphasis != null && !SystemInformation.HighContrast;
        if (BorderMode == ThemeCardBorder.None && !emphasized)
        {
            return;
        }

        float width = emphasized ? Math.Max(2, AppTheme.Scale(this, 2)) : Math.Max(1, AppTheme.Scale(this, 1));
        using var pen = new Pen(emphasized ? emphasis!.Value : AppTheme.CardBorder, width);
        if (BorderMode == ThemeCardBorder.Right && !emphasized)
        {
            float x = Width - width / 2;
            e.Graphics.DrawLine(pen, x, 0, x, Height);
            return;
        }
        if (SystemInformation.HighContrast)
        {
            e.Graphics.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
            return;
        }
        var saved = e.Graphics.Save();
        try
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            float inset = width / 2;
            using var path = AppTheme.Rounded(new RectangleF(inset, inset, Width - width, Height - width), AppTheme.Scale(this, CornerRadius));
            e.Graphics.DrawPath(pen, path);
        }
        finally { e.Graphics.Restore(saved); }
    }
}
