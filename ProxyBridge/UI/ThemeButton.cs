using System.ComponentModel;
using System.Diagnostics;
using System.Drawing.Drawing2D;

namespace ProxyBridge;

// Painting only: Button still owns clicks, enabled state, focus, keyboard,
// accessibility and dialog behavior. No action handlers are invoked here.
internal sealed class ThemeButton : Button
{
    bool hovered, pointerPressed, keyPressed, selected, isPrimary;
    string? navigationIcon;
    // Keep >= 8: the corner regression in tests/DesignPreview samples 2x2
    // exterior pixels and skips smaller radii.
    int cornerRadius = 8;
    System.Windows.Forms.Timer? transition;
    Color currentBackground, fromBackground, targetBackground;
    long transitionStarted;
    bool hasBackground;

    [DefaultValue(false)]
    public bool Selected
    {
        get => selected;
        // Keep navigation state and its blue accent in sync from the first frame.
        set
        {
            if (selected == value)
            {
                return;
            }

            selected = value;
            RefreshVisual(animate: false);
        }
    }

    [DefaultValue(false)]
    public bool IsPrimary
    {
        get => isPrimary;
        set
        {
            if (isPrimary == value)
            {
                return;
            }

            isPrimary = value;
            RefreshVisual(animate: false);
        }
    }

    [DefaultValue(null)]
    public string? NavigationIcon
    {
        get => navigationIcon;
        set
        {
            navigationIcon = value;
            Invalidate();
        }
    }

    [DefaultValue(8)]
    public int CornerRadius
    {
        get => cornerRadius;
        set
        {
            cornerRadius = Math.Max(0, value);
            Invalidate();
        }
    }

    public ThemeButton()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
            ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        SetStyle(ControlStyles.Opaque, false);
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        hovered = true;
        base.OnMouseEnter(e);
        RefreshVisual();
    }
    protected override void OnMouseLeave(EventArgs e)
    {
        hovered = false;
        base.OnMouseLeave(e);
        RefreshVisual();
    }
    protected override void OnMouseDown(MouseEventArgs e)
    {
        if (Enabled && e.Button == MouseButtons.Left)
        {
            pointerPressed = true;
        }

        base.OnMouseDown(e);
        RefreshVisual();
    }
    protected override void OnMouseUp(MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left)
        {
            pointerPressed = false;
        }

        base.OnMouseUp(e);
        RefreshVisual();
    }
    protected override void OnMouseCaptureChanged(EventArgs e)
    {
        if (!Capture)
        {
            pointerPressed = false;
        }

        base.OnMouseCaptureChanged(e);
        RefreshVisual();
    }
    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (Enabled && e.KeyCode == Keys.Space)
        {
            keyPressed = true;
        }

        base.OnKeyDown(e);
        RefreshVisual();
    }
    protected override void OnKeyUp(KeyEventArgs e)
    {
        if (e.KeyCode == Keys.Space)
        {
            keyPressed = false;
        }

        base.OnKeyUp(e);
        RefreshVisual();
    }
    protected override void OnGotFocus(EventArgs e)
    {
        base.OnGotFocus(e);
        Invalidate();
    }
    protected override void OnLostFocus(EventArgs e)
    {
        keyPressed = false;
        base.OnLostFocus(e);
        RefreshVisual();
    }
    protected override void OnEnabledChanged(EventArgs e)
    {
        if (!Enabled)
        {
            hovered = pointerPressed = keyPressed = false;
        }
        base.OnEnabledChanged(e);
        RefreshVisual(animate: false);
    }

    protected override void OnBackColorChanged(EventArgs e)
    {
        base.OnBackColorChanged(e);
        RefreshVisual(animate: false);
    }
    protected override void OnVisibleChanged(EventArgs e)
    {
        base.OnVisibleChanged(e);
        RefreshVisual(animate: false);
    }
    protected override void OnSystemColorsChanged(EventArgs e)
    {
        base.OnSystemColorsChanged(e);
        RefreshVisual(animate: false);
    }
    protected override void OnHandleDestroyed(EventArgs e)
    {
        transition?.Stop();
        base.OnHandleDestroyed(e);
    }

    bool Pressed => Enabled && (keyPressed || pointerPressed && hovered);

    Color DesiredBackground() => !Enabled ? AppTheme.Card
        // Selected navigation is a solid accent fill, as in System Settings.
        : selected ? (Pressed ? AppTheme.PrimaryPressed : hovered ? AppTheme.PrimaryHover : AppTheme.Primary)
        : IsPrimary ? (Pressed ? AppTheme.PrimaryPressed : hovered ? AppTheme.PrimaryHover : AppTheme.Primary)
        : Pressed ? FlatAppearance.MouseDownBackColor
        : hovered ? FlatAppearance.MouseOverBackColor : BackColor;

    void RefreshVisual(bool animate = true)
    {
        if (IsDisposed || Disposing)
        {
            return;
        }

        Color next = DesiredBackground();
        if (!hasBackground || !animate || !IsHandleCreated || !Visible || !AppTheme.AnimationsEnabled)
        {
            transition?.Stop();
            currentBackground = targetBackground = next;
            hasBackground = true;
        }
        else if (next != targetBackground)
        {
            fromBackground = currentBackground;
            targetBackground = next;
            transitionStarted = Stopwatch.GetTimestamp();
            if (transition == null)
            {
                transition = new System.Windows.Forms.Timer { Interval = 15 };
                transition.Tick += Animate;
            }
            transition.Start();
        }
        Invalidate();
    }

    void Animate(object? sender, EventArgs e)
    {
        if (IsDisposed || Disposing)
        {
            transition?.Stop();
            return;
        }
        if (!Visible || !AppTheme.AnimationsEnabled)
        {
            transition?.Stop();
            currentBackground = targetBackground;
            Invalidate();
            return;
        }
        double progress = Math.Min(1, Stopwatch.GetElapsedTime(transitionStarted).TotalMilliseconds / 150);
        double eased = 1 - Math.Pow(1 - progress, 3);
        currentBackground = Color.FromArgb(
            (int)Math.Round(fromBackground.R + (targetBackground.R - fromBackground.R) * eased),
            (int)Math.Round(fromBackground.G + (targetBackground.G - fromBackground.G) * eased),
            (int)Math.Round(fromBackground.B + (targetBackground.B - fromBackground.B) * eased));
        if (progress >= 1)
        {
            transition?.Stop();
        }

        Invalidate();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && transition != null)
        {
            transition.Stop();
            transition.Tick -= Animate;
            transition.Dispose();
            transition = null;
        }
        base.Dispose(disposing);
    }

    protected override void OnPaintBackground(PaintEventArgs e) => e.Graphics.Clear(AppTheme.ParentBackground(this));

    protected override void OnPaint(PaintEventArgs e)
    {
        // A rounded fill leaves the four corner areas untouched. Button's native
        // flat/hover paint paths can omit a separate background erase, so every
        // custom frame must repaint the entire rectangular surface itself.
        // Do not invalidate the parent: that would recursively repaint siblings.
        using (var parentBrush = new SolidBrush(AppTheme.ParentBackground(this)))
        {
            e.Graphics.FillRectangle(parentBrush, ClientRectangle);
        }

        if (Width < 3 || Height < 3)
        {
            return;
        }

        bool pressed = Pressed;
        bool highContrast = SystemInformation.HighContrast;
        Color background = transition?.Enabled == true ? currentBackground : DesiredBackground();
        if (transition?.Enabled != true)
        {
            currentBackground = targetBackground = background;
            hasBackground = true;
        }
        Color foreground = !Enabled ? AppTheme.Disabled : selected || IsPrimary ? AppTheme.PrimaryText : ForeColor;
        Color iconColor = !Enabled ? AppTheme.Disabled : selected ? AppTheme.PrimaryText : AppTheme.Muted;
        Color border = !Enabled ? AppTheme.CardBorder : hovered ? AppTheme.Border : FlatAppearance.BorderColor;
        bool focusRing = Enabled && Focused && ShowFocusCues;
        if (highContrast)
        {
            bool highlighted = Enabled && (selected || IsPrimary || BackColor == SystemColors.Highlight);
            background = highlighted ? SystemColors.Highlight : SystemColors.Control;
            foreground = !Enabled ? SystemColors.GrayText : highlighted ? SystemColors.HighlightText : SystemColors.ControlText;
            iconColor = foreground;
            border = SystemColors.WindowFrame;
        }
        var saved = e.Graphics.Save();
        try
        {
            e.Graphics.SmoothingMode = highContrast ? SmoothingMode.None : SmoothingMode.AntiAlias;
            var bounds = new RectangleF(.5f, .5f, Width - 1, Height - 1);
            using var brush = new SolidBrush(background);
            using var pen = new Pen(border, Math.Max(1, AppTheme.Scale(this, 1)));
            if (highContrast)
            {
                e.Graphics.FillRectangle(brush, ClientRectangle);
                ControlPaint.DrawBorder3D(e.Graphics, ClientRectangle, pressed ? Border3DStyle.Sunken : Border3DStyle.RaisedInner);
            }
            else
            {
                using var path = AppTheme.Rounded(bounds, AppTheme.Scale(this, CornerRadius));
                e.Graphics.FillPath(brush, path);
                // While the focus ring is visible the own outline is skipped,
                // so the two never form a double frame.
                if (FlatAppearance.BorderSize > 0 && !focusRing)
                {
                    e.Graphics.DrawPath(pen, path);
                }
            }
            if (focusRing)
            {
                if (highContrast)
                {
                    int inset = Math.Max(3, (int)Math.Round(AppTheme.Scale(this, 3)));
                    var focus = Rectangle.Inflate(ClientRectangle, -inset, -inset);
                    if (focus.Width > 0 && focus.Height > 0)
                    {
                        ControlPaint.DrawFocusRectangle(e.Graphics, focus, foreground, background);
                    }
                }
                else
                {
                    // 3 px ring along the edge; white on accent fills (Accent on
                    // Primary is only 2.2:1), translucent Accent elsewhere.
                    bool onAccent = IsPrimary || selected;
                    float ring = Math.Max(2, AppTheme.Scale(this, 3));
                    float inset = AppTheme.Scale(this, onAccent ? 2 : 1.5f) + ring / 2;
                    var focus = RectangleF.Inflate(new RectangleF(0, 0, Width, Height), -inset, -inset);
                    if (focus.Width > 0 && focus.Height > 0)
                    {
                        using var focusPath = AppTheme.Rounded(focus, Math.Max(0, AppTheme.Scale(this, CornerRadius) - inset));
                        Color focusColor = onAccent ? AppTheme.PrimaryText : Color.FromArgb(180, AppTheme.Accent);
                        using var focusPen = new Pen(focusColor, ring);
                        e.Graphics.DrawPath(focusPen, focusPath);
                    }
                }
            }
        }
        finally { e.Graphics.Restore(saved); }

        var textBounds = new Rectangle(Padding.Left + 2, Padding.Top + 2,
            Math.Max(0, ClientSize.Width - Padding.Horizontal - 4),
            Math.Max(0, ClientSize.Height - Padding.Vertical - 4));
        if (NavigationIcon is "overview" or "proxy" or "exclusions" or "help")
        {
            int iconSize = (int)Math.Round(AppTheme.Scale(this, 16));
            int iconGap = (int)Math.Round(AppTheme.Scale(this, 10));
            var iconBounds = new Rectangle(textBounds.Left, (Height - iconSize) / 2, iconSize, iconSize);
            if (RightToLeft == RightToLeft.Yes)
            {
                iconBounds.X = textBounds.Right - iconSize;
            }

            DrawNavigationIcon(e.Graphics, iconBounds, iconColor, NavigationIcon);
            if (RightToLeft != RightToLeft.Yes)
            {
                textBounds.X += iconSize + iconGap;
            }

            textBounds.Width = Math.Max(0, textBounds.Width - iconSize - iconGap);
        }
        if (pressed)
        {
            textBounds.Offset(0, Math.Max(1, (int)Math.Round(AppTheme.Scale(this, 1))));
        }

        var flags = TextFormatFlags.WordBreak | TextFormatFlags.EndEllipsis | TextFormatFlags.PreserveGraphicsClipping;
        flags |= TextAlign is ContentAlignment.TopLeft or ContentAlignment.MiddleLeft or ContentAlignment.BottomLeft
            ? TextFormatFlags.Left : TextAlign is ContentAlignment.TopRight or ContentAlignment.MiddleRight or ContentAlignment.BottomRight
                ? TextFormatFlags.Right : TextFormatFlags.HorizontalCenter;
        if (!UseMnemonic)
        {
            flags |= TextFormatFlags.NoPrefix;
        }
        else if (!ShowKeyboardCues)
        {
            flags |= TextFormatFlags.HidePrefix;
        }

        if (RightToLeft == RightToLeft.Yes)
        {
            flags |= TextFormatFlags.RightToLeft;
        }

        var measured = TextRenderer.MeasureText(e.Graphics, Text, Font, textBounds.Size, flags);
        int spareHeight = Math.Max(0, textBounds.Height - measured.Height);
        if (TextAlign is ContentAlignment.MiddleLeft or ContentAlignment.MiddleCenter or ContentAlignment.MiddleRight)
        {
            textBounds.Y += spareHeight / 2;
        }
        else if (TextAlign is ContentAlignment.BottomLeft or ContentAlignment.BottomCenter or ContentAlignment.BottomRight)
        {
            textBounds.Y += spareHeight;
        }

        textBounds.Height = Math.Max(0, ClientSize.Height - Padding.Bottom - 2 - textBounds.Y);
        TextRenderer.DrawText(e.Graphics, Text, Font, textBounds, foreground, flags);
    }

    static void DrawNavigationIcon(Graphics graphics, Rectangle bounds, Color color, string icon)
    {
        var saved = graphics.Save();
        try
        {
            graphics.SmoothingMode = SmoothingMode.AntiAlias;
            graphics.TranslateTransform(bounds.X, bounds.Y);
            graphics.ScaleTransform(bounds.Width / 18f, bounds.Height / 18f);
            using var pen = new Pen(color, 1.5f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
            using var brush = new SolidBrush(color);
            switch (icon)
            {
                case "overview":
                    foreach (var box in new[] { new RectangleF(1, 1, 6, 6), new RectangleF(11, 1, 6, 6),
                        new RectangleF(1, 11, 6, 6), new RectangleF(11, 11, 6, 6) })
                    {
                        using var path = AppTheme.Rounded(box, 1.4f);
                        graphics.DrawPath(pen, path);
                    }
                    break;
                case "proxy":
                    foreach (float y in new[] { 1f, 11f })
                    {
                        using var path = AppTheme.Rounded(new RectangleF(1, y, 16, 6), 1.8f);
                        graphics.DrawPath(pen, path);
                        graphics.FillEllipse(brush, 3, y + 2, 2, 2);
                        graphics.DrawLine(pen, 10, y + 3, 14, y + 3);
                    }
                    break;
                case "exclusions":
                    using (var path = AppTheme.Rounded(new RectangleF(1, 1, 12, 12), 2))
                    {
                        graphics.DrawPath(pen, path);
                    }

                    graphics.DrawLine(pen, 5, 17, 17, 17);
                    graphics.DrawLine(pen, 17, 5, 17, 17);
                    graphics.DrawLine(pen, 4, 7, 6, 9);
                    graphics.DrawLine(pen, 6, 9, 10, 5);
                    break;
                case "help":
                    graphics.DrawEllipse(pen, 1, 1, 16, 16);
                    graphics.DrawArc(pen, 6, 4, 6, 5, 185, 275);
                    graphics.DrawLine(pen, 9, 9, 9, 10.5f);
                    graphics.FillEllipse(brush, 8.25f, 13, 1.5f, 1.5f);
                    break;
            }
        }
        finally { graphics.Restore(saved); }
    }
}
