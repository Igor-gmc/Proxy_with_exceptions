using System.Drawing.Drawing2D;

namespace ProxyBridge;

// Painting only: CheckBox still owns Checked, clicks, keyboard, focus and
// accessibility. Replaces the light native glyph on the dark background.
// High contrast keeps the native rendering.
internal sealed class ThemeCheckBox : CheckBox
{
    bool hovered;

    public ThemeCheckBox()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
            ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, !SystemInformation.HighContrast);
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        hovered = true;
        base.OnMouseEnter(e);
        Invalidate();
    }
    protected override void OnMouseLeave(EventArgs e)
    {
        hovered = false;
        base.OnMouseLeave(e);
        Invalidate();
    }
    protected override void OnCheckedChanged(EventArgs e)
    {
        base.OnCheckedChanged(e);
        Invalidate();
    }
    protected override void OnEnabledChanged(EventArgs e)
    {
        base.OnEnabledChanged(e);
        Invalidate();
    }
    protected override void OnGotFocus(EventArgs e)
    {
        base.OnGotFocus(e);
        Invalidate();
    }
    protected override void OnLostFocus(EventArgs e)
    {
        base.OnLostFocus(e);
        Invalidate();
    }

    public override Size GetPreferredSize(Size proposedSize)
    {
        int box = (int)Math.Round(AppTheme.Scale(this, 16));
        if (string.IsNullOrEmpty(Text))
        {
            return new Size(box + 4, box + 4);
        }

        var text = TextRenderer.MeasureText(Text, Font);
        int gap = (int)Math.Round(AppTheme.Scale(this, 8));
        return new Size(box + gap + text.Width + 4, Math.Max(box + 4, text.Height + 4));
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        if (SystemInformation.HighContrast)
        {
            base.OnPaint(e);
            return;
        }

        e.Graphics.Clear(AppTheme.ParentBackground(this));
        int size = (int)Math.Round(AppTheme.Scale(this, 16));
        var box = new RectangleF(1.5f, (Height - size) / 2f, size - 1, size - 1);
        var saved = e.Graphics.Save();
        try
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var path = AppTheme.Rounded(box, AppTheme.Scale(this, 4));
            if (Checked)
            {
                Color fill = !Enabled ? AppTheme.Raised : hovered ? AppTheme.PrimaryHover : AppTheme.Primary;
                using var brush = new SolidBrush(fill);
                e.Graphics.FillPath(brush, path);
                using var tick = new Pen(Enabled ? AppTheme.PrimaryText : AppTheme.Disabled, Math.Max(1.5f, AppTheme.Scale(this, 2)))
                {
                    StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round
                };
                float x = box.X, y = box.Y, w = box.Width;
                e.Graphics.DrawLines(tick, [new PointF(x + w * .25f, y + w * .52f), new PointF(x + w * .43f, y + w * .7f), new PointF(x + w * .76f, y + w * .32f)]);
            }
            else
            {
                using var brush = new SolidBrush(Enabled && hovered ? AppTheme.Raised : AppTheme.Input);
                e.Graphics.FillPath(brush, path);
                using var pen = new Pen(Enabled ? (hovered ? AppTheme.BorderHover : AppTheme.Border) : AppTheme.CardBorder, Math.Max(1, AppTheme.Scale(this, 1)));
                e.Graphics.DrawPath(pen, path);
            }
            if (Focused && ShowFocusCues)
            {
                float ring = Math.Max(2, AppTheme.Scale(this, 2));
                var focus = RectangleF.Inflate(box, ring, ring);
                using var focusPath = AppTheme.Rounded(focus, AppTheme.Scale(this, 6));
                using var focusPen = new Pen(Color.FromArgb(180, AppTheme.Accent), ring);
                e.Graphics.DrawPath(focusPen, focusPath);
            }
        }
        finally { e.Graphics.Restore(saved); }

        if (!string.IsNullOrEmpty(Text))
        {
            int gap = (int)Math.Round(AppTheme.Scale(this, 8));
            var textBounds = new Rectangle(size + gap + 2, 0, Math.Max(0, Width - size - gap - 2), Height);
            TextRenderer.DrawText(e.Graphics, Text, Font, textBounds, Enabled ? ForeColor : AppTheme.Disabled,
                TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        }
    }
}
