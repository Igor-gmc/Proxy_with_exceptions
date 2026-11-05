$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$projectRoot = Split-Path -Parent $PSScriptRoot
$assets = Join-Path $projectRoot 'ProxyBridge\Assets'
New-Item -ItemType Directory -Force -Path $assets | Out-Null
$sizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)
$variants = @(
    @{ Name = 'drive'; Letter = 'D'; Color = '#168A45' },
    @{ Name = 'parking'; Letter = 'P'; Color = '#E0AC00' },
    @{ Name = 'stop'; Letter = 'S'; Color = '#D62E38' }
)
foreach ($variant in $variants) {
    $frames = @()
    foreach ($size in $sizes) {
        $bitmap = New-Object Drawing.Bitmap($size, $size)
        $graphics = [Drawing.Graphics]::FromImage($bitmap)
        $path = New-Object Drawing.Drawing2D.GraphicsPath
        $family = New-Object Drawing.FontFamily('Segoe UI')
        $format = [Drawing.StringFormat]::GenericTypographic
        $matrix = New-Object Drawing.Drawing2D.Matrix
        $brush = New-Object Drawing.SolidBrush([Drawing.ColorTranslator]::FromHtml($variant.Color))
        $png = New-Object IO.MemoryStream
        try {
            $graphics.Clear([Drawing.Color]::White)
            $graphics.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
            $graphics.PixelOffsetMode = [Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $path.AddString($variant.Letter, $family, [int][Drawing.FontStyle]::Bold, [single]100, [Drawing.PointF]::Empty, $format)
            $bounds = $path.GetBounds()
            $scale = ($size * 0.78) / $bounds.Height
            $x = ($size - $bounds.Width * $scale) / 2 - $bounds.X * $scale
            $y = ($size - $bounds.Height * $scale) / 2 - $bounds.Y * $scale
            $matrix.Scale([single]$scale, [single]$scale)
            $matrix.Translate([single]$x, [single]$y, [Drawing.Drawing2D.MatrixOrder]::Append)
            $path.Transform($matrix)
            $graphics.FillPath($brush, $path)
            $bitmap.Save($png, [Drawing.Imaging.ImageFormat]::Png)
            $frames += ,$png.ToArray()
            if ($size -eq 64) { $bitmap.Save((Join-Path $assets ($variant.Name + '.png')), [Drawing.Imaging.ImageFormat]::Png) }
        } finally {
            $png.Dispose(); $brush.Dispose(); $matrix.Dispose(); $format.Dispose()
            $family.Dispose(); $path.Dispose(); $graphics.Dispose(); $bitmap.Dispose()
        }
    }
    $iconStream = [IO.File]::Create((Join-Path $assets ($variant.Name + '.ico')))
    $writer = New-Object IO.BinaryWriter($iconStream)
    try {
        $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$sizes.Count)
        $offset = 6 + 16 * $sizes.Count
        for ($i = 0; $i -lt $sizes.Count; $i++) {
            $dimension = if ($sizes[$i] -eq 256) { 0 } else { $sizes[$i] }
            $writer.Write([byte]$dimension); $writer.Write([byte]$dimension)
            $writer.Write([byte]0); $writer.Write([byte]0)
            $writer.Write([uint16]1); $writer.Write([uint16]32)
            $writer.Write([uint32]$frames[$i].Length); $writer.Write([uint32]$offset)
            $offset += $frames[$i].Length
        }
        foreach ($frame in $frames) { $writer.Write([byte[]]$frame) }
    } finally { $writer.Dispose() }
}
