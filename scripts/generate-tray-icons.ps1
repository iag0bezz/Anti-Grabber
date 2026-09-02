#Requires -Version 5.1
Add-Type -AssemblyName System.Drawing

function New-CircleIcon {
    param([string]$OutPath, [string]$HexColor, [int]$Size = 256)

    $color = [System.Drawing.ColorTranslator]::FromHtml($HexColor)
    $bitmap = New-Object System.Drawing.Bitmap($Size, $Size)
    $g = [System.Drawing.Graphics]::FromImage($bitmap)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)
    $pad = [int]($Size * 0.06)
    $brush = New-Object System.Drawing.SolidBrush($color)
    $g.FillEllipse($brush, $pad, $pad, $Size - 2 * $pad, $Size - 2 * $pad)
    $g.Dispose()

    $ms = New-Object System.IO.MemoryStream
    $bitmap.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)

    $icoBytes = New-Object System.Collections.Generic.List[byte]
    $icoBytes.AddRange([byte[]]@(0,0, 1,0, 1,0))
    $pngBytes = $ms.ToArray()
    $wByte = if ($Size -ge 256) { 0 } else { $Size }
    $icoBytes.AddRange([byte[]]@($wByte, $wByte, 0, 0, 1,0, 32,0))
    $icoBytes.AddRange([BitConverter]::GetBytes([int]$pngBytes.Length))
    $icoBytes.AddRange([BitConverter]::GetBytes([int]22))
    $icoBytes.AddRange($pngBytes)

    [System.IO.File]::WriteAllBytes($OutPath, $icoBytes.ToArray())
    $bitmap.Dispose()
    Write-Host "Gerado: $OutPath"
}

$assets = Join-Path $PSScriptRoot "..\tray-ui\assets"
New-Item -ItemType Directory -Force -Path $assets | Out-Null

New-CircleIcon -OutPath (Join-Path $assets "tray-idle.ico") -HexColor "#8E8E93" -Size 32
New-CircleIcon -OutPath (Join-Path $assets "tray-active.ico") -HexColor "#2FA84F" -Size 32
New-CircleIcon -OutPath (Join-Path $assets "tray-block.ico") -HexColor "#D63A3A" -Size 32
New-CircleIcon -OutPath (Join-Path $assets "app.ico") -HexColor "#2FA84F" -Size 256

Write-Host "Ícones gerados em $assets"
