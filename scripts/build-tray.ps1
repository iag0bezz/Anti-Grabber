#Requires -Version 5.1
param(
    [string]$Configuration = "Release",
    [string]$OutputRoot = "",
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$cleanScriptRoot = $PSScriptRoot -replace '^Microsoft\.PowerShell\.Core\\FileSystem::', ''
$root = Split-Path $cleanScriptRoot -Parent
if (-not $OutputRoot) { $OutputRoot = Join-Path $root "dist" }

$src = Join-Path $root "tray-ui"
$dest = Join-Path $OutputRoot "AntiGrabber.Tray"
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnet) { $dotnet = "C:\Program Files\dotnet\dotnet.exe" } else { $dotnet = $dotnet.Source }

if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }

Write-Host "Publicando AntiGrabber.Tray -> $dest" -ForegroundColor Cyan
$publishArgs = @(
    (Join-Path $root "AntiGrabber.Tray\AntiGrabber.Tray.csproj")
    "-c", $Configuration, "-r", "win-x64", "--self-contained", "true"
    "-p:PublishSingleFile=true", "-p:IncludeNativeLibrariesForSelfExtract=true"
    "-o", $dest
)
if ($Version) { $publishArgs += "-p:Version=$Version" }
& $dotnet publish @publishArgs
if ($LASTEXITCODE -ne 0) { throw "Falha ao publicar AntiGrabber.Tray" }

Write-Host "Copiando web (HTML/CSS/JS)..." -ForegroundColor Cyan
$webDest = Join-Path $dest "web"
if (Test-Path $webDest) { Remove-Item -Recurse -Force $webDest }
Copy-Item (Join-Path $src "src\renderer") $webDest -Recurse

Write-Host "Copiando assets (ícones)..." -ForegroundColor Cyan
$assetsDest = Join-Path $dest "assets"
if (Test-Path $assetsDest) { Remove-Item -Recurse -Force $assetsDest }
Copy-Item (Join-Path $src "assets") $assetsDest -Recurse

$sizeMb = [math]::Round((Get-ChildItem $dest -Recurse | Measure-Object Length -Sum).Sum / 1MB, 1)
Write-Host "Tray empacotado em $dest ($sizeMb MB)" -ForegroundColor Green
