#Requires -Version 5.1
param(
    [string]$OutputRoot = ""
)

$ErrorActionPreference = "Stop"
$cleanScriptRoot = $PSScriptRoot -replace '^Microsoft\.PowerShell\.Core\\FileSystem::', ''
$root = Split-Path $cleanScriptRoot -Parent
if (-not $OutputRoot) { $OutputRoot = Join-Path $root "dist" }

$src = Join-Path $root "tray-ui"
$electronDist = Join-Path $src "node_modules\electron\dist"
$dest = Join-Path $OutputRoot "AntiGrabber.Tray"

if (-not (Test-Path (Join-Path $electronDist "electron.exe"))) {
    throw "Runtime Electron não encontrado em $electronDist. Rode 'npm install' dentro de tray-ui\ primeiro."
}

if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
New-Item -ItemType Directory -Force -Path $dest | Out-Null

Write-Host "Copiando runtime Electron..." -ForegroundColor Cyan
Copy-Item "$electronDist\*" $dest -Recurse

Write-Host "Renomeando electron.exe -> AntiGrabber.Tray.exe..." -ForegroundColor Cyan
Rename-Item (Join-Path $dest "electron.exe") "AntiGrabber.Tray.exe"

$appDest = Join-Path $dest "resources\app"
Write-Host "Copiando nosso código pra resources\app\ (carregado automaticamente pelo Electron)..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $appDest | Out-Null
Copy-Item (Join-Path $src "package.json") $appDest
Copy-Item (Join-Path $src "src") $appDest -Recurse
Copy-Item (Join-Path $src "assets") $appDest -Recurse

$sizeMb = [math]::Round((Get-ChildItem $dest -Recurse | Measure-Object Length -Sum).Sum / 1MB, 1)
Write-Host "Tray empacotado em $dest ($sizeMb MB, runtime incluso)" -ForegroundColor Green
