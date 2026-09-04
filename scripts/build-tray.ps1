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
$trayExe = Join-Path $dest "AntiGrabber.Tray.exe"
Rename-Item (Join-Path $dest "electron.exe") "AntiGrabber.Tray.exe"

$appIcon = Join-Path $src "assets\app.ico"
$rcedit = Join-Path $src "node_modules\rcedit\bin\rcedit-x64.exe"
if ((Test-Path $rcedit) -and (Test-Path $appIcon)) {
    Write-Host "Aplicando ícone da AntiGrabber ao executável..." -ForegroundColor Cyan
    & $rcedit $trayExe --set-icon $appIcon
    if ($LASTEXITCODE -ne 0) { throw "rcedit falhou ao trocar o ícone de $trayExe" }
} else {
    Write-Host "rcedit ou assets\app.ico não encontrados — ícone padrão do Electron mantido (rode 'npm install' em tray-ui\)." -ForegroundColor Yellow
}

$appDest = Join-Path $dest "resources\app"
Write-Host "Copiando nosso código pra resources\app\ (carregado automaticamente pelo Electron)..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $appDest | Out-Null
Copy-Item (Join-Path $src "package.json") $appDest
Copy-Item (Join-Path $src "src") $appDest -Recurse
Copy-Item (Join-Path $src "assets") $appDest -Recurse

$scriptsDest = Join-Path $appDest "scripts"
New-Item -ItemType Directory -Force -Path $scriptsDest | Out-Null
Copy-Item (Join-Path $src "scripts\update-helper.ps1") $scriptsDest

$sizeMb = [math]::Round((Get-ChildItem $dest -Recurse | Measure-Object Length -Sum).Sum / 1MB, 1)
Write-Host "Tray empacotado em $dest ($sizeMb MB, runtime incluso)" -ForegroundColor Green
