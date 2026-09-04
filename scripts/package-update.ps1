#Requires -Version 5.1
# Empacota um update leve (Service.exe + código do Tray, sem runtime Electron nem WinDivert)
# num zip + manifest.json com sha256 por arquivo. Rodar depois de publish.ps1/build-tray.ps1
# (precisa de dist\AntiGrabber.Service\AntiGrabber.Service.exe já publicado).
param(
    [string]$OutputRoot = "",
    [Parameter(Mandatory = $true)][string]$Version
)

$ErrorActionPreference = "Stop"
$cleanScriptRoot = $PSScriptRoot -replace '^Microsoft\.PowerShell\.Core\\FileSystem::', ''
$root = Split-Path $cleanScriptRoot -Parent
if (-not $OutputRoot) { $OutputRoot = Join-Path $root "dist" }

$serviceExe = Join-Path $OutputRoot "AntiGrabber.Service\AntiGrabber.Service.exe"
if (-not (Test-Path $serviceExe)) {
    throw "Service.exe não encontrado em $serviceExe — rode publish.ps1 primeiro."
}

$updateDir = Join-Path $OutputRoot "update"
if (Test-Path $updateDir) { Remove-Item -Recurse -Force $updateDir }
New-Item -ItemType Directory -Force -Path $updateDir | Out-Null

Write-Host "Copiando Service.exe..." -ForegroundColor Cyan
$serviceDest = Join-Path $updateDir "Service"
New-Item -ItemType Directory -Force -Path $serviceDest | Out-Null
Copy-Item $serviceExe $serviceDest

Write-Host "Copiando código do Tray..." -ForegroundColor Cyan
$trayAppDest = Join-Path $updateDir "Tray\resources\app"
New-Item -ItemType Directory -Force -Path $trayAppDest | Out-Null
Copy-Item (Join-Path $root "tray-ui\src") $trayAppDest -Recurse
Copy-Item (Join-Path $root "tray-ui\assets") $trayAppDest -Recurse
Copy-Item (Join-Path $root "tray-ui\package.json") $trayAppDest

Write-Host "Gerando manifest.json..." -ForegroundColor Cyan
$files = Get-ChildItem $updateDir -Recurse -File
$manifestFiles = foreach ($f in $files) {
    $rel = $f.FullName.Substring($updateDir.Length + 1) -replace '\\', '/'
    [PSCustomObject]@{
        path   = $rel
        sha256 = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
    }
}
$manifest = [PSCustomObject]@{ version = $Version; files = $manifestFiles }
$manifest | ConvertTo-Json -Depth 5 | Out-File (Join-Path $updateDir "manifest.json") -Encoding utf8

$installerDir = Join-Path $OutputRoot "installer"
New-Item -ItemType Directory -Force -Path $installerDir | Out-Null
$zipPath = Join-Path $installerDir "AntiGrabberUpdate-$Version.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path (Join-Path $updateDir "*") -DestinationPath $zipPath

$hash = (Get-FileHash $zipPath -Algorithm SHA256).Hash
"$hash  $(Split-Path $zipPath -Leaf)" | Out-File "$zipPath.sha256" -Encoding ascii

$sizeMb = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
Write-Host "Pacote de update gerado em $zipPath ($sizeMb MB)" -ForegroundColor Green
