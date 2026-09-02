#Requires -Version 5.1
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$cleanScriptRoot = $PSScriptRoot -replace '^Microsoft\.PowerShell\.Core\\FileSystem::', ''
$root = Split-Path $cleanScriptRoot -Parent

& (Join-Path $cleanScriptRoot "publish.ps1") -Configuration $Configuration
& (Join-Path $cleanScriptRoot "build-tray.ps1")

$iscc = Get-ChildItem -Path "$env:ProgramFiles\Inno Setup 6","${env:ProgramFiles(x86)}\Inno Setup 6","$env:LOCALAPPDATA\Programs\Inno Setup 6" `
    -Filter "ISCC.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName

if (-not $iscc) {
    throw "ISCC.exe (Inno Setup) não encontrado. Instale com: winget install JRSoftware.InnoSetup"
}

Write-Host "Compilando instalador com $iscc..." -ForegroundColor Cyan
& $iscc (Join-Path $root "installer\AntiGrabber.iss")
if ($LASTEXITCODE -ne 0) { throw "ISCC falhou ao compilar o instalador." }

Write-Host ""
Write-Host "Instalador gerado em dist\installer\AntiGrabberSetup.exe" -ForegroundColor Green
