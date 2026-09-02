#Requires -Version 5.1
param(
    [string]$Configuration = "Release",
    [string]$OutputRoot = ""
)

$ErrorActionPreference = "Stop"
$cleanScriptRoot = $PSScriptRoot -replace '^Microsoft\.PowerShell\.Core\\FileSystem::', ''
$root = Split-Path $cleanScriptRoot -Parent
if (-not $OutputRoot) { $OutputRoot = Join-Path $root "dist" }
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnet) { $dotnet = "C:\Program Files\dotnet\dotnet.exe" } else { $dotnet = $dotnet.Source }

$projects = @(
    @{ Name = "AntiGrabber.Service";     Path = "AntiGrabber.Service\AntiGrabber.Service.csproj" }
    @{ Name = "AntiGrabber.TestHarness"; Path = "AntiGrabber.TestHarness\AntiGrabber.TestHarness.csproj" }
)

foreach ($p in $projects) {
    $out = Join-Path $OutputRoot $p.Name
    Write-Host "Publicando $($p.Name) -> $out" -ForegroundColor Cyan
    & $dotnet publish (Join-Path $root $p.Path) `
        -c $Configuration -r win-x64 --self-contained true `
        -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
        -o $out
    if ($LASTEXITCODE -ne 0) { throw "Falha ao publicar $($p.Name)" }
}

Write-Host ""
Write-Host "IMPORTANTE: WinDivert64.sys/WinDivert.dll não vêm no pacote NuGet WindivertDotnet." -ForegroundColor Yellow
Write-Host "Baixe o redistributable oficial em https://reqrypt.org/windivert.html e copie" -ForegroundColor Yellow
Write-Host "WinDivert.dll + WinDivert64.sys (ou WinDivert32.sys em x86) para dentro de" -ForegroundColor Yellow
Write-Host "  $OutputRoot\AntiGrabber.Service\" -ForegroundColor Yellow
Write-Host "antes de rodar build-installer.ps1 / ISCC." -ForegroundColor Yellow
