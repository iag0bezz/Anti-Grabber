#Requires -Version 5.1
# Baixa o redistributable oficial do WinDivert (driver de rede usado pelo NetworkFilterWorker)
# e copia DLL + driver x64 pra dentro de dist\AntiGrabber.Service\. Idempotente: pula o
# download se os arquivos já estiverem lá. URL e hash fixados numa versão conhecida — falha
# alto se o hash não bater, em vez de aceitar um binário adulterado silenciosamente.
param(
    [string]$OutputRoot = ""
)

$ErrorActionPreference = "Stop"
$cleanScriptRoot = $PSScriptRoot -replace '^Microsoft\.PowerShell\.Core\\FileSystem::', ''
$root = Split-Path $cleanScriptRoot -Parent
if (-not $OutputRoot) { $OutputRoot = Join-Path $root "dist" }

$serviceDist = Join-Path $OutputRoot "AntiGrabber.Service"
$dllDest = Join-Path $serviceDist "WinDivert.dll"
$sysDest = Join-Path $serviceDist "WinDivert64.sys"

if ((Test-Path $dllDest) -and (Test-Path $sysDest)) {
    Write-Host "WinDivert já presente em $serviceDist — pulando download." -ForegroundColor Cyan
    return
}

$version = "2.2.2"
$url = "https://github.com/basil00/WinDivert/releases/download/v$version/WinDivert-$version-A.zip"
$expectedSha256 = "63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15"

$zipPath = Join-Path ([System.IO.Path]::GetTempPath()) "WinDivert-$version-A.zip"
Write-Host "Baixando WinDivert $version..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $url -OutFile $zipPath -UserAgent "antigrabber-build"

$actualSha256 = (Get-FileHash $zipPath -Algorithm SHA256).Hash
if ($actualSha256 -ne $expectedSha256) {
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    throw "SHA256 do WinDivert-$version-A.zip não bate. Esperado $expectedSha256, obtido $actualSha256 — download pode estar comprometido."
}

$extractDir = Join-Path ([System.IO.Path]::GetTempPath()) "WinDivert-$version-extract"
if (Test-Path $extractDir) { Remove-Item -Recurse -Force $extractDir }
Expand-Archive -Path $zipPath -DestinationPath $extractDir

New-Item -ItemType Directory -Force -Path $serviceDist | Out-Null
Copy-Item (Join-Path $extractDir "WinDivert-$version-A\x64\WinDivert.dll") $dllDest -Force
Copy-Item (Join-Path $extractDir "WinDivert-$version-A\x64\WinDivert64.sys") $sysDest -Force

Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $extractDir -ErrorAction SilentlyContinue

Write-Host "WinDivert $version copiado pra $serviceDist" -ForegroundColor Green
