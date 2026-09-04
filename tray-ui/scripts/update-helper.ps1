#Requires -Version 5.1
# Roda ELEVADO (spawnado via Start-Process -Verb RunAs pelo Tray, ver main.js runElevatedHelper).
# Para o serviço, troca os arquivos listados em manifest.json (staging -> install, com backup
# .bak), reinicia o serviço, confere que subiu. Qualquer falha restaura os .bak e tenta
# devolver o serviço ao estado anterior — nunca deixa a instalação num estado quebrado.
param(
    [Parameter(Mandatory = $true)][string]$StagingDir,
    [Parameter(Mandatory = $true)][string]$InstallDir,
    [string]$ServiceName = "AntiGrabberService"
)

$ErrorActionPreference = "Stop"
$logFile = Join-Path $env:TEMP "antigrabber-update-helper.log"
function Log([string]$msg) { "$([DateTime]::Now.ToString('u')) $msg" | Out-File -FilePath $logFile -Append -Encoding utf8 }

function Wait-ServiceState([string]$name, [string]$wantedState, [int]$timeoutSeconds = 30) {
    $deadline = (Get-Date).AddSeconds($timeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $out = (& sc.exe query $name) -join "`n"
        if ($out -match $wantedState) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

try {
    $manifestPath = Join-Path $StagingDir "manifest.json"
    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
    Log "Iniciando update para versão $($manifest.version). Staging=$StagingDir Install=$InstallDir"

    Log "Parando serviço $ServiceName..."
    & sc.exe stop $ServiceName | Out-Null
    Wait-ServiceState $ServiceName "STOPPED" 30 | Out-Null

    $backups = @()
    $failed = $false
    $failReason = ""

    foreach ($f in $manifest.files) {
        $src = Join-Path $StagingDir $f.path
        $dest = Join-Path $InstallDir $f.path
        try {
            $destDir = Split-Path $dest -Parent
            if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Force -Path $destDir | Out-Null }
            if (Test-Path $dest) {
                $bak = "$dest.bak"
                if (Test-Path $bak) { Remove-Item $bak -Force }
                Move-Item $dest $bak -Force
                $backups += [PSCustomObject]@{ Dest = $dest; Bak = $bak }
            }
            Copy-Item $src $dest -Force
            Log "Atualizado: $($f.path)"
        } catch {
            $failed = $true
            $failReason = "cópia falhou em $($f.path): $_"
            Log "ERRO: $failReason"
            break
        }
    }

    if ($failed) {
        Log "Restaurando backups por falha de cópia..."
        foreach ($b in $backups) {
            if (Test-Path $b.Bak) {
                if (Test-Path $b.Dest) { Remove-Item $b.Dest -Force }
                Move-Item $b.Bak $b.Dest -Force
            }
        }
        & sc.exe start $ServiceName | Out-Null
        Log "Update abortado, arquivos restaurados."
        exit 1
    }

    Log "Iniciando serviço..."
    & sc.exe start $ServiceName | Out-Null
    $running = Wait-ServiceState $ServiceName "RUNNING" 30

    if (-not $running) {
        Log "Serviço não subiu com a versão nova — restaurando backups..."
        & sc.exe stop $ServiceName | Out-Null
        Wait-ServiceState $ServiceName "STOPPED" 15 | Out-Null
        foreach ($b in $backups) {
            if (Test-Path $b.Bak) {
                if (Test-Path $b.Dest) { Remove-Item $b.Dest -Force }
                Move-Item $b.Bak $b.Dest -Force
            }
        }
        & sc.exe start $ServiceName | Out-Null
        Log "Rollback concluído."
        exit 1
    }

    foreach ($b in $backups) {
        if (Test-Path $b.Bak) { Remove-Item $b.Bak -Force }
    }
    Log "Update concluído com sucesso, serviço rodando."
    exit 0
} catch {
    Log "ERRO fatal: $_"
    exit 1
}
