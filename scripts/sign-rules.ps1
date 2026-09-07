#Requires -Version 5.1
<#
Assina docs/rules/rules.json com a chave privada RSA das public rules,
gerando docs/rules/rules.json.sig. Commitar rules.json + .sig e dar push
atualiza as regras em produção (GitHub Pages) sem precisar de update do app.

A chave privada NUNCA é commitada. Guarde-a fora do repo.
#>
param(
    [string]$RulesPath = "",
    [Parameter(Mandatory = $true)][string]$PrivateKeyPath
)

$ErrorActionPreference = "Stop"
$cleanScriptRoot = $PSScriptRoot -replace '^Microsoft\.PowerShell\.Core\\FileSystem::', ''
$root = Split-Path $cleanScriptRoot -Parent
if (-not $RulesPath) { $RulesPath = Join-Path $root "docs\rules\rules.json" }

$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) { throw "openssl não encontrado no PATH." }
if (-not (Test-Path $RulesPath)) { throw "rules.json não encontrado em $RulesPath" }
if (-not (Test-Path $PrivateKeyPath)) { throw "Chave privada não encontrada em $PrivateKeyPath" }

$sigPath = "$RulesPath.sig"
$rawSigPath = [System.IO.Path]::GetTempFileName()

try {
    & openssl dgst -sha256 -sign $PrivateKeyPath -out $rawSigPath $RulesPath
    if ($LASTEXITCODE -ne 0) { throw "Falha ao assinar $RulesPath" }

    $bytes = [System.IO.File]::ReadAllBytes($rawSigPath)
    [System.IO.File]::WriteAllText($sigPath, [System.Convert]::ToBase64String($bytes))
}
finally {
    Remove-Item $rawSigPath -ErrorAction SilentlyContinue
}

Write-Host "Assinado: $sigPath" -ForegroundColor Green
