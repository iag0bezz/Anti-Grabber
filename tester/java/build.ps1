#Requires -Version 5.1
<#
Compila o ExfilTest.java num exfil-test.jar executavel. Precisa de um JDK (javac).
Se -JdkBin nao for passado, tenta o JDK que o Prism Launcher baixa.
Uso: .\build.ps1  (ou)  .\build.ps1 -JdkBin "C:\caminho\do\jdk\bin"
#>
param([string]$JdkBin = "")

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot -replace '^Microsoft\.PowerShell\.Core\\FileSystem::', ''

if (-not $JdkBin) {
    $javac = Get-Command javac -ErrorAction SilentlyContinue
    if ($javac) {
        $JdkBin = Split-Path $javac.Source -Parent
    } else {
        $prism = Join-Path $env:APPDATA "PrismLauncher\java"
        if (Test-Path $prism) {
            $found = Get-ChildItem $prism -Recurse -Filter javac.exe -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) { $JdkBin = Split-Path $found.FullName -Parent }
        }
    }
}
if (-not $JdkBin -or -not (Test-Path (Join-Path $JdkBin "javac.exe"))) {
    throw "javac nao encontrado. Passe -JdkBin com a pasta bin de um JDK (ex: ...\PrismLauncher\java\<runtime>\bin)."
}

$javac = Join-Path $JdkBin "javac.exe"
$jar = Join-Path $JdkBin "jar.exe"
$out = Join-Path $here "out"

Write-Host "Usando JDK: $JdkBin" -ForegroundColor Cyan
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Path $out | Out-Null

& $javac -d $out (Join-Path $here "ExfilTest.java")
if ($LASTEXITCODE -ne 0) { throw "Falha ao compilar." }

& $jar --create --file (Join-Path $here "exfil-test.jar") --main-class ExfilTest -C $out .
if ($LASTEXITCODE -ne 0) { throw "Falha ao empacotar o jar." }

Remove-Item $out -Recurse -Force
Write-Host "Gerado: $(Join-Path $here 'exfil-test.jar')" -ForegroundColor Green
