<#
    Build the portable Windows distribution published with each release.

    Produces one ZIP holding a private CPython runtime and the tool. Extract it
    anywhere - a USB stick, an evidence workstation, an air-gapped analysis host
    - and run it. Nothing is installed, nothing touches the registry, and no
    Python is needed on the target machine.

    Run by .github/workflows/release.yml. It works locally too:

        pwsh .github/scripts/build_portable.ps1
        pwsh .github/scripts/build_portable.ps1 -PythonVersion 3.13.9

    The runtime is the official python.org embeddable build, downloaded at build
    time and recorded in the package by SHA-256 so the result can be checked
    against python.org independently.
#>

[CmdletBinding()]
param(
    [string]$PythonVersion = '3.14.7',
    # Resolved in the body, not as a default. A default referencing $PSScriptRoot
    # is evaluated before that variable is populated when the script is invoked
    # by a relative path, which silently expands to the root of the current
    # drive - the build then succeeds and leaves the package somewhere nobody
    # looks.
    [string]$OutputDir = '',
    [switch]$NoVerify
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$AppName = 'WGF'

function Say  { param($m) Write-Host "  $m" }
function Ok   { param($m) Write-Host "  $m" -ForegroundColor Green }
function Note { param($m) Write-Host "  $m" -ForegroundColor DarkGray }
function Die  { param($m) Write-Host "  $m" -ForegroundColor Red; exit 1 }

# --------------------------------------------------------------- locate
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $here) { Die 'Cannot determine the script directory.' }

$Root = $null
$probe = (Resolve-Path $here).Path
for ($i = 0; $i -lt 5 -and $probe; $i++) {
    if (Test-Path (Join-Path $probe 'wifigeo\__init__.py')) { $Root = $probe; break }
    $probe = Split-Path -Parent $probe
}
if (-not $Root) { Die 'Cannot find the project root (no wifigeo\__init__.py above this script).' }

if (-not $OutputDir) { $OutputDir = Join-Path $Root 'dist' }
$Staging  = Join-Path ([IO.Path]::GetTempPath()) ("wgf-build-" + [Guid]::NewGuid().ToString('N'))
$CacheDir = Join-Path ([IO.Path]::GetTempPath()) 'wgf-runtime-cache'

$verText  = Get-Content (Join-Path $Root 'wifigeo\__init__.py') -Raw
$verMatch = [regex]::Matches($verText, '__version__\s*=\s*[''"]([^''"]+)[''"]')
if ($verMatch.Count -eq 0) { Die 'Cannot read __version__ from wifigeo\__init__.py.' }
$AppVersion = $verMatch[0].Groups[1].Value

Say "Project root    : $Root"
Say "Tool version    : $AppVersion"
Say "Python runtime  : $PythonVersion (embeddable, amd64)"

# --------------------------------------------------------------- download
if (-not (Test-Path $CacheDir)) { $null = New-Item -ItemType Directory $CacheDir -Force }
$embedName = "python-$PythonVersion-embed-amd64.zip"
$embedZip  = Join-Path $CacheDir $embedName
$embedUrl  = "https://www.python.org/ftp/python/$PythonVersion/$embedName"

if (Test-Path $embedZip) {
    Note "Using cached $embedName"
} else {
    Say "Downloading $embedUrl"
    try {
        Invoke-WebRequest -Uri $embedUrl -OutFile $embedZip -UseBasicParsing
    } catch {
        Die ("Download failed: " + $_.Exception.Message +
             "`n  Check the version exists at https://www.python.org/ftp/python/")
    }
}
$embedHash = (Get-FileHash $embedZip -Algorithm SHA256).Hash.ToLower()
Ok ("Runtime archive : {0:N1} MB  sha256 {1}..." -f ((Get-Item $embedZip).Length / 1MB), $embedHash.Substring(0, 16))

# ---------------------------------------------------------------- stage
$null   = New-Item -ItemType Directory $Staging -Force
$appDir = Join-Path $Staging $AppName
$runtime = Join-Path $appDir 'runtime'
$null   = New-Item -ItemType Directory $runtime -Force

Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::ExtractToDirectory($embedZip, $runtime)
Ok 'Runtime extracted'

# Make the runtime able to see the application, which sits one level up.
$pthName = "python$($PythonVersion.Split('.')[0])$($PythonVersion.Split('.')[1])._pth"
$pth = Join-Path $runtime $pthName
if (-not (Test-Path $pth)) {
    $pth = Get-ChildItem $runtime -Filter '*._pth' | Select-Object -First 1 -ExpandProperty FullName
}
if ($null -eq $pth) { Die 'No ._pth file in the embeddable runtime; cannot set the import path.' }
$stdlibZip = (Get-ChildItem $runtime -Filter 'python*.zip' | Select-Object -First 1).Name
@(
    $stdlibZip
    '.'
    '..'
    ''
    '# The application is imported as a package from the parent directory.'
) | Set-Content -Path $pth -Encoding ascii
Note "Import path set via $(Split-Path $pth -Leaf)"

# --- copy the application -------------------------------------------------
Copy-Item (Join-Path $Root 'wifigeo') (Join-Path $appDir 'wifigeo') -Recurse

# Bytecode is stripped just before packaging rather than here, because the
# verification below imports the package and would write it straight back.
# The probes also run with -B so there is nothing to strip in the first place.

foreach ($doc in @('README.md', 'LICENSE', 'CHANGELOG.md')) {
    $p = Join-Path $Root $doc
    if (Test-Path $p) { Copy-Item $p $appDir }
}
$null = New-Item -ItemType Directory (Join-Path $appDir 'evidence') -Force
Set-Content -Path (Join-Path $appDir 'evidence\README.txt') -Encoding utf8 -Value @'
Evidence packages are written here by default.

Each investigation produces:
  <CASE-ID>/                 the working case directory
  <CASE-ID>_EVIDENCE.zip     the sealed, hash-verified evidence package
  <CASE-ID>_REPORT.html      the report, openable in any browser

To verify a package, extract it and run  py verify_evidence.py  from
inside the case directory.
'@
Ok 'Application copied'

# --- launchers ------------------------------------------------------------
Set-Content -Path (Join-Path $appDir 'WGF.cmd') -Encoding ascii -Value @'
@echo off
rem Launch the WGF interface. Opens a browser on a loopback-only server.
setlocal
cd /d "%~dp0"
"%~dp0runtime\python.exe" -m wifigeo %*
if errorlevel 1 (
  echo.
  echo WGF exited with an error. Press any key to close.
  pause >nul
)
'@

Set-Content -Path (Join-Path $appDir 'WGF-CLI.cmd') -Encoding ascii -Value @'
@echo off
rem Run a single enquiry without the interface.
rem   WGF-CLI.cmd --bssid 00:00:5e:00:53:a6
rem   WGF-CLI.cmd --scan
setlocal
cd /d "%~dp0"
"%~dp0runtime\python.exe" -m wifigeo --cli %*
pause
'@

Set-Content -Path (Join-Path $appDir 'START-HERE.txt') -Encoding utf8 -Value @"
$AppName $AppVersion - WiFi Geolocation Forensics
=================================================

PORTABLE. Nothing is installed. Extract anywhere and run.

  WGF.cmd                            Open the interface in your browser.
  WGF-CLI.cmd --bssid <address>      Run one enquiry from the command line.
  WGF-CLI.cmd --scan                 List the networks the radio can see.

WHAT IT DOES
  Resolves a Wi-Fi access point address to a geographic position using two
  independent, credential-free positioning databases (Apple and Microsoft),
  cross-validates them against each other, enriches the result with
  OpenStreetMap data, and seals everything it touched into a hash-verified
  evidence package with a printable report.

  No API keys. No accounts. No configuration.

REQUIREMENTS
  64-bit Windows. Internet access for the positioning lookups.
  A wireless adapter only if you want to scan locally; addresses supplied by
  hand or read from a saved scan work without one.

BUILD PROVENANCE
  Runtime  : CPython $PythonVersion (official python.org embeddable build)
  SHA-256  : $embedHash
  Built    : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
  Packages : none - WGF uses only the Python standard library

  Check the runtime against python.org yourself:
  https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip
"@
Ok 'Launchers written'

# --------------------------------------------------------------- verify
if (-not $NoVerify) {
    Say 'Verifying the built runtime...'
    $py = Join-Path $runtime 'python.exe'

    $probe = & $py -B -m wifigeo --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ($probe | Out-String) -ForegroundColor Red
        Die 'The built distribution failed to start.'
    }
    Ok ('Smoke test      : ' + ($probe | Select-Object -First 1))

    # The parts that need native modules: TLS to the providers, ctypes for the
    # radio scanner, hashlib for evidence sealing, http.server for the UI.
    $modProbe = & $py -B -c "import ssl,ctypes,socket,hashlib,zipfile,http.server; from wifigeo import apple,msft,scan,geo,report,ingest,evidence,etl; print('modules ok')" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ($modProbe | Out-String) -ForegroundColor Red
        Die 'A required module is missing from the runtime.'
    }
    Ok ('Module test     : ' + ($modProbe | Select-Object -First 1))

    # A wheel that ships without its interface installs a tool whose UI 404s on
    # every request. That has shipped once; this is why it cannot ship again.
    $uiProbe = & $py -B -c "import os,sys; from wifigeo import app; need={'index.html','app.css','app.js'}; have=set(os.listdir(app.WEB_DIR)) if os.path.isdir(app.WEB_DIR) else set(); missing=sorted(need-have); sys.exit('missing web assets: %s' % missing) if missing else print('ui ok')" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ($uiProbe | Out-String) -ForegroundColor Red
        Die 'The portable build is missing its web interface.'
    }
    Ok ('Interface test  : ' + ($uiProbe | Select-Object -First 1))
}

# ---------------------------------------------------------------- package
# Last thing before the archive: nothing after this point can put it back.
Get-ChildItem $appDir -Recurse -Include '__pycache__', '*.pyc' -Force |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
$stray = Get-ChildItem $appDir -Recurse -Force |
    Where-Object { $_.Name -eq '__pycache__' -or $_.Extension -eq '.pyc' }
if ($stray) { Die ('Bytecode survived the strip: ' + ($stray[0].FullName)) }
Ok 'Bytecode stripped'

if (-not (Test-Path $OutputDir)) { $null = New-Item -ItemType Directory $OutputDir -Force }
$zipPath = Join-Path $OutputDir ("{0}-{1}-win64.zip" -f $AppName, $AppVersion)
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

[IO.Compression.ZipFile]::CreateFromDirectory(
    $Staging, $zipPath, [IO.Compression.CompressionLevel]::Optimal, $false)

$zipInfo   = Get-Item $zipPath
$zipHash   = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
$fileCount = (Get-ChildItem $appDir -Recurse -File).Count
$rawSize   = ((Get-ChildItem $appDir -Recurse -File) | Measure-Object Length -Sum).Sum

Remove-Item $Staging -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
Ok 'Build complete'
Write-Host  '  ------------------------------------------------------------'
Write-Host ('  Package    : ' + $zipPath)
Write-Host ('  Size       : {0:N1} MB compressed, {1:N1} MB extracted' -f ($zipInfo.Length / 1MB), ($rawSize / 1MB))
Write-Host ('  Files      : {0:N0}' -f $fileCount)
Write-Host ('  SHA-256    : ' + $zipHash)
Write-Host ('  Runtime    : CPython ' + $PythonVersion)
Write-Host  '  Third-party dependencies: none'

if ($env:GITHUB_OUTPUT) {
    "zip=$zipPath"          | Out-File $env:GITHUB_OUTPUT -Append -Encoding utf8
    "name=$(Split-Path $zipPath -Leaf)" | Out-File $env:GITHUB_OUTPUT -Append -Encoding utf8
    "version=$AppVersion"   | Out-File $env:GITHUB_OUTPUT -Append -Encoding utf8
    "sha256=$zipHash"       | Out-File $env:GITHUB_OUTPUT -Append -Encoding utf8
    "runtime=$PythonVersion" | Out-File $env:GITHUB_OUTPUT -Append -Encoding utf8
}
