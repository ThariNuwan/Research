#Requires -Version 5.1
<#
.SYNOPSIS
    Install and verify the pinned scanner toolchain from tools/scanners.lock.json.
.DESCRIPTION
    Downloads Trivy and tfsec release archives, verifies SHA256 against the
    lockfile, extracts them into tools/bin/, installs Checkov as an isolated
    uv tool, then resolves absolute executable paths into tools/resolved.json.

    Verifies rather than trusts: a checksum mismatch is a hard failure.
.PARAMETER Verify
    Re-assert an existing install without downloading. Fails if any scanner is
    missing, mismatched, or reports a version other than its pin.
#>
[CmdletBinding()]
param([switch]$Verify)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ToolsDir = Join-Path $RepoRoot 'tools'
$BinDir = Join-Path $ToolsDir 'bin'
$CacheDir = Join-Path $ToolsDir 'cache'
$LockPath = Join-Path $ToolsDir 'scanners.lock.json'
$ResolvedPath = Join-Path $ToolsDir 'resolved.json'

function Write-Step($Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok($Message) { Write-Host "    OK   $Message" -ForegroundColor Green }
function Die($Message) { Write-Host "    FAIL $Message" -ForegroundColor Red; exit 1 }

if (-not (Test-Path $LockPath)) { Die "lockfile not found: $LockPath" }
$lock = Get-Content $LockPath -Raw | ConvertFrom-Json

foreach ($dir in @($BinDir, $CacheDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
}

function Get-Sha256($Path) {
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
}

function Invoke-VersionCheck($ExePath, $VersionArgs, $Expected, $Name) {
    # PS 5.1 wraps native stderr redirected into the pipeline as error records and
    # sets $? false even on exit 0, so under the script's 'Stop' preference any
    # scanner that writes a single line to stderr during --version would abort the
    # bootstrap. Dropping the 2>&1 is not the fix: some tools print their version
    # to stderr and it must still be captured. Relax the preference around just
    # this call, then restore it.
    #
    # Relaxing the preference stops the abort but NOT the wrapping: each stderr
    # line is still an ErrorRecord, and Out-String renders those as their full
    # formatted diagnostic - "At <this file>:<line> char:<col>", the caret line,
    # CategoryInfo, FullyQualifiedErrorId. Observed on tfsec 1.28.14, whose
    # "joining the Trivy family" banner goes to stderr: 658 captured chars of
    # which 272 described bootstrap.ps1's own source, written verbatim into
    # resolved.json's version_output and reading exactly like a crash. Unwrap
    # each record to its message text; 386 clean chars, pin still matched.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = & $ExePath @VersionArgs 2>&1 |
            ForEach-Object {
                if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { $_ }
            } | Out-String
    }
    finally { $ErrorActionPreference = $previous }
    if ($raw -notmatch [regex]::Escape($Expected)) {
        Die "$Name reports a version not matching pin '$Expected'. Raw output: $($raw.Trim())"
    }
    Write-Ok "$Name $Expected"
    return $raw.Trim()
}

function Install-ReleaseBinary($Name, $Entry) {
    $exePath = Join-Path $BinDir $Entry.exe
    $archiveName = Split-Path $Entry.url -Leaf
    $archivePath = Join-Path $CacheDir $archiveName

    if (-not (Test-Path $exePath)) {
        if ($Verify) { Die "$Name not installed at $exePath (run bootstrap without -Verify)" }

        if (-not (Test-Path $archivePath)) {
            Write-Step "downloading $Name $($Entry.version)"
            # TLS 1.2 is not the PS 5.1 default on all hosts.
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $Entry.url -OutFile $archivePath -UseBasicParsing
        }

        $actual = Get-Sha256 $archivePath
        if ($actual -ne $Entry.sha256.ToLower()) {
            Remove-Item $archivePath -Force
            Die "$Name checksum mismatch. expected $($Entry.sha256) got $actual (archive deleted)"
        }
        Write-Ok "$Name checksum verified"

        Write-Step "extracting $Name"
        if ($Entry.archive -eq 'zip') {
            Expand-Archive -Path $archivePath -DestinationPath $BinDir -Force
        }
        elseif ($Entry.archive -eq 'targz') {
            # Out-Host, not bare: this function returns a hashtable, and native
            # stdout emitted inside it would be folded into that return value,
            # turning it into an array and corrupting resolved.json's shape.
            & tar -xzf $archivePath -C $BinDir | Out-Host
            if ($LASTEXITCODE -ne 0) { Die "tar failed to extract $archiveName" }
        }
        else { Die "unknown archive type '$($Entry.archive)' for $Name" }

        if (-not (Test-Path $exePath)) { Die "$Name extracted but $($Entry.exe) not found in $BinDir" }
    }
    else {
        # Re-verify the cached archive when it is still present.
        if (Test-Path $archivePath) {
            $actual = Get-Sha256 $archivePath
            if ($actual -ne $Entry.sha256.ToLower()) { Die "$Name cached archive checksum drifted" }
            Write-Ok "$Name checksum verified"
        }
    }

    $raw = Invoke-VersionCheck $exePath $Entry.version_args $Entry.version $Name
    return @{ exe = (Resolve-Path $exePath).Path; version = $Entry.version; version_output = $raw }
}

function Install-UvTool($Name, $Entry) {
    # No PATH search here, deliberately. Two observed facts rule it out:
    #
    #  1. checkov 3.3.12 declares no console_scripts entry point - its dist-info
    #     carries no entry_points.txt, only the wheel data scripts
    #     Scripts/checkov and Scripts/checkov.cmd - so no checkov.exe trampoline
    #     exists for uv (or pip) to install anywhere.
    #  2. Upstream's checkov.cmd resolves `python` from PATH instead of from the
    #     tool venv. On a Windows host carrying the Microsoft Store
    #     app-execution alias that is the stub: observed exit 9009, "Python was
    #     not found". A PATH lookup would find precisely that broken launcher,
    #     and `Get-Command checkov -CommandType Application` returns *two*
    #     matches here (checkov.cmd and checkov), so .Source would be an array.
    #
    # Resolve the isolated tool venv instead and generate a launcher pinned to
    # its own interpreter. That keeps resolved.json's contract at exactly one
    # absolute, directly invocable path per scanner, and makes the isolation the
    # lockfile claims real rather than PATH-dependent.
    #
    # Assigned, not left in the pipeline: this function returns a hashtable, and
    # native stdout emitted inside it would be folded into that return value.
    $toolRoot = (& uv tool dir | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { Die "uv tool dir failed" }

    $venvScripts = Join-Path $toolRoot "$Name\Scripts"
    $venvPython = Join-Path $venvScripts 'python.exe'
    $venvScript = Join-Path $venvScripts $Entry.script

    if (-not ((Test-Path $venvPython) -and (Test-Path $venvScript))) {
        if ($Verify) { Die "$Name not installed (run bootstrap without -Verify)" }
        Write-Step "installing $Name $($Entry.version) as an isolated uv tool"
        & uv tool install $Entry.package --python $Entry.python | Out-Host
        if ($LASTEXITCODE -ne 0) { Die "uv tool install $($Entry.package) failed" }
        if (-not (Test-Path $venvPython)) { Die "$Name installed but interpreter not found at $venvPython" }
        if (-not (Test-Path $venvScript)) { Die "$Name installed but script not found at $venvScript" }
    }

    # Regenerated on every run, -Verify included: it is our own glue over the
    # tool venv, not part of the install being verified, and rewriting identical
    # bytes keeps it from drifting away from the interpreter it wraps.
    $shimPath = Join-Path $BinDir $Entry.exe
    $body = @(
        '@echo off',
        'REM Generated by tools/bootstrap.ps1 - do not edit; tools/bin/ is gitignored.',
        "`"$venvPython`" `"$venvScript`" %*",
        'exit /b %ERRORLEVEL%'
    ) -join "`r`n"
    # CRLF and no BOM: cmd.exe mis-parses a batch file that opens with a BOM.
    [System.IO.File]::WriteAllText($shimPath, "$body`r`n", (New-Object System.Text.UTF8Encoding $false))
    Write-Ok "$Name launcher pinned to $venvPython"

    $raw = Invoke-VersionCheck $shimPath $Entry.version_args $Entry.version $Name
    return @{ exe = (Resolve-Path $shimPath).Path; version = $Entry.version; version_output = $raw }
}

$resolved = @{}
foreach ($name in $lock.scanners.PSObject.Properties.Name) {
    $entry = $lock.scanners.$name
    Write-Step "$name ($($entry.channel))"
    if ($entry.channel -eq 'github-release') {
        $resolved[$name] = Install-ReleaseBinary $name $entry
    }
    elseif ($entry.channel -eq 'uv-tool') {
        $resolved[$name] = Install-UvTool $name $entry
    }
    else { Die "unknown channel '$($entry.channel)' for $name" }
}

# Out-File -Encoding utf8 is UTF-8 *with* BOM in PS 5.1. ConvertFrom-Json
# tolerates the BOM, so the break would not surface here - it would surface in
# Task 7's provenance builder as json.loads raising "Unexpected UTF-8 BOM".
$json = $resolved | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($ResolvedPath, $json, (New-Object System.Text.UTF8Encoding $false))
Write-Host ""
Write-Host "All scanners verified. Resolved paths -> tools/resolved.json" -ForegroundColor Green
