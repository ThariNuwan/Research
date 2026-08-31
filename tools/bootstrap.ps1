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
# Failures go to stderr, not to the host: Write-Host reaches an interactive
# console but not a caller capturing stderr, which would see a bare exit 1 with
# no reason given. Written straight to the error stream rather than via
# Write-Error so the message stays a single line and does not acquire a
# PowerShell diagnostic wrapper of its own.
function Die($Message) { [Console]::Error.WriteLine("    FAIL $Message"); exit 1 }

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
    # The save/restore below is strictly redundant: an assignment inside a
    # function creates a function-scoped variable, so the script scope's value
    # was never at risk and the local dies with the call. Kept deliberately.
    # This is the one function in the file whose scoping subtleties have already
    # produced a live defect, and trading defensive clarity for two lines here is
    # a bad bargain.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = & $ExePath @VersionArgs 2>&1 |
            ForEach-Object {
                if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { $_ }
            } | Out-String
        # Captured immediately, still inside the try: $LASTEXITCODE is global, so
        # the next native invocation anywhere in the script overwrites it.
        $exit = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previous }

    # A scanner that prints its pinned version and then crashes is not a verified
    # scanner: the match below is a substring test over merged stdout+stderr, so
    # a Go panic or a dying interpreter after the version banner would pass it.
    # Checked before the match, and with no per-scanner exemption - trivy, tfsec
    # and the generated checkov.cmd each exit 0 on --version, tfsec while writing
    # its entire banner to stderr. This also makes the function consistent with
    # the three other $LASTEXITCODE checks in this file, which is the anomaly
    # that flagged it: the one native call whose result is the script's actual
    # verdict was the one left unchecked.
    if ($exit -ne 0) {
        Die "$Name --version exited $exit (expected 0). Output: $($raw.Trim())"
    }
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

    # An optional integrity check is not an integrity check, so a github-release
    # entry with no exe_sha256 is a lockfile defect and stops the run - it is
    # never a licence to skip the comparison below. Checked here, before any
    # download, so the defect costs nothing. Tested for by name because
    # Set-StrictMode turns a missing property into a PropertyNotFound error,
    # which would report the wrong problem.
    if ($Entry.PSObject.Properties.Name -notcontains 'exe_sha256') {
        Die "$Name has no exe_sha256 in $LockPath. Refusing to install or verify an executable the lockfile does not pin."
    }

    if (-not (Test-Path $exePath)) {
        if ($Verify) { Die "$Name not installed at $exePath (run bootstrap without -Verify)" }

        if (-not (Test-Path $archivePath)) {
            Write-Step "downloading $Name $($Entry.version)"
            # TLS 1.2 is not the PS 5.1 default on all hosts.
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $Entry.url -OutFile $archivePath -UseBasicParsing

            # A truncated or empty transfer is a download failure, not a content
            # mismatch. Left to the checksum below it reports "checksum
            # mismatch", which invites the worst possible repair: pasting the
            # observed hash over the pin.
            if (-not (Test-Path $archivePath)) {
                Die "$Name download produced no file at $archivePath (download failed, not a checksum mismatch)"
            }
            if ((Get-Item $archivePath).Length -eq 0) {
                Remove-Item $archivePath -Force
                Die "$Name download produced a zero-byte $archiveName (download failed, not a checksum mismatch)"
            }
        }

        $actual = Get-Sha256 $archivePath
        if ($actual -ne $Entry.sha256.ToLower()) {
            Remove-Item $archivePath -Force
            Die "$Name checksum mismatch. expected $($Entry.sha256) got $actual (archive deleted)"
        }
        Write-Ok "$Name archive checksum verified"

        Write-Step "extracting $Name"
        if ($Entry.archive -eq 'zip') {
            Expand-Archive -Path $archivePath -DestinationPath $BinDir -Force
        }
        elseif ($Entry.archive -eq 'targz') {
            # Windows 10 1803+ ships bsdtar as C:\Windows\System32\tar.exe, but
            # say so rather than assume: under the script's 'Stop' preference an
            # absent tar becomes a raw PowerShell terminating error and is the
            # one failure in this file that would print no FAIL line.
            if ($null -eq (Get-Command tar -CommandType Application -ErrorAction SilentlyContinue)) {
                Die "tar not found on PATH, needed to extract $archiveName. Windows 10 1803+ ships it as C:\Windows\System32\tar.exe; install bsdtar or add System32 to PATH."
            }
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
        # Re-verify the cached archive when it is still present. This is an
        # acquisition-time check and is *additional* to the executable hash
        # below, never a substitute: tools/cache/ is gitignored and disposable,
        # so this branch can legitimately find nothing to compare.
        if (Test-Path $archivePath) {
            $actual = Get-Sha256 $archivePath
            if ($actual -ne $Entry.sha256.ToLower()) { Die "$Name cached archive checksum drifted" }
            Write-Ok "$Name archive checksum verified"
        }
    }

    # The check that makes "verified" mean verified. Hashing the archive proves
    # the download was authentic; it proves nothing about the binary now sitting
    # in tools/bin/, which is what Task 8 executes and Task 7 records. So the
    # executable is hashed unconditionally, on both branches and in both modes:
    #
    #  - one call site after the branches converge, not one inside each, so no
    #    future branch can be added that skips it;
    #  - on the extract path it runs after extraction, catching a corrupted
    #    unpack that a valid archive hash cannot detect;
    #  - on the already-installed path it is the *only* integrity comparison
    #    when tools/cache/ has been cleared, which is exactly the hole that let
    #    -Verify print "All scanners verified" having compared nothing.
    #
    # Before Invoke-VersionCheck, deliberately: a binary that fails its hash
    # must never be executed, not even to ask it its own version - and a version
    # string a binary prints about itself is not evidence of anything.
    $actualExe = Get-Sha256 $exePath
    if ($actualExe -ne $Entry.exe_sha256.ToLower()) {
        Die "$Name executable checksum mismatch at $exePath. expected $($Entry.exe_sha256) got $actualExe"
    }
    Write-Ok "$Name executable checksum verified"

    $raw = Invoke-VersionCheck $exePath $Entry.version_args $Entry.version $Name
    return [ordered]@{ exe = (Resolve-Path $exePath).Path; version = $Entry.version; version_output = $raw }
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
    #
    # ---------------------------------------------------------------------
    # Why this channel carries no exe_sha256, unlike github-release
    # ---------------------------------------------------------------------
    # A reasoned exemption, not an oversight. checkov's `exe` is the .cmd this
    # function *generates*, and its body embeds the absolute path of this host's
    # tool-venv interpreter. Its hash is therefore host-specific and changes
    # legitimately on every machine, so a pinned digest would be wrong
    # everywhere except the machine that recorded it - a check that fails for
    # correct installs teaches people to delete checks.
    #
    # checkov's integrity rests on four other things instead:
    #
    #  1. the exact `checkov==3.3.12` pin in the lockfile, resolved by uv, which
    #     is what actually decides the code that gets installed;
    #  2. the tool venv's own interpreter and script both existing at the paths
    #     uv's layout implies (the Die pair below) - a missing either means the
    #     install is not what the lockfile describes;
    #  3. the -Verify content comparison further down: the launcher on disk must
    #     equal the launcher the lockfile and the resolved tool venv imply, so a
    #     launcher repointed at a different interpreter is reported, not healed;
    #  4. the version check, which runs the launcher and requires 3.3.12.
    #
    # What this does NOT cover, stated plainly rather than glossed: nothing here
    # hashes checkov's installed Python code. That would need a uv-side
    # attestation (a locked wheel digest) which this channel does not surface.
    # The gap is the reason (1)-(4) are enumerated rather than assumed.
    $toolRoot = (& uv tool dir | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { Die "uv tool dir failed" }

    # uv names the tool venv after the *package*, not after our lockfile key. The
    # two coincide today only because the key `checkov` happens to equal the
    # distribution name; for any tool whose key differed, keying off $Name would
    # produce a confusing "not installed" on a tool that is installed. Split the
    # version pin off the package spec instead.
    $distName = ($Entry.package -split '==')[0]

    # <uv tool dir>/<dist>/Scripts/ is a uv *internal* layout, not a documented
    # contract, so a uv upgrade could move it. The two existence checks below are
    # what make relying on it safe: they fail loudly and name the exact path, so a
    # layout change is reported as itself rather than mistaken for a missing tool.
    $venvScripts = Join-Path $toolRoot "$distName\Scripts"
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

    # One source of truth for the content, one branch on mode. This refines
    # Ruling F25 rather than overturning it: F25 wanted the launcher never to
    # drift from the interpreter it wraps, and rewriting it blindly does not
    # achieve that - it *conceals* drift. The one tampering -Verify could
    # plausibly catch, a launcher repointed at a different interpreter, which
    # would quietly destroy the isolation the lockfile claims, was being
    # overwritten before anyone could notice it; and a mode documented as
    # "re-assert an existing install" was writing to disk. So build the expected
    # content once, then write it (install) or compare it (verify).
    $shimPath = Join-Path $BinDir $Entry.exe
    $body = @(
        '@echo off',
        'REM Generated by tools/bootstrap.ps1 - do not edit; tools/bin/ is gitignored.',
        "`"$venvPython`" `"$venvScript`" %*",
        'exit /b %ERRORLEVEL%'
    ) -join "`r`n"
    # CRLF and no BOM: cmd.exe mis-parses a batch file that opens with a BOM.
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $expected = "$body`r`n"

    if ($Verify) {
        if (-not (Test-Path $shimPath)) {
            Die "$Name launcher missing at $shimPath (run bootstrap without -Verify)"
        }
        # Compared as raw bytes, not as text and not via any string form:
        # ReadAllText would silently strip an injected BOM and report a match on a
        # file cmd.exe can no longer parse.
        #
        # This compared two base64 strings with -ne until it was measured. PS 5.1's
        # -eq/-ne are case-INSENSITIVE and base64 is case-SIGNIFICANT, so that
        # comparison called genuinely different bytes equal: 41 42 6F -> "QUJv" and
        # 41 42 55 -> "QUJV" differ only in case, because base64 indices i and i+26
        # are the same letter in different cases. Any single byte at an offset
        # congruent to 2 mod 3 whose low six bits shift by exactly 26 collides that
        # way, and 'o'/'U' and 'A'/'[' both occur in the paths interpolated above.
        # A tampered launcher would have passed -Verify as "launcher matches".
        # SequenceEqual removes the class rather than patching it with -cne: no
        # encoding round-trip, so no comparison semantics to get wrong.
        $onDisk = [System.IO.File]::ReadAllBytes($shimPath)
        if (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$onDisk, [byte[]]$utf8NoBom.GetBytes($expected))) {
            Die "$Name launcher at $shimPath does not match what the lockfile and the tool venv at $venvScripts imply. -Verify reports this rather than repairing it; re-run bootstrap without -Verify to regenerate."
        }
        Write-Ok "$Name launcher matches $venvPython"
    }
    else {
        [System.IO.File]::WriteAllText($shimPath, $expected, $utf8NoBom)
        Write-Ok "$Name launcher pinned to $venvPython"
    }

    $raw = Invoke-VersionCheck $shimPath $Entry.version_args $Entry.version $Name
    return [ordered]@{ exe = (Resolve-Path $shimPath).Path; version = $Entry.version; version_output = $raw }
}

# [ordered], not @{}: a plain hashtable has no defined enumeration order, so
# resolved.json's key order would not be contractually stable. Task 7 copies this
# file into the dissertation's provenance block, and a block whose keys shuffle
# between runs undermines the reproducibility claim it exists to support. The two
# per-scanner hashtables above are ordered for the same reason.
$resolved = [ordered]@{}
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
