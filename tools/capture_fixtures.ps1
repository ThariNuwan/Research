#Requires -Version 5.1
<#
.SYNOPSIS
    Capture each scanner's real JSON output over the pinned corpus (S0 Task 5).
.DESCRIPTION
    Runs Checkov, Trivy and tfsec read-only over the scan roots declared in
    tools/corpus.lock.json and saves each scanner's stdout verbatim under
    tests/harvest/fixtures/. Task 6 writes its walkers against those bytes, so
    this script's job is to observe, not to interpret: it records what came back
    and refuses to report success on output it could not parse.

    Six captures: three scanners x the two distinct scan roots. One case per
    corpus case would run the same scanner over the same directory four times -
    the four Terraform cases share a scan root, and findings are attributed to
    cases afterwards by the `attribution` rule in tools/corpus.lock.json, not by
    which directory was scanned.

    tfsec x kubernetes is deliberately off-matrix. tools/scanners.lock.json
    declares tfsec Terraform-only; the capture runs it against Kubernetes YAML
    anyway because spec section 5 item 2 asks what a Terraform-only scanner does
    with a manifest directory, and "we assumed it would refuse" is not an
    observation. It is the ONLY capture allowed to produce something that is not
    JSON.

    Reads. Never writes: nothing here touches tools/cache, tools/bin or
    corpus/vendor. The corpus trees are verified blob-identical to two pinned
    upstream subtrees and scanning them read-only is the whole point.
.OUTPUTS
    tests/harvest/fixtures/<scanner>-<platform>.json  - scanner stdout, verbatim
    artifacts/scanner-behavior.json                   - what each run did
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot     = Split-Path -Parent $PSScriptRoot
$ResolvedPath = Join-Path $RepoRoot 'tools\resolved.json'
$ScannerLock  = Join-Path $RepoRoot 'tools\scanners.lock.json'
$CorpusLock   = Join-Path $RepoRoot 'tools\corpus.lock.json'
$FixtureDir   = Join-Path $RepoRoot 'tests\harvest\fixtures'
$ArtifactDir  = Join-Path $RepoRoot 'artifacts'
$ManifestPath = Join-Path $ArtifactDir 'scanner-behavior.json'
$ManifestSchemaVersion = 1
# Stands in for this checkout root inside the recorded argv; see argv_note.
$RepoRootToken = '<repo>'

# Same reasoning as tools/vendor_corpus.ps1:55-63. A scanner or platform name out
# of this class would be joined into a fixture filename; the lockfiles are ours
# and the risk is low, but the guard is one line.
$NameRe = '^[a-z0-9][a-z0-9-]*$'

function Write-Step($Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok($Message) { Write-Host "    OK   $Message" -ForegroundColor Green }
# Failures go to stderr, not to the host, so a caller capturing stderr sees the
# reason instead of a bare exit 1. Mirrors tools/vendor_corpus.ps1:79.
function Die($Message) { [Console]::Error.WriteLine("    FAIL $Message"); exit 1 }
function Write-Warn($Message) { [Console]::Error.WriteLine("    WARN $Message") }

# A .NET method that throws inside try/catch arrives wrapped in a
# MethodInvocationException whose Message names the call, not the problem.
function Get-FailureMessage($ErrorRecord) {
    if ($null -ne $ErrorRecord.Exception.InnerException) {
        return $ErrorRecord.Exception.InnerException.Message
    }
    return $ErrorRecord.Exception.Message
}

# ReadAllText, never a bare Get-Content: PS 5.1 decodes a BOM-less file as ANSI,
# so non-ASCII would arrive as mojibake. Also strips a BOM, which
# ConvertFrom-Json tolerates and Python's json.load does not.
function Read-JsonFile($Path, $Who, $Remedy) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Die "$Who not found at $Path. Run $Remedy first."
    }
    try { return [IO.File]::ReadAllText($Path) | ConvertFrom-Json }
    catch { Die "$Who at $Path is not valid JSON: $(Get-FailureMessage $_). Run $Remedy to regenerate it." }
}

# The property names an object actually carries. Under Set-StrictMode -Version
# Latest, dereferencing an absent property throws PropertyNotFoundStrict, which
# names a PowerShell property instead of naming the lockfile field that is
# missing - so every field is confirmed present before it is read.
function Get-PropertyNames($Object) {
    if ($null -eq $Object) { return @() }
    return @($Object.PSObject.Properties | ForEach-Object { $_.Name })
}

# JSON validity, decided by the parser the fixtures are actually for.
#
# NOT ConvertFrom-Json: on PS 5.1 that path raises "the length of the string
# exceeds the value set on the maxJsonLength property" on large payloads, and a
# 2.2 MB capture must not fail for being big.
#
# And NOT JavaScriptSerializer, which is what this script reached for first. It
# takes an unlimited MaxJsonLength so it survives the size, but it is a
# JavaScript deserializer rather than a JSON one and it accepts input json.load
# refuses. Measured on this host, twelve bytes each:
#
#   {"a": "b<LF>c"}   JavaScriptSerializer -> Ok=True, TopLevel=object
#                     Python json.loads    -> Invalid control character at:
#                                             line 1 column 9 (char 8)
#
# A raw control character inside a string literal is not hypothetical here: it is
# what PS 5.1's `2>&1 | Out-String` hard-wrap produces, the hazard the two-file
# redirect below exists to avoid. `stdout_is_json: true` in the manifest is read
# downstream as "Python can load this file", so the verdict has to come from
# Python or the field is a claim about a different parser.
#
# The validator runs over the STAGED FILE, not over a decoded string: decoding
# first would answer a question about a PowerShell string rather than about the
# bytes a Python consumer opens. What it does NOT decide is the BOM question -
# measured, json.loads over bytes takes json.detect_encoding, which reports
# utf-8-sig for BOM-led input and parses it happily, as does
# json.load(open(path, "rb")). Only the text path, open(path, encoding="utf-8"),
# raises "Unexpected UTF-8 BOM". That is why stdout_has_bom is a separate
# byte-level field rather than a corollary of stdout_is_json, and why a BOM is
# warned about on its own below. If the validator cannot be run at all, the
# capture dies. Falling back to the permissive probe would put
# `stdout_is_json: true` in the manifest having checked nothing, which is worse
# than carrying no such field.
$ValidatorSource = @'
"""Decide whether one file is JSON, and report its top-level shape.

Written into the staging directory and invoked once per capture by
tools/capture_fixtures.ps1. Prints exactly one line: `OK <object|array|null|
scalar>`, `EMPTY <why>` or `BAD <parser message>`. The exit status is 0 whenever
this script itself ran, so the caller can tell "the file is not JSON" (a result)
from "the validator did not run" (a failure) and stop rather than record a
verdict it never obtained.

Bytes, not text: json.loads over bytes is the same detect-encoding path that
json.load(open(path, "rb")) takes, which is how every consumer of these fixtures
reaches them. Note what that path does not settle - it ACCEPTS a leading UTF-8
BOM, because detect_encoding reports utf-8-sig for it. The text path,
open(path, encoding="utf-8"), rejects the same bytes. The BOM is therefore
checked separately, on the bytes, by the caller.
"""
import json
import sys

raw = open(sys.argv[1], "rb").read()
if not raw.strip():
    print("EMPTY stdout was empty or whitespace only")
    sys.exit(0)
try:
    doc = json.loads(raw)
except ValueError as exc:
    print("BAD " + " ".join(str(exc).split()))
    sys.exit(0)
if isinstance(doc, dict):
    print("OK object")
elif isinstance(doc, list):
    print("OK array")
elif doc is None:
    print("OK null")
else:
    print("OK scalar")
'@

# PS 5.1 does not quote -ArgumentList elements; an unquoted path with a space in
# it would arrive as two arguments. RepoRoot has none today, which is exactly why
# this is handled here rather than discovered later on a different host. One
# function for both the scanner launches and the validator.
function Format-LaunchArgs([string[]]$Vector) {
    return @($Vector | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } })
}

function Test-JsonFile($Path) {
    $vOut = Join-Path $TempDir 'validator.out'
    $vErr = Join-Path $TempDir 'validator.err'
    # uv, never a bare `python`: on this host `python` is the Microsoft Store alias
    # stub and exits without running anything. -WorkingDirectory pins uv's project
    # discovery to this repository, so the verdict comes from the project's own
    # interpreter however the operator invoked this script.
    try {
        $proc = Start-Process -FilePath 'uv' -WorkingDirectory $RepoRoot `
            -ArgumentList (Format-LaunchArgs @('run', 'python', $ValidatorPath, $Path)) `
            -RedirectStandardOutput $vOut -RedirectStandardError $vErr -Wait -NoNewWindow -PassThru
        $proc.WaitForExit()
    }
    catch {
        $script:KeepTemp = $true
        Die "could not run the JSON validator (uv run python $ValidatorPath): $(Get-FailureMessage $_). Every stdout_is_json verdict in the manifest comes from Python's json.load, so without it this run would record a verdict it never obtained. Install uv (tools/bootstrap.ps1) and re-run."
    }
    $code   = if ($null -eq $proc.ExitCode) { -1 } else { [int]$proc.ExitCode }
    $said   = if (Test-Path -LiteralPath $vOut -PathType Leaf) { [IO.File]::ReadAllText($vOut) } else { '' }
    $cried  = if (Test-Path -LiteralPath $vErr -PathType Leaf) { [IO.File]::ReadAllText($vErr) } else { '' }
    $spoken = @($said -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 })
    if ($code -ne 0 -or @($spoken).Count -eq 0) {
        $script:KeepTemp = $true
        Die "the JSON validator did not run: exit=$code, $(@($spoken).Count) line(s) on stdout. stderr: $($cried.Trim()). Refusing to record a stdout_is_json verdict this run never obtained."
    }
    $verdict = $spoken[0]
    $word    = $verdict.Split(' ')[0]
    $detail  = if ($verdict.Length -gt $word.Length) { $verdict.Substring($word.Length + 1) } else { '' }
    # Which of the two shapes came back is load-bearing for Task 6: Checkov emits
    # a JSON object for a single detected framework and a JSON ARRAY of result
    # objects when it detects several, so a walker that assumes a dict breaks on
    # the other corpus half. Recorded per capture rather than assumed.
    switch -CaseSensitive ($word) {
        'EMPTY' { return [ordered]@{ Ok = $false; TopLevel = 'empty';   Error = $detail } }
        'BAD'   { return [ordered]@{ Ok = $false; TopLevel = 'invalid'; Error = $detail } }
        'OK'    {
            # Top-level null parses but carries nothing: a fixture that is the four
            # bytes `null` would satisfy a downstream "it parsed" assertion and
            # nothing else. Treated as a failure, as the old probe treated it.
            if ($detail -ceq 'null') {
                return [ordered]@{ Ok = $false; TopLevel = 'null'; Error = 'parsed to JSON null' }
            }
            return [ordered]@{ Ok = $true; TopLevel = $detail; Error = $null }
        }
    }
    $script:KeepTemp = $true
    Die "the JSON validator printed '$verdict', which is none of OK/EMPTY/BAD. Its contract and this switch have drifted apart, so neither a pass nor a fail can be read out of it."
}

# ---------------------------------------------------------------------------
# Preconditions. Every one of these is a thing a fixture would silently encode
# if it were wrong: the wrong scanner build, a missing corpus, a scan root that
# does not exist. Checked before anything runs.
# ---------------------------------------------------------------------------
Write-Step 'checking preconditions'

$resolved = Read-JsonFile $ResolvedPath 'tools/resolved.json' 'tools/bootstrap.ps1'
$scanners = Read-JsonFile $ScannerLock 'tools/scanners.lock.json' 'tools/bootstrap.ps1'
$corpus   = Read-JsonFile $CorpusLock  'tools/corpus.lock.json'  'tools/vendor_corpus.ps1'

foreach ($pair in @(@{ Obj = $scanners; Name = 'tools/scanners.lock.json'; Field = 'scanners' },
                    @{ Obj = $corpus;   Name = 'tools/corpus.lock.json';   Field = 'cases' })) {
    if ((Get-PropertyNames $pair.Obj) -cnotcontains $pair.Field) {
        Die "$($pair.Name) has no '$($pair.Field)' key, so this run has nothing to iterate."
    }
}

# recorded_utc is read at the very end of the run, into the manifest, and nowhere
# before it. Confirmed here so a lockfile missing it stops the run in the second
# before the first scanner starts instead of throwing PropertyNotFoundStrict in
# the minute after all six have finished and their bytes are staged.
# tests/test_corpus_lock.py covers the same field, including that it is not in
# the future.
if ((Get-PropertyNames $corpus) -cnotcontains 'recorded_utc' -or
    [string]::IsNullOrWhiteSpace($corpus.recorded_utc)) {
    Die "tools/corpus.lock.json has no usable 'recorded_utc', which every manifest records as corpus_recorded_utc to say which corpus these fixtures describe. Run tools/vendor_corpus.ps1."
}

$ScannerNames = @(Get-PropertyNames $scanners.scanners | Sort-Object)
if (@($ScannerNames).Count -eq 0) {
    Die "tools/scanners.lock.json declares zero scanners, so this run would write an empty fixture set and report success. Refusing. Run tools/bootstrap.ps1."
}

$ExePath = @{}
# [ordered], not @{}: a plain hashtable has no defined key order, so the
# scanner_versions block of the committed manifest could reorder between runs
# and show up as a diff that means nothing.
$Versions = [ordered]@{}
foreach ($name in $ScannerNames) {
    if ($name -cnotmatch $NameRe) {
        Die "scanner name '$name' in tools/scanners.lock.json is outside $NameRe and is joined into a fixture filename."
    }
    # resolved.json is written by bootstrap and is git-ignored, so it can be
    # absent or stale in a fresh clone while the lockfile is present. Say which
    # scanner is missing rather than failing on a null exe path later.
    if ((Get-PropertyNames $resolved) -cnotcontains $name) {
        Die "tools/resolved.json has no entry for '$name' although tools/scanners.lock.json pins it. Run tools/bootstrap.ps1."
    }
    $entry = $resolved.$name
    foreach ($field in @('exe', 'version')) {
        if ((Get-PropertyNames $entry) -cnotcontains $field -or [string]::IsNullOrWhiteSpace($entry.$field)) {
            Die "tools/resolved.json entry for '$name' has no usable '$field'. Run tools/bootstrap.ps1."
        }
    }
    if (-not (Test-Path -LiteralPath $entry.exe -PathType Leaf)) {
        Die "the executable tools/resolved.json records for '$name' does not exist: $($entry.exe). Run tools/bootstrap.ps1."
    }
    # Both sides are read from disk; nothing is recomputed. A resolved build that
    # is not the pinned build would produce fixtures that quietly describe a
    # different scanner version than the dissertation claims.
    #
    # 'platforms' is confirmed here although it is read further down, by the
    # platform-coverage loop ($declared = ...). Both loops walk $ScannerNames, so
    # this is the first pass over the same entries; checking it there instead
    # would leave one field of this object read unguarded, which is the exact
    # thing the comment at :84 promises does not happen.
    $lockEntry = $scanners.scanners.$name
    foreach ($field in @('version', 'platforms')) {
        if ((Get-PropertyNames $lockEntry) -cnotcontains $field) {
            Die "tools/scanners.lock.json entry for '$name' has no '$field' key. tests/test_scanners_lock.py asserts the same fields; run uv run pytest for the full picture."
        }
    }
    if ([string]::IsNullOrWhiteSpace($lockEntry.version)) {
        Die "tools/scanners.lock.json entry for '$name' declares an empty 'version', so nothing would pin the build these fixtures describe. Run tools/bootstrap.ps1."
    }
    $pinned = $lockEntry.version
    if ($entry.version -cne $pinned) {
        Die "'$name' resolves to version $($entry.version) but tools/scanners.lock.json pins $pinned. Fixtures captured now would describe the wrong build. Run tools/bootstrap.ps1."
    }
    $ExePath[$name] = $entry.exe
    $Versions[$name] = $entry.version
    Write-Ok "$name $($entry.version) at $($entry.exe)"
}

# ---------------------------------------------------------------------------
# The capture matrix, from scan_root.
#
# Deliberately NOT Split-Path -Parent of each case's `path`: that would infer a
# scan root instead of reading the one the lockfile declares, and it gets
# kg-scenarios wrong outright - that case's `path` IS a directory, so taking its
# parent would scan every scenario's sibling directories. scan_root is a declared
# field (tools/corpus.lock.json) precisely so this script does not have to guess.
# ---------------------------------------------------------------------------
Write-Step 'building the capture matrix from declared scan roots'

$cases = @($corpus.cases)
if (@($cases).Count -eq 0) {
    Die "tools/corpus.lock.json declares zero cases, so there is nothing to scan. Run tools/vendor_corpus.ps1."
}

foreach ($case in $cases) {
    foreach ($field in @('id', 'platform', 'path', 'scan_root')) {
        if ((Get-PropertyNames $case) -cnotcontains $field -or [string]::IsNullOrWhiteSpace($case.$field)) {
            $shown = if ((Get-PropertyNames $case) -ccontains 'id') { $case.id } else { '<no id>' }
            Die "case '$shown' in tools/corpus.lock.json has no usable '$field'. tests/test_corpus_lock.py asserts the same fields; run uv run pytest for the full picture."
        }
    }
    if ($case.platform -cnotmatch $NameRe) {
        Die "case '$($case.id)' declares platform '$($case.platform)', outside $NameRe, and the platform is joined into a fixture filename."
    }
}

# scan_root deduplicated per platform. Four Terraform cases share one root, so
# this is 2 roots and not 5 - the difference between 6 scanner runs and 15.
# Ordinal comparer, not the default one. `[ordered]@{}` builds an OrderedDictionary
# with a case-INSENSITIVE comparer, so `$Roots.Contains('Terraform')` answers true
# for a root declared as 'terraform'. That would let a scanner declaring the wrong
# case pass the coverage check below and then be looked up, later, under a key that
# is not in the dictionary. The lockfile is lowercase and $NameRe enforces it; this
# makes the dictionary agree instead of quietly forgiving.
# Unreachable from the current schema, and that is worth saying out loud:
# $NameRe is '^[a-z0-9][a-z0-9-]*$' and is applied with -cnotmatch to both sides
# of every comparison this dictionary makes - the case platforms that become its
# keys (:327) and the scanner-declared platforms that look them up - so no
# lockfile that passes those two guards can hold two names differing only in
# case, and the six Invoke-Capture calls pass lowercase literals. The N4a probe
# could change a verdict only by calling Contains directly on a dictionary built
# each way. Kept anyway, for one constructor argument, because it is the
# assumption $NameRe is carrying: admit uppercase to that regex and this comparer
# is the only thing between a mis-cased platform and a lookup that misses in
# silence.
$Roots = New-Object System.Collections.Specialized.OrderedDictionary([StringComparer]::Ordinal)
foreach ($platformName in @($cases | ForEach-Object { $_.platform } | Sort-Object -Unique)) {
    $matched = @($cases | Where-Object { $_.platform -ceq $platformName })
    # NOT $roots: PowerShell identifiers are case-insensitive, so a lower-case
    # $roots here and the $Roots matrix above are ONE variable. Measured - the
    # array overwrote the dictionary and the next line failed with "cannot
    # convert kubernetes to System.Int32", because it was indexing a string
    # array by name. No two names in this script may differ only in case.
    $platformRoots = @($matched | ForEach-Object { $_.scan_root } | Sort-Object -Unique)
    if (@($platformRoots).Count -ne 1) {
        # Not a failure of the lockfile, a failure of this script's shape: the
        # straight-line Capture calls below name one fixture per scanner and
        # platform. A second root for a platform needs a naming decision
        # (which root owns <scanner>-<platform>.json), not a silent overwrite.
        Die "platform '$platformName' declares $(@($platformRoots).Count) distinct scan roots ($($platformRoots -join ', ')). This script writes one fixture per scanner and platform and would overwrite one with the other. Extend the fixture naming before adding a second root."
    }
    $abs = Join-Path $RepoRoot ($platformRoots[0] -replace '/', '\')
    if (-not (Test-Path -LiteralPath $abs -PathType Container)) {
        Die "scan root '$($platformRoots[0])' for platform '$platformName' is not a directory at $abs. Run tools/vendor_corpus.ps1 to vendor the corpus."
    }
    # The lockfile is ours, but the resolved path is handed to a scanner as a
    # directory to walk; a '..' segment would point the scan outside the repo and
    # a fixture would then describe files that are not corpus.
    # tools/vendor_corpus.ps1:55-63 refuses the same class of path by a different
    # mechanism - a regex over the declared string, applied before anything is
    # resolved. This one tests the resolved path, so it also catches a symlink or
    # a junction, which no regex over the lockfile text can see.
    #
    # Compared on a directory boundary, not as a string prefix: 'D:\Research' is a
    # string prefix of 'D:\Research-scratch', which is a sibling directory and not
    # inside the repository at all. Equality is allowed deliberately - a scan root
    # that IS the repository root is inside it.
    $full     = [IO.Path]::GetFullPath($abs).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $repoFull = [IO.Path]::GetFullPath($RepoRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ($full -cne $repoFull -and -not $full.StartsWith(
            $repoFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::Ordinal)) {
        Die "scan root '$($platformRoots[0])' resolves to $full, outside the repository at $repoFull. Refusing to scan it."
    }
    $Roots[$platformName] = [ordered]@{
        Relative = $platformRoots[0]
        Absolute = $full
        CaseIds  = @($matched | ForEach-Object { $_.id } | Sort-Object)
    }
    Write-Ok "$platformName -> $($platformRoots[0]) ($(@($matched).Count) case(s): $($Roots[$platformName].CaseIds -join ', '))"
}

# Every platform a scanner claims to support must have somewhere to be observed.
# Without this the empty-match state is silent: a scanner declaring `kubernetes`
# with no Kubernetes case in the corpus produces five green captures and an
# unexercised claim. Measured with a scanner's platforms set to
# @('terraform','cloudformation'): the message below names cloudformation and the
# run stops, where unguarded `cases | Where-Object platform` returns nothing and
# @(...).Count is 0 rather than throwing - silence, not an error.
foreach ($name in $ScannerNames) {
    $declared = @($scanners.scanners.$name.platforms)
    if (@($declared).Count -eq 0) {
        Die "tools/scanners.lock.json declares no platforms for '$name', so nothing decides what to run it against."
    }
    # Same guard the corpus cases get at :327, for the same reason: a platform name
    # is joined into a fixture filename. Checked here as well because these two
    # lists are separate declarations - a case's platform passing $NameRe says
    # nothing about a scanner's, and $Roots is keyed by the case side.
    foreach ($declaredPlatform in $declared) {
        if ($declaredPlatform -cnotmatch $NameRe) {
            Die "'$name' in tools/scanners.lock.json declares platform '$declaredPlatform', outside $NameRe, and the platform is joined into a fixture filename."
        }
    }
    $missing = @($declared | Where-Object { -not $Roots.Contains($_) })
    if (@($missing).Count -gt 0) {
        Die "'$name' declares support for $($missing -join ', ') but tools/corpus.lock.json has no case with that platform, so this run would capture nothing for it and still report success. Add a case or narrow the scanner's platforms."
    }
}
Write-Ok "every declared scanner platform has a corpus scan root"

# ---------------------------------------------------------------------------
# Output directories, all three through one helper.
#
# Measured on this host, not assumed: `New-Item -ItemType Directory -Force`
# against a path that is an existing FILE is a silent no-op. It does not throw
# under $ErrorActionPreference='Stop', it does not create the directory, and it
# leaves the file's bytes alone (a 21-byte file was still 21 bytes afterwards).
# `-ItemType File -Force` is the form that truncates - same measurement, 21 bytes
# to 0 - and this script never uses it.
#
# So the hazard here is a lost error rather than lost data: the run carries on
# believing the directory exists, and the first write into it throws
# "Could not find a part of the path ...\checkov-terraform.json", which names the
# fixture and says nothing about its parent being a file - a minute into a
# scanner run, or in the publish step, whichever touches it first.
#
# Two of the three creations tested for a container first and the third called
# -Force bare, so whether anything noticed at all depended on which line you
# read. One helper, which turns it into a named precondition failure before the
# first scanner starts.
# ---------------------------------------------------------------------------
function New-OutputDirectory([string]$Path, [string]$What) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        Die "$What at $Path is a file, not a directory. New-Item -ItemType Directory -Force will not fail on it - it silently creates nothing, and a later write would fail naming a file inside $Path instead. Move it aside and run this again."
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

New-OutputDirectory $FixtureDir 'the fixture directory'
New-OutputDirectory $ArtifactDir 'the artifact directory'

# Staged outside the repository. A scanner killed halfway leaves a truncated file,
# and a truncated fixture that still happens to parse is worse than no fixture:
# stdout lands here first and moves into tests/harvest/fixtures only once all six
# captures have parsed - see the publish step after the matrix assertion.
$TempDir = Join-Path ([IO.Path]::GetTempPath()) ("iacrisk-capture-" + [guid]::NewGuid().ToString('N').Substring(0, 12))
New-OutputDirectory $TempDir 'the staging directory'
$KeepTemp = $false

# The validator lives in the staging directory rather than in tools/: it is twenty
# lines that exist only to lend this script a JSON parser, and a tools/*.py file
# would be a second Python entry point for Task 6 to either import or duplicate.
$ValidatorPath = Join-Path $TempDir 'validate_json.py'
$NoBom = New-Object Text.UTF8Encoding $false
[IO.File]::WriteAllText($ValidatorPath, $ValidatorSource, $NoBom)

# Construct both states and observe them rather than trust that the gate is live.
# The rejected sample is the exact input the JavaScriptSerializer probe accepted -
# a raw LF inside a string literal - so if this script ever loses its real parser
# again it stops here, before a scanner runs, instead of at a manifest full of
# stdout_is_json: true.
$probeGood = Join-Path $TempDir 'validator-selfcheck-good.json'
$probeBad  = Join-Path $TempDir 'validator-selfcheck-bad.json'
[IO.File]::WriteAllText($probeGood, "{`"a`": `"b`"}", $NoBom)
[IO.File]::WriteAllText($probeBad,  "{`"a`": `"b`nc`"}", $NoBom)
$saysGood = Test-JsonFile $probeGood
$saysBad  = Test-JsonFile $probeBad
if (-not $saysGood.Ok -or $saysGood.TopLevel -cne 'object') {
    Die "the JSON validator rejected a valid JSON object (verdict: $($saysGood.TopLevel) / $($saysGood.Error)). Nothing it says about a real capture could be trusted."
}
if ($saysBad.Ok) {
    Die "the JSON validator accepted a raw newline inside a string literal, which Python's json.load rejects. It is not the parser this script claims to use, so every stdout_is_json in the manifest would describe some other parser."
}
Write-Ok "json.load validator live: object accepted, raw newline in a string literal rejected ($($saysBad.Error))"

$Records = New-Object System.Collections.Generic.List[object]
# One entry per capture that parsed, published together after the last one. Held
# separately from $Records because a record is what the manifest says and an entry
# here is a file that still has to be moved.
$Pending = New-Object System.Collections.Generic.List[object]

function Invoke-Capture {
    param(
        [Parameter(Mandatory = $true)][string]$Scanner,
        [Parameter(Mandatory = $true)][string]$Platform,
        # Everything except the scan root, which is appended last. Checkov's -d
        # therefore goes at the end of this array; Trivy and tfsec take the
        # directory as a trailing positional and need no flag for it.
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        # $true for exactly one capture: see MayBeNonJson below.
        [switch]$MayBeNonJson,
        [string]$Why = ''
    )

    $root = $Roots[$Platform]
    $argv = @($Arguments) + @($root.Absolute)
    # Quoted by Format-LaunchArgs, which the validator launch shares.
    $launch = Format-LaunchArgs $argv

    $stagedOut = Join-Path $TempDir "$Scanner-$Platform.out"
    $stagedErr = Join-Path $TempDir "$Scanner-$Platform.err"

    Write-Step "$Scanner over $($root.Relative) ($Platform)"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        # Two separate files, never 2>&1: on PS 5.1 a native command's stderr
        # redirected inside PowerShell arrives as ErrorRecord objects injected
        # into the success stream, and `2>&1 | Out-String` would additionally
        # hard-wrap at the host buffer width - a newline inside a JSON string
        # literal. Measured: tfsec writes a 365-byte deprecation banner to stderr
        # on every invocation including --help, so this is not hypothetical.
        # Start-Process writes the child's bytes to disk with no PowerShell
        # decoding, and it works on checkov's .cmd launcher (verified: exit 0,
        # 8 bytes of stdout for --version).
        $proc = Start-Process -FilePath $ExePath[$Scanner] -ArgumentList $launch `
            -RedirectStandardOutput $stagedOut -RedirectStandardError $stagedErr `
            -Wait -NoNewWindow -PassThru
    }
    catch {
        $script:KeepTemp = $true
        Die "could not launch $Scanner ($($ExePath[$Scanner])): $(Get-FailureMessage $_)"
    }
    # -Wait can return before the object's exit code is populated; WaitForExit on
    # the object itself settles it. The code comes off the process object, never
    # from $LASTEXITCODE, which Start-Process does not set at all - reading it
    # here would report the exit status of some earlier command entirely.
    $proc.WaitForExit()
    $sw.Stop()
    if ($null -eq $proc.ExitCode) {
        $script:KeepTemp = $true
        Die "$Scanner exited but reported no exit code, so this run cannot be recorded honestly."
    }
    $exit = [int]$proc.ExitCode

    # Bytes, not characters. $text.Length on a UTF-8 file with any non-ASCII in
    # it is smaller than the file, and the byte count is what a reader checks a
    # committed fixture against.
    $outBytes = [IO.File]::ReadAllBytes($stagedOut)
    $errBytes = [IO.File]::ReadAllBytes($stagedErr)
    $bom = ($outBytes.Length -ge 3 -and $outBytes[0] -eq 0xEF -and $outBytes[1] -eq 0xBB -and $outBytes[2] -eq 0xBF)
    # Skipped for the decode below, which exists only to count CRLF pairs and
    # where GetString would otherwise turn a BOM into a leading U+FEFF. The JSON
    # verdict is taken over the whole staged file, BOM included, and measured that
    # verdict is unchanged by one: json.loads over bytes accepts a leading BOM.
    # $bom is recorded and warned about separately for exactly that reason.
    $offset = if ($bom) { 3 } else { 0 }
    $outText = [Text.Encoding]::UTF8.GetString($outBytes, $offset, $outBytes.Length - $offset)
    $errText = [Text.Encoding]::UTF8.GetString($errBytes)

    # .gitattributes normalizes these fixtures to LF in the index. A capture with
    # CRLF in it would be committed with different bytes than were observed, so
    # the count is recorded and a non-zero one warns rather than passing silently.
    # Replacing CRLF with LF removes exactly one character per occurrence.
    $crlf = $outText.Length - $outText.Replace("`r`n", "`n").Length

    # Split on either ending so the line count is right on any host. Measured on
    # this one: tfsec's banner is LF-only - 365 bytes, 12 lines, zero CRLF pairs.
    $errLines = @()
    if ($errText.Length -gt 0) {
        $errLines = @($errText -split "`r?`n")
    }
    # The literal first line AND the first line carrying text, deliberately both.
    # $errFirst alone misleads on a stream that opens blank, and tfsec's banner
    # does: stderr_first_line is '' on a capture that produced 365 bytes over 12
    # lines, so a reader checking that one field concludes stderr was silent.
    # stderr_first_line is not redefined to paper over it - it is the literal
    # first line and is still the honest answer to that question - the value a
    # reader actually wants is recorded beside it instead.
    $errFirst = if (@($errLines).Count -gt 0) { $errLines[0] } else { '' }
    $errFirstText = ''
    foreach ($line in $errLines) {
        if ($line.Trim().Length -gt 0) { $errFirstText = $line; break }
    }

    $probe = Test-JsonFile $stagedOut
    # MayBeNonJson is set for exactly one capture, tfsec x kubernetes, and the
    # reason is recorded in the manifest rather than left to this comment: tfsec
    # is pinned Terraform-only, the run exists to find out what it does with
    # manifests, and "it printed a sentence instead of JSON" is a valid answer.
    # Every OTHER capture that fails to parse is a hard failure. A scanner given a
    # wrong flag writes a plausible file - a usage message, an empty object, half a
    # document - and Task 6 would be written against it. The staged bytes are left
    # in place so the operator can read what actually came back.
    if (-not $probe.Ok -and -not $MayBeNonJson) {
        $script:KeepTemp = $true
        $bomNote = if ($bom) { ' The output also starts with a UTF-8 BOM - not the cause of the parse failure above, since json.loads over bytes accepts one, but a second defect to fix.' } else { '' }
        Die ("$Scanner over $($root.Relative) did not produce JSON ($($probe.Error)). exit=$exit, " +
             "stdout=$($outBytes.Length) bytes, stderr=$($errBytes.Length) bytes.$bomNote " +
             "Staged output kept at $stagedOut and stderr at $stagedErr - read them before changing the argument array. " +
             "A fixture is only useful if it is what the scanner really emits.")
    }

    # The extension states the outcome. A file named .json that is not JSON is a
    # trap for any test that globs the fixture directory, so a capture that did
    # not parse is saved as .stdout.txt instead and the stale sibling from a
    # previous run is removed rather than left to be picked up.
    #
    # Queued here, not published. Publishing each capture as it finished meant a
    # run that died on capture four left four new fixtures beside two old ones and
    # a manifest describing neither - a mixed set that
    # tests/harvest/test_fixtures.py detects by byte count but cannot repair, and
    # that no single file on disk announces.
    $ext = if ($probe.Ok) { '.json' } else { '.stdout.txt' }
    $fixture = Join-Path $FixtureDir "$Scanner-$Platform$ext"
    $stale = Join-Path $FixtureDir ("$Scanner-$Platform" + $(if ($probe.Ok) { '.stdout.txt' } else { '.json' }))
    $Pending.Add([ordered]@{ Staged = $stagedOut; Fixture = $fixture; Stale = $stale })
    # Repo-relative and forward-slashed: the manifest is read by Python tests and
    # quoted in the spec appendix, neither of which wants a drive-letter prefix.
    $sep = [IO.Path]::DirectorySeparatorChar
    $fixtureRel = $fixture.Substring($RepoRoot.Length).TrimStart($sep).Replace($sep, '/')

    if ($bom) { Write-Warn "$Scanner-$Platform starts with a UTF-8 BOM; json.loads over bytes accepts it, a text-mode reader does not" }
    if ($crlf -gt 0) { Write-Warn "$Scanner-$Platform contains $crlf CRLF pairs, which .gitattributes will normalize to LF on commit" }
    $verdict = if ($probe.Ok) { "$($probe.TopLevel)" } else { "NOT JSON ($($probe.TopLevel))" }
    Write-Ok ("exit=$exit stdout=$($outBytes.Length)B [$verdict] stderr=$($errBytes.Length)B " +
              "in $([math]::Round($sw.Elapsed.TotalSeconds, 1))s -> staged for $(Split-Path -Leaf $fixture)")

    $Records.Add([ordered]@{
        scanner            = $Scanner
        scanner_version    = $Versions[$Scanner]
        platform           = $Platform
        off_matrix         = [bool]$MayBeNonJson
        off_matrix_reason  = if ($MayBeNonJson) { $Why } else { $null }
        scan_root          = $root.Relative
        case_ids           = @($root.CaseIds)
        # The launched vector carries this checkout absolute path; the recorded
        # one carries the <repo> token in its place (see argv_note). Portability
        # of a committed artifact, and the substitution is declared rather than
        # silent - $RepoRoot is a property of the checkout, not of the experiment.
        argv               = @($argv | ForEach-Object {
            if ($_.StartsWith($RepoRoot, [StringComparison]::Ordinal)) {
                $RepoRootToken + ($_.Substring($RepoRoot.Length).Replace($sep, [char]47))
            } else { $_ }
        })
        exit_code          = $exit
        duration_s         = [math]::Round($sw.Elapsed.TotalSeconds, 2)
        fixture            = $fixtureRel
        stdout_bytes       = $outBytes.Length
        stdout_is_json     = [bool]$probe.Ok
        stdout_top_level   = $probe.TopLevel
        stdout_parse_error = $probe.Error
        stdout_has_bom     = [bool]$bom
        stdout_crlf_pairs  = $crlf
        stderr_bytes       = $errBytes.Length
        stderr_lines       = @($errLines).Count
        stderr_first_line  = $errFirst
        stderr_first_text  = $errFirstText
        stderr_head        = @($errLines | Select-Object -First 4)
    })
}

# ---------------------------------------------------------------------------
# The six captures, written out one call at a time.
#
# Straight-line rather than a loop over a scanner x platform table, and that is a
# concession THIS SCRIPT is allowed and pipeline code is not. Each scanner's
# argument array is different, one combination is deliberately off-matrix, and the
# flags carry a paragraph of measured justification each - a table would either
# lose that or grow a per-scanner branch inside the loop, which is a loop in name
# only. Do not copy this shape into src/iacrisk: layer 2 runs scanners as
# configured data, not as six hand-written calls.
#
# Every flag below was checked against the pinned build's own --help and then
# measured. What is deliberately ABSENT matters as much as what is present:
#
#   checkov --quiet     REJECTED. Measured on one file: --quiet drops the
#                       passed_checks, skipped_checks and parsing_errors keys out
#                       of `results` entirely (241320 -> 135381 bytes), leaving
#                       only failed_checks. A walker written against that fixture
#                       would KeyError on any normal Checkov run.
#   checkov --compact   KEPT. Sets code_block to null and removes no key at all
#                       (the 28 per-finding keys are identical with and without
#                       it; 421943 -> 241320 bytes). What it drops is a verbatim
#                       echo of corpus source, which would otherwise copy pinned
#                       vendored bytes into a committed fixture for no schema gain.
#   checkov --framework NOT PASSED. Letting Checkov auto-detect is the point: its
#                       top-level shape changes from an object to an ARRAY when it
#                       detects more than one framework, and pinning the framework
#                       would hide that from Task 6.
#   tfsec --soft-fail   REJECTED, although the draft carried it. It forces exit 0,
#                       and the exit code is data here - spec section 5 item 2
#                       asks what tfsec's exit status is on Kubernetes input, and
#                       --soft-fail makes that question unanswerable.
#
# Nothing below treats a non-zero exit as failure: Checkov and tfsec exit 1 when
# they have findings, which is the normal case for a deliberately-insecure corpus.
# ---------------------------------------------------------------------------

# --skip-download keeps the run offline (no Prisma Cloud fetch); measured cost is
# that the `guideline` field comes back null instead of a docs URL.
Invoke-Capture -Scanner 'checkov' -Platform 'terraform' `
    -Arguments @('--output', 'json', '--compact', '--skip-download', '--directory')
Invoke-Capture -Scanner 'checkov' -Platform 'kubernetes' `
    -Arguments @('--output', 'json', '--compact', '--skip-download', '--directory')

# --skip-check-update uses the checks bundle embedded in the binary instead of
# pulling one from an OCI registry, so the pinned 0.74.0 build decides the rules.
# --quiet suppresses the progress bar only; results are unaffected.
Invoke-Capture -Scanner 'trivy' -Platform 'terraform' `
    -Arguments @('config', '--format', 'json', '--quiet', '--disable-telemetry', '--skip-check-update')
Invoke-Capture -Scanner 'trivy' -Platform 'kubernetes' `
    -Arguments @('config', '--format', 'json', '--quiet', '--disable-telemetry', '--skip-check-update')

# --no-module-downloads keeps tfsec from fetching remote Terraform modules, which
# would make the fixture depend on the network and on upstream module tags.
Invoke-Capture -Scanner 'tfsec' -Platform 'terraform' `
    -Arguments @('--format', 'json', '--no-colour', '--no-module-downloads')

# The one off-matrix capture, and the only one permitted to be non-JSON.
Invoke-Capture -Scanner 'tfsec' -Platform 'kubernetes' -MayBeNonJson `
    -Arguments @('--format', 'json', '--no-colour', '--no-module-downloads') `
    -Why 'tools/scanners.lock.json pins tfsec as terraform-only. This run exists to record what a Terraform-only scanner does with a Kubernetes manifest directory (spec section 5 item 2) instead of assuming it refuses, so a usage message or empty output on stdout is a result rather than a failure.'

# ---------------------------------------------------------------------------
# The manifest.
# ---------------------------------------------------------------------------
# The straight-line calls above and the two lockfiles can drift apart silently:
# a fourth scanner added to tools/scanners.lock.json with no Invoke-Capture call
# would leave five fixtures and a run that reports success. The product is what
# the matrix claims to be, so it is asserted rather than assumed.
$expected = @($ScannerNames).Count * @($Roots.Keys).Count
# $Records.Count, NOT @($Records).Count. The @() wrapper is the right habit for a
# pipeline result, which can be $null or a bare scalar - but measured on PS 5.1,
# @() around a System.Collections.Generic.List throws "Argument types do not
# match" whatever the element type is. A List always has a real .Count, so the
# wrapper protects against nothing here and breaks the line instead.
if ($Records.Count -ne $expected) {
    Die "captured $($Records.Count) fixture(s) but the matrix is $(@($ScannerNames).Count) scanner(s) x $(@($Roots.Keys).Count) scan root(s) = $expected. Add or remove an Invoke-Capture call to match."
}

# ---------------------------------------------------------------------------
# Publish.
#
# Every capture has run and parsed, so the staged files move into the repository
# now, together, and the manifest is written after them.
#
# This shrinks the window rather than closing it, which is the honest claim: what
# is left is six renames with nothing between them that can invoke a scanner, in
# place of six scanner runs each of which could die after the previous ones had
# already published. A crash inside this loop still leaves a mixed set. It is a
# much smaller target, and it is the smallest one available without a transaction
# the filesystem does not offer.
# ---------------------------------------------------------------------------
Write-Step 'publishing'
if ($Pending.Count -ne $expected) {
    Die "$($Pending.Count) staged capture(s) are queued for publication but the matrix is $expected. A capture recorded itself without queuing its bytes, or the reverse."
}
foreach ($entry in $Pending) {
    if (-not (Test-Path -LiteralPath $entry.Staged -PathType Leaf)) {
        $script:KeepTemp = $true
        Die "the staged capture at $($entry.Staged) is gone before it could be published to $($entry.Fixture). Nothing has been moved; the fixtures on disk are still the previous run's."
    }
}
foreach ($entry in $Pending) {
    if (Test-Path -LiteralPath $entry.Stale -PathType Leaf) { Remove-Item -LiteralPath $entry.Stale -Force }
    Move-Item -LiteralPath $entry.Staged -Destination $entry.Fixture -Force
    Write-Ok "$(Split-Path -Leaf $entry.Fixture)"
}

$rootSummary = [ordered]@{}
foreach ($platformName in $Roots.Keys) {
    $rootSummary[$platformName] = [ordered]@{
        scan_root = $Roots[$platformName].Relative
        case_ids  = @($Roots[$platformName].CaseIds)
    }
}

$manifest = [ordered]@{
    schema_version = $ManifestSchemaVersion
    captured_utc   = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    generated_by   = 'tools/capture_fixtures.ps1'
    host_os        = [Environment]::OSVersion.VersionString
    powershell     = $PSVersionTable.PSVersion.ToString()
    note           = 'Mechanical record of six scanner runs over the pinned corpus (S0 Task 5). Deliberately scanner-agnostic: it records exit codes, byte counts, stream separation and the top-level JSON shape, and does NOT name where each scanner keeps a rule id or a severity. Those field paths are an interpretation of the fixtures, they belong to the Task 6 walkers, and encoding them in the capture tool would mean the tool and the walker share one assumption instead of the walker being tested against observed bytes. They are written up in the Appendix of docs/superpowers/specs/2026-08-24-implementation-phase0-design.md.'
    argv_note      = 'Each capture argv is the vector this script passed to the scanner, with one declared substitution: the absolute path of this checkout is replaced by the token <repo>, and the separators after it by forward slashes. Nothing else is rewritten. The scanners were launched with the native absolute path, which is why checkov file_abs_path and tfsec location.filename carry backslashes in the fixtures. To reproduce, substitute the root of your own checkout.'
    no_digest_note = 'No fixture digest is recorded here. A hash this script computed from a file it had just written would be self-attested and would verify nothing; git already stores a blob id for every committed fixture. stdout_crlf_pairs is recorded instead, because .gitattributes normalizes these paths to LF and a fixture with CRLF in it would be committed with bytes other than the ones observed.'
    stderr_note    = 'Three stderr fields, because one is not enough. stderr_first_line is the literal first line of the stream. stderr_first_text is the first line carrying non-whitespace. They differ: tfsec opens its 365-byte deprecation banner with a blank line, so stderr_first_line is the empty string on a capture that produced 12 lines, and either field read on its own can mislead - for tfsec the first line with text on it is a rule of equals signs. stderr_head therefore carries the first four lines verbatim, and it is stderr_head that shows the two tfsec runs emitting the same banner whether the run found 119 results or none: the observation behind the finding that the banner carries no signal about whether tfsec did any work.'
    scanner_versions = $Versions
    corpus_recorded_utc = $corpus.recorded_utc
    scan_roots     = $rootSummary
    # .ToArray(), not @($Records): measured on PS 5.1, ConvertTo-Json throws
    # "Argument types do not match" on a List[object] whose items are ordered
    # dictionaries, and @() around the list does not help. A real object[] does.
    captures       = $Records.ToArray()
}

# ConvertTo-Json on PS 5.1 emits CRLF between lines, and .gitattributes normalizes
# artifacts/** to LF - so the bytes on disk would differ from the bytes committed.
# String.Replace, ordinal: a real CR or LF inside a JSON string value is escaped by
# the serializer as \r or \n (two characters), so the only CRLF left in the text is
# formatting. WriteAllText with UTF8Encoding($false) because Set-Content and
# Out-File both prepend a UTF-8 BOM on PS 5.1, and a text-mode Python reader
# rejects the result - measured, open(path, encoding="utf-8") raises "Unexpected
# UTF-8 BOM". The bytes path accepts it, which is what makes a BOM here a silent
# defect rather than a loud one.
$json = ($manifest | ConvertTo-Json -Depth 8).Replace("`r`n", "`n")
if (-not $json.EndsWith("`n")) { $json += "`n" }
[IO.File]::WriteAllText($ManifestPath, $json, (New-Object Text.UTF8Encoding $false))
# The success line used to say "no BOM" without looking. Both halves are measured
# now, against the file as it is on disk: the first three bytes, and the same
# json.load validator every fixture went through. tests/harvest/test_fixtures.py
# asserts the same two properties of the committed manifest; this is the same
# check at the moment of writing, where the remedy is still obvious.
#
# The byte check is not redundant with the validator. Measured: the validator's
# json.loads-over-bytes path ACCEPTS a leading UTF-8 BOM, so a BOM'd manifest
# would pass it and fail later in any consumer that opens the file as text. The
# three bytes are the only thing here that catches one.
$manifestBytes = [IO.File]::ReadAllBytes($ManifestPath)
$manifestBom = ($manifestBytes.Length -ge 3 -and
                $manifestBytes[0] -eq 0xEF -and $manifestBytes[1] -eq 0xBB -and $manifestBytes[2] -eq 0xBF)
if ($manifestBom) {
    Die "artifacts/scanner-behavior.json was written with a UTF-8 BOM. json.loads over its bytes would still parse it, so this would not surface here - it surfaces in any consumer that opens the file as text, where json.load raises 'Unexpected UTF-8 BOM'. WriteAllText with a UTF8Encoding constructed to emit no preamble is supposed to make it impossible."
}
$manifestProbe = Test-JsonFile $ManifestPath
if (-not $manifestProbe.Ok -or $manifestProbe.TopLevel -cne 'object') {
    # Two different failures, and the parser only has something to say about one
    # of them: a wrong-shape manifest parses cleanly and leaves Error empty, so
    # naming the shape is the only way this message says anything.
    $why = if ($manifestProbe.Ok) {
        "it parsed as a JSON $($manifestProbe.TopLevel), not an object"
    } else {
        "the parser rejected it: $($manifestProbe.Error)"
    }
    Die "artifacts/scanner-behavior.json is not a JSON object after being written - $why. Every consumer reads it with json.load and indexes it by key."
}
Write-Ok "wrote artifacts/scanner-behavior.json ($($manifestBytes.Length) bytes, no BOM in the first three, json.load reads it as an $($manifestProbe.TopLevel))"

# Only on success: a failed run leaves the staged bytes for the operator to read,
# and the Die that sent them there names the path.
if (-not $KeepTemp) { Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction SilentlyContinue }

Write-Step 'summary'
foreach ($r in $Records) {
    $shape = if ($r.stdout_is_json) { $r.stdout_top_level } else { "NOT-JSON:$($r.stdout_top_level)" }
    Write-Host ("    {0,-8} {1,-11} exit={2,-3} stdout={3,9} B  {4,-16} stderr={5,6} B" -f `
        $r.scanner, $r.platform, $r.exit_code, $r.stdout_bytes, $shape, $r.stderr_bytes)
}
Write-Ok "$($Records.Count) fixtures under tests/harvest/fixtures/"
