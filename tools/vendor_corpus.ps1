#Requires -Version 5.1
<#
.SYNOPSIS
    Vendor corpus v0 at the commits pinned in tools/corpus.lock.json.
.DESCRIPTION
    Clones each source into tools/cache, checks out the exact pinned commit,
    then copies the declared subtree into corpus/vendor/<name>/ as a plain
    directory - not a submodule, so the dissertation artifact stays complete
    when archived. Upstream .git is not copied. Writes SOURCES.md attribution.

    Verifies rather than trusts: the checked-out HEAD must equal the pin, the
    cache clone must be clean before anything is copied, and an upstream tree
    with no license text is a hard failure rather than a warning.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$CacheDir = Join-Path $RepoRoot 'tools\cache'
$VendorDir = Join-Path $RepoRoot 'corpus\vendor'
$LockPath = Join-Path $RepoRoot 'tools\corpus.lock.json'

# Searched in this order, first match wins. Matched case-insensitively against
# the real filenames in the clone root, and the name actually found is what gets
# vendored and recorded: NTFS is case-insensitive but case-preserving, so probing
# Test-Path 'LICENSE.md' against an upstream 'License.md' would succeed and then
# record a filename that does not exist upstream.
$LicenseCandidates = @('LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING', 'COPYING.md')

# Source names become directory names under corpus\vendor and tools\cache, and
# one of those directories is passed to Remove-Item -Recurse -Force. A name
# carrying a path separator or '..' would place that deletion somewhere else
# entirely, so anything outside this class is rejected before a path is built
# from it. The lockfile is ours and the risk is low; the operation is not
# recoverable and the guard is one line.
$SourceNameRe = '^[a-z0-9][a-z0-9-]*$'

# The pin's shape, checked before the pin is used for anything at all - including
# the progress line that takes Substring(0, 12) of it. A short or empty commit
# there throws a raw ArgumentOutOfRangeException, which is precisely the
# "RuntimeException instead of the reason" failure the comment at :63-72 argues
# against. Lower-case hex only: git prints lower case, and an upper-case pin that
# passed here would fail the -cne comparison after checkout with a message about
# HEAD rather than about the lockfile.
$CommitRe = '^[0-9a-f]{40}$'

# `subtree` is joined into the destination path, created with New-Item -Force and
# written by Copy-Item, so it gets the same one-line guard `name` gets. A segment
# must start alphanumeric, which rejects '..' and any leading-dot segment; no
# backslash, no leading or trailing slash, and no drive letter (the colon is
# outside the class). Mixed case is allowed because upstream directory names are
# not ours to constrain. This is a create/write hazard rather than a delete one -
# nothing under a subtree path is deleted - but §A5's reasoning applies: the
# lockfile is ours, the risk is low, and the guard is one line.
$SubtreeRe = '^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$'

# Every field this script reads out of a source entry. Checked as a set before any
# of them is dereferenced: under Set-StrictMode -Version Latest a missing property
# throws PropertyNotFoundStrict, which names a PowerShell property instead of
# naming the lockfile field that is absent. `tests/test_corpus_lock.py` asserts the
# same seven names so CI catches it first, but the script run standalone should
# still say what is wrong. scope_note is optional and deliberately not listed.
$RequiredSourceFields = @('url', 'commit', 'ref', 'license', 'retrieved_utc',
    'pin_verified_utc', 'subtree')

function Write-Step($Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok($Message) { Write-Host "    OK   $Message" -ForegroundColor Green }
# Failures go to stderr, not to the host: Write-Host reaches an interactive
# console but not a caller capturing stderr, which would see a bare exit 1 with
# no reason given. Mirrors tools/bootstrap.ps1:30-35.
function Die($Message) { [Console]::Error.WriteLine("    FAIL $Message"); exit 1 }

if (-not (Test-Path $LockPath)) { Die "lockfile not found: $LockPath" }
# ReadAllText, not a bare Get-Content: PS 5.1 decodes a BOM-less file as ANSI, so
# non-ASCII in the lockfile would arrive as mojibake. This also strips a BOM if
# one is ever written by mistake, which ConvertFrom-Json otherwise tolerates
# silently and json.loads on the Python side does not.
$lock = [System.IO.File]::ReadAllText($LockPath) | ConvertFrom-Json

# A lockfile that declares no sources vendors nothing, and every per-source check
# below is satisfied by absence. Unguarded it does still fail - measured: with
# "sources": {} the script exits 1 on
# `The property 'Name' cannot be found on this object`, because member enumeration
# over zero properties throws PropertyNotFoundStrict under
# Set-StrictMode -Version Latest - but it fails naming a PowerShell property
# instead of naming the problem. Same reasoning as the @() wrapping below: fail
# with the reason, not with a RuntimeException. Enumerated through ForEach-Object
# rather than .Properties.Name for exactly that reason. The -or short-circuits,
# so $lock.sources is only touched once the property is known to exist.
$lockProps = @($lock.PSObject.Properties | ForEach-Object { $_.Name })
if (($lockProps -cnotcontains 'sources') -or ($null -eq $lock.sources)) {
    Die "lockfile $LockPath has no 'sources' map, so there is nothing to vendor"
}
$sourceNames = @($lock.sources.PSObject.Properties | ForEach-Object { $_.Name })
if ($sourceNames.Count -eq 0) {
    Die "lockfile $LockPath declares zero sources, so this run would vendor nothing and write an attribution file that attributes nothing. Refusing rather than reporting success."
}

foreach ($dir in @($CacheDir, $VendorDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# Corpus v0 - vendored sources')
$lines.Add('')
$lines.Add('Generated by `tools/vendor_corpus.ps1` from `tools/corpus.lock.json`. Do not edit by hand.')
$lines.Add('')
$lines.Add('These are third-party deliberately-insecure IaC repositories, vendored at')
$lines.Add('exact commits for evaluation reproducibility. Original licenses apply and')
$lines.Add('each upstream license file is retained alongside the vendored tree.')
$lines.Add('')
$lines.Add('Vendored trees hold the bytes upstream committed: each cache clone is checked')
$lines.Add('out with `core.autocrlf=false` and `core.eol=lf`, so no line-ending conversion')
$lines.Add('happens on the way in. `.gitattributes` normalizes `corpus/**` to LF in this')
$lines.Add('index; for both pins below every upstream blob is already LF, so that')
$lines.Add('normalization is a no-op and the committed blob ids equal the upstream ones.')
$lines.Add('')

foreach ($name in $sourceNames) {
    # -cnotmatch, not -notmatch: PS 5.1's -match/-notmatch are case-INSENSITIVE,
    # so 'TerraGoat' satisfies '^[a-z0-9][a-z0-9-]*$' and the guard would pass a
    # name it was written to reject.
    if ($name -cnotmatch $SourceNameRe) {
        Die "source name '$name' is not a safe directory name (expected $SourceNameRe). Refusing to build a path from it: one of the paths derived from this name is deleted with Remove-Item -Recurse -Force."
    }

    $src = $lock.sources.$name
    # Presence before shape, shape before use. -cnotcontains for the same reason
    # :66 uses it: -contains is case-insensitive, so a lockfile carrying 'Commit'
    # would satisfy the presence check and then throw on $src.commit.
    $srcFields = @($src.PSObject.Properties | ForEach-Object { $_.Name })
    $missing = @($RequiredSourceFields | Where-Object { $srcFields -cnotcontains $_ })
    if ($missing.Count -gt 0) {
        Die "source '$name' is missing lockfile field(s): $($missing -join ', '). This script reads all of $($RequiredSourceFields -join ', ')."
    }
    if ($src.commit -cnotmatch $CommitRe) {
        Die "source '$name' pin '$($src.commit)' is not a full 40-character lower-case commit SHA (expected $CommitRe). Transcribe the pin from upstream; never recompute it from what is on disk."
    }
    if ($src.subtree -cnotmatch $SubtreeRe) {
        Die "source '$name' subtree '$($src.subtree)' is not a safe relative POSIX path (expected $SubtreeRe). Refusing to build a destination path from it: that path is created and written to under corpus\vendor."
    }

    # A normal clone, not a bare one, despite the .git suffix on the name: the
    # working tree is what the subtree is copied from and what the cleanliness
    # check below inspects. --bare would leave nothing to copy.
    $clone = Join-Path $CacheDir "$name.git"
    $dest = Join-Path $VendorDir $name

    if (-not (Test-Path $clone)) {
        # A full clone, deliberately. --depth 1 or --single-branch would work
        # today only because both upstreams are dormant and their pins happen to
        # be the current branch tips; the first upstream commit after that leaves
        # the pinned SHA unreachable, and the failure reads like a network fault.
        #
        # core.autocrlf=false / core.eol=lf, set on the new clone itself rather
        # than passed per command, so the working tree Copy-Item reads holds the
        # bytes upstream committed. Git for Windows ships core.autocrlf=true in
        # its SYSTEM config, which this host has (measured: 141 CRLF pairs and a
        # 4887-byte terraform/aws/s3.tf against upstream's 4746-byte LF blob).
        # corpus/** text=auto eol=lf would still normalize that back to LF at
        # git-add time, so the committed blob is faithful either way - but the
        # vendored files on disk would not be, and anything that hashes one for a
        # provenance block would record a digest no other checkout can reproduce.
        # Passed at clone time and not merely afterwards because clone performs
        # its own initial checkout, and the later `git checkout <pin>` rewrites
        # nothing when the pin is already the branch tip.
        Write-Step "cloning $name (full clone: a shallow clone cannot reach an unreferenced pin)"
        & git clone --quiet --config core.autocrlf=false --config core.eol=lf $src.url $clone
        $cloneExit = $LASTEXITCODE
        if ($cloneExit -ne 0) { Die "git clone $($src.url) failed (exit $cloneExit)" }
    }
    else {
        Write-Ok "reusing cache clone $clone"
    }

    # Re-asserted on the reuse path as well, so a clone created before this
    # setting existed is not silently trusted. It cannot rewrite an
    # already-CRLF working tree, because git checkout only writes files whose
    # content changes - but it does make the cleanliness check below report that
    # clone as dirty, which is the correct outcome rather than a hidden one: its
    # working tree is not the pinned content.
    foreach ($cfg in @(@('core.autocrlf', 'false'), @('core.eol', 'lf'))) {
        & git -C $clone config $cfg[0] $cfg[1]
        $cfgExit = $LASTEXITCODE
        if ($cfgExit -ne 0) { Die "git config $($cfg[0]) failed for $name (exit $cfgExit)" }
    }

    Write-Step "checking out $name @ $($src.commit.Substring(0, 12))"
    # Each exit code captured on the line after its call. $LASTEXITCODE is global,
    # so checking it only after the checkout would read the checkout's status and
    # never the fetch's. A failed fetch followed by a checkout of an absent commit
    # still dies at the checkout - but a failed fetch against a stale cache that
    # happens to contain the pin succeeds silently, and the network failure is
    # never learned.
    #
    # The fetch is skipped when the pin is already an object in the cache clone,
    # which is what makes a re-vendor possible offline: a pinned corpus that can
    # only be reproduced with a working network is a weaker reproducibility claim
    # than one that cannot. This is not the loose "trust the cache" behaviour the
    # capture above guards against - the probe asks for this exact commit, and the
    # cleanliness and HEAD checks below still run either way. `^{commit}` makes it
    # a commit lookup rather than any-object lookup, and --quiet keeps a missing
    # object silent (exit 1, no stderr) so an absent pin reads as a decision to
    # fetch rather than as noise.
    & git -C $clone rev-parse --verify --quiet "$($src.commit)^{commit}" | Out-Null
    $pinPresentExit = $LASTEXITCODE
    if ($pinPresentExit -eq 0) {
        Write-Ok "$name pin is already in the cache clone; skipping fetch (offline re-vendor)"
    }
    else {
        & git -C $clone fetch --quiet origin
        $fetchExit = $LASTEXITCODE
        if ($fetchExit -ne 0) { Die "git fetch origin failed for $name (exit $fetchExit)" }
    }

    & git -C $clone checkout --quiet $src.commit
    $checkoutExit = $LASTEXITCODE
    if ($checkoutExit -ne 0) { Die "checkout $($src.commit) failed for $name (exit $checkoutExit)" }

    $actual = (& git -C $clone rev-parse HEAD | Out-String).Trim()
    $revParseExit = $LASTEXITCODE
    if ($revParseExit -ne 0) { Die "git rev-parse HEAD failed for $name (exit $revParseExit)" }
    # -cne, not -ne: PS 5.1's -ne is case-insensitive and git prints lowercase
    # hex, so a pin recorded in upper case would compare equal here and then
    # disagree with every other record of it.
    if ($actual -cne $src.commit) { Die "$name HEAD is $actual, expected $($src.commit)" }
    Write-Ok "$name pinned at $actual"

    # tools\cache\<name>.git is reused across runs, and git checkout carries local
    # modifications forward for any file identical between the two commits. So a
    # clone left dirty by an earlier run - or edited by hand while debugging -
    # would silently vendor modified upstream code, and the commit would then
    # record that modification as authoritative provenance. Checked after the pin
    # is confirmed and before anything is copied. @() wrapped: see the file-count
    # comment below.
    $dirty = @(& git -C $clone status --porcelain)
    $statusExit = $LASTEXITCODE
    if ($statusExit -ne 0) { Die "git status --porcelain failed for $name (exit $statusExit)" }
    if ($dirty.Count -gt 0) {
        Die "cache clone $clone is not clean, so the subtree about to be vendored is not the pinned upstream content. Dirty entries: $($dirty -join ' | '). Inspect them; the cache clone is disposable, so deleting only that one directory and re-running is the safe repair."
    }
    Write-Ok "$name cache clone is clean at the pin"

    # Every guard in this loop runs BEFORE $dest is cleared. The natural writing
    # order is clear-the-destination then read-the-source, and that is what this
    # loop did first - but any Die after the clear leaves an empty or partial
    # corpus/vendor/<name> that a later `git add corpus/` would commit as
    # provenance. Both halves were measured against the earlier ordering: a
    # lockfile naming a subtree upstream does not have left the destination at 0
    # files, and a license search that found nothing left it at 17 files with
    # `D corpus/vendor/terragoat/LICENSE` in git status - a vendored tree stripped
    # of the license text this repository redistributes it under. Validate, then
    # destroy.
    $subtreeSrc = Join-Path $clone ($src.subtree -replace '/', '\')
    if (-not (Test-Path $subtreeSrc)) {
        Die "$name subtree '$($src.subtree)' not found upstream at $subtreeSrc"
    }

    # Counted over the SOURCE subtree. This check first counted the copy, and had
    # to be placed before the license was copied into $dest or it could never
    # reach 0 - measured: an empty upstream subtree still left $dest holding the
    # copied LICENSE, so the guard read like a live one while being unreachable.
    # Counting the source refuses the same input one step earlier and leaves the
    # good tree standing. A post-copy count on top of this one would be the dead
    # guard instead: Copy-Item runs under $ErrorActionPreference = 'Stop' and
    # cannot half-succeed silently, so it could only fire in a state this check
    # has already refused.
    $subtreeFiles = @(Get-ChildItem -LiteralPath $subtreeSrc -Recurse -File)
    if ($subtreeFiles.Count -eq 0) {
        Die "$name subtree '$($src.subtree)' holds no files upstream at $subtreeSrc, so there is nothing to vendor"
    }

    # Resolved before the clear too, and for the same reason. Enumerated rather
    # than probed with Test-Path so the name recorded is the one upstream actually
    # uses. -eq is case-insensitive here and that is deliberate: the match should
    # be lax, the recorded name exact.
    $rootFiles = @(Get-ChildItem -LiteralPath $clone -File)
    $licenseFile = $null
    foreach ($candidate in $LicenseCandidates) {
        $licenseFile = $rootFiles | Where-Object { $_.Name -eq $candidate } | Select-Object -First 1
        if ($null -ne $licenseFile) { break }
    }
    if ($null -eq $licenseFile) {
        Die "no license file found upstream for $name (looked for: $($LicenseCandidates -join ', ')). This repository redistributes $($src.license) code; vendoring a tree without its license text is a licensing failure, not a cosmetic gap."
    }

    if (Test-Path $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null

    $subtreeDest = Join-Path $dest ($src.subtree -replace '/', '\')
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $subtreeDest) | Out-Null
    # $subtreeDest deliberately does not exist yet: Copy-Item -Recurse copies the
    # source directory *as* a destination that does not exist, but *into* one that
    # does, which would nest the subtree one level deeper on every re-run.
    Copy-Item -LiteralPath $subtreeSrc -Destination $subtreeDest -Recurse -Force

    Copy-Item -LiteralPath $licenseFile.FullName -Destination (Join-Path $dest $licenseFile.Name) -Force
    Write-Ok "$name license text vendored as $($licenseFile.Name)"

    # @() wrapped: an enumeration that yields nothing is $null in PS 5.1, and
    # $null.Count under Set-StrictMode -Version Latest throws
    # PropertyNotFoundStrict instead of reporting 0 - a confusing error in place of
    # a clear one.
    $vendored = @(Get-ChildItem -LiteralPath $dest -Recurse -File)
    $fileCount = $vendored.Count
    $byteCount = ($vendored | Measure-Object -Property Length -Sum).Sum
    Write-Ok "$name vendored ($fileCount files, $byteCount bytes)"

    $lines.Add("## $name")
    $lines.Add('')
    $lines.Add("- Upstream: <$($src.url)>")
    $lines.Add("- Commit: ``$($src.commit)`` (ref ``$($src.ref)``)")
    $lines.Add("- License: $($src.license), upstream file ``$($licenseFile.Name)`` retained at ``corpus/vendor/$name/$($licenseFile.Name)``")
    $lines.Add("- Pin verified against upstream: $($src.pin_verified_utc)")
    $lines.Add("- Retrieved (vendored): $($src.retrieved_utc)")
    $lines.Add("- Vendored subtree: ``$($src.subtree)``")
    $lines.Add("- Vendored tree: ``corpus/vendor/$name/`` ($fileCount files, $byteCount bytes, license text included)")
    # -ccontains, not -contains: :66 and :126 both use the case-sensitive operator
    # for this same kind of lookup, and this was the one place the file did not.
    # The key is ours and lower-case, so nothing changes today; consistency here is
    # what keeps the convention readable as a convention.
    if ($src.PSObject.Properties.Name -ccontains 'scope_note') {
        $lines.Add("- Scope: $($src.scope_note)")
    }
    $lines.Add('')
}

$outPath = Join-Path $VendorDir 'SOURCES.md'
# WriteAllText with an explicit BOM-less encoder: Out-File -Encoding utf8 and
# Set-Content -Encoding utf8 both emit a UTF-8 BOM on PS 5.1, and a BOM in a
# provenance file is a silent corruption rather than a crash. TrimEnd on the
# joined body so the per-source trailing blank line does not accumulate into a
# blank line at EOF.
$body = ($lines -join "`n").TrimEnd("`n")
[System.IO.File]::WriteAllText($outPath, "$body`n", (New-Object System.Text.UTF8Encoding $false))
Write-Host ""
Write-Host "Wrote $outPath" -ForegroundColor Green
