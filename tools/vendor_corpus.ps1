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

    Writes in two phases. Each subtree is copied into corpus/vendor/<name>.new
    first and swapped into place with renames only after every source has been
    staged, so no failure - a bad lockfile, a locked file, a full disk, Ctrl-C -
    can leave a vendored tree half-replaced.
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
# "RuntimeException instead of the reason" failure the comment at :103-112 argues
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
# A condition the operator must see but that does not invalidate the run. stderr for
# the same reason Die uses it: a caller capturing output should get the warning.
function Write-Warn($Message) { [Console]::Error.WriteLine("    WARN $Message") }

# A .NET method that throws inside try/catch arrives wrapped in a
# MethodInvocationException whose own Message reads 'Exception calling "Move" with
# "2" argument(s): ...'. The inner exception carries the sentence that names the
# actual problem ('Access to the path ... is denied'), which is the one worth putting
# in a failure message.
function Get-FailureMessage($ErrorRecord) {
    if ($null -ne $ErrorRecord.Exception.InnerException) {
        return $ErrorRecord.Exception.InnerException.Message
    }
    return $ErrorRecord.Exception.Message
}

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

# The run is two phases. Phase 1 clones, verifies and copies each subtree into a
# staging sibling `corpus\vendor\<name>.new`, touching no vendored tree. Phase 2
# swaps each staged tree into place with renames and then writes SOURCES.md. This
# is what a failure between "the old tree is gone" and "the new tree is complete"
# used to cost: a locked file or a full disk during the copy left
# corpus/vendor/<name> empty or subtree-only-without-LICENSE, and a later
# `git add corpus/` would commit that as provenance.
$staged = New-Object System.Collections.Generic.List[object]

foreach ($name in $sourceNames) {
    # -cnotmatch, not -notmatch: PS 5.1's -match/-notmatch are case-INSENSITIVE,
    # so 'TerraGoat' satisfies '^[a-z0-9][a-z0-9-]*$' and the guard would pass a
    # name it was written to reject.
    if ($name -cnotmatch $SourceNameRe) {
        Die "source name '$name' is not a safe directory name (expected $SourceNameRe). Refusing to build a path from it: one of the paths derived from this name is deleted with Remove-Item -Recurse -Force."
    }

    $src = $lock.sources.$name
    # Presence before shape, shape before use. -cnotcontains for the same reason
    # :114 uses it: -contains is case-insensitive, so a lockfile carrying 'Commit'
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

    # Every guard in this loop runs before anything is written, and since the write
    # now goes to a staging sibling, nothing in this loop can leave the vendored
    # tree in a state it was not already in. The guards are still ordered
    # validate-then-write rather than relying on the staging alone: an earlier
    # ordering cleared the destination first, and both halves of that were measured
    # - a lockfile naming a subtree upstream does not have left the destination at 0
    # files, and a license search that found nothing left it at 17 files with
    # `D corpus/vendor/terragoat/LICENSE` in git status, a vendored tree stripped of
    # the license text this repository redistributes it under. Staging closes the
    # I/O half of that window; the ordering closes the input half, and neither
    # substitutes for the other.
    $subtreeSrc = Join-Path $clone ($src.subtree -replace '/', '\')
    if (-not (Test-Path $subtreeSrc)) {
        Die "$name subtree '$($src.subtree)' not found upstream at $subtreeSrc"
    }

    # Counted over the SOURCE subtree. This check first counted the copy, and had
    # to be placed before the license was copied into the destination or it could
    # never reach 0 - measured: an empty upstream subtree still left the destination
    # holding the copied LICENSE, so the guard read like a live one while being
    # unreachable. Counting the source refuses the same input one step earlier and
    # leaves the good tree standing. A post-copy count on top of this one would be
    # the dead guard instead: Copy-Item runs under $ErrorActionPreference = 'Stop'
    # and cannot half-succeed silently, so it could only fire in a state this check
    # has already refused.
    $subtreeFiles = @(Get-ChildItem -LiteralPath $subtreeSrc -Recurse -File)
    if ($subtreeFiles.Count -eq 0) {
        Die "$name subtree '$($src.subtree)' holds no files upstream at $subtreeSrc, so there is nothing to vendor"
    }

    # Resolved before any write too, and for the same reason. Enumerated rather
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

    # --- phase 1 ends here: stage the new tree beside the old one, do not touch
    # the old one. Everything above validated the source; everything below writes
    # only to corpus\vendor\<name>.new, so no failure in this loop - a Die, a
    # locked file, a full disk, Ctrl-C - can leave corpus\vendor\<name> in a state
    # it was not already in. $SourceNameRe forbids '.', so '<name>.new' and
    # '<name>.old' can never collide with another source's directory.
    $stage = Join-Path $VendorDir "$name.new"
    $backup = Join-Path $VendorDir "$name.old"

    # A leftover .old means an earlier run stopped between the two renames in phase
    # 2, or could not delete the backup after a successful swap. The two cases are
    # distinguishable and only one of them is dangerous: if the vendored tree is
    # missing, the .old copy may be the only one there is and this script will not
    # touch it. If the vendored tree is present, the .old is a stale backup and is
    # removed here - before anything is written, so a removal failure costs nothing.
    # A leftover .new is always reproducible from upstream, so it goes without
    # comment.
    if (Test-Path $backup) {
        if (-not (Test-Path $dest)) {
            Die "found a leftover $backup and no vendored tree at $dest. That backup may be the only copy of the vendored $name tree, so this script will not delete or overwrite it. Rename it to corpus/vendor/$name (or restore the committed bytes with git checkout -- corpus) and re-run."
        }
        Write-Warn "removing a stale $backup left by an earlier run; corpus/vendor/$name is present, so this copy is redundant"
        try {
            Remove-Item -LiteralPath $backup -Recurse -Force
        }
        catch {
            Die "could not remove the stale backup $backup ($(Get-FailureMessage $_)). Nothing has been written yet. Remove it by hand - it would otherwise sit inside corpus/vendor/ and be picked up by a later git add corpus/."
        }
    }
    if (Test-Path $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $stage | Out-Null

    $subtreeDest = Join-Path $stage ($src.subtree -replace '/', '\')
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $subtreeDest) | Out-Null
    # $subtreeDest deliberately does not exist yet: Copy-Item -Recurse copies the
    # source directory *as* a destination that does not exist, but *into* one that
    # does, which would nest the subtree one level deeper on every re-run.
    Copy-Item -LiteralPath $subtreeSrc -Destination $subtreeDest -Recurse -Force

    Copy-Item -LiteralPath $licenseFile.FullName -Destination (Join-Path $stage $licenseFile.Name) -Force
    Write-Ok "$name staged at $stage with its $($licenseFile.Name)"

    $staged.Add([pscustomobject]@{
            Name    = $name
            Src     = $src
            Dest    = $dest
            Stage   = $stage
            Backup  = $backup
            License = $licenseFile.Name
        })
}

# Phase 2. Nothing above this line modified corpus\vendor\<name>; nothing below it
# reads upstream. Each source is swapped in with two directory renames rather than a
# clear followed by a copy, so the destination holds the old bytes or the new bytes
# and never a mixture.
#
# [System.IO.Directory]::Move, not Move-Item, and this is the whole point of the
# restructure rather than a style preference. Measured on this host, renaming a tree
# that holds one file with an exclusive handle (FileShare None) three levels down:
#
#   Remove-Item -Recurse -Force  throws, and DELETES the rest of the tree (1 of 3
#                                files left) - the pre-change failure mode
#   Move-Item                    throws, and SPLITS the tree (1 file left at the
#                                source, 2 already at the destination)
#   [IO.Directory]::Move         throws, source complete at 3 files, destination
#                                not created at all
#
# Move-Item recurses per entry and stops where it fails, so swapping with it would
# have reproduced the same partial-tree defect one level up. Directory.Move is a
# single rename: it either happens or it does not. Both paths are siblings in
# corpus\vendor, so this is always a same-volume rename and never a copy.
#
# SOURCES.md is still written once, after every swap. That is deliberate and it is
# also what makes a mid-loop Die safe now: a failure in phase 1 leaves both the
# vendored trees and their attribution file exactly as the previous successful run
# left them, so the census in SOURCES.md still describes what is on disk. Under the
# old single-loop ordering, source #1 was already re-vendored by the time source #2
# failed and SOURCES.md still described the previous run.
foreach ($item in $staged) {
    $name = $item.Name
    $src = $item.Src

    if (Test-Path $item.Dest) {
        try {
            [System.IO.Directory]::Move($item.Dest, $item.Backup)
        }
        catch {
            Die "could not move the existing $name tree aside: $(Get-FailureMessage $_). Nothing was lost for $name specifically - corpus/vendor/$name still holds the previous tree, complete, and the new one is staged at $($item.Stage); delete that stage directory to abandon this run. This claim covers $name only: phase 2 swaps the sources one at a time, so every source with an '<name> vendored (...)' line above this message already carries its NEW tree. SOURCES.md is written after the loop and so was not rewritten - its census still describes the previous run. Run git status corpus to see which trees actually changed."
        }
    }
    try {
        [System.IO.Directory]::Move($item.Stage, $item.Dest)
    }
    catch {
        $swapError = Get-FailureMessage $_
        # Put the old tree back before dying: an absent destination is the one state
        # this restructure exists to prevent.
        if ((Test-Path $item.Backup) -and -not (Test-Path $item.Dest)) {
            try {
                [System.IO.Directory]::Move($item.Backup, $item.Dest)
                Die "could not move the staged $name tree into place: $swapError. The previous tree has been restored to corpus/vendor/$name; the staged copy is still at $($item.Stage)."
            }
            catch {
                Die "could not move the staged $name tree into place ($swapError) and could not restore the previous one ($(Get-FailureMessage $_)). corpus/vendor/$name is absent right now: the previous tree is at $($item.Backup) and the new one at $($item.Stage). Rename one of them to corpus/vendor/$name; git checkout -- corpus also restores the committed bytes."
            }
        }
        Die "could not move the staged $name tree into place: $swapError. corpus/vendor/$name is unchanged."
    }
    # The swap has happened and corpus/vendor/<name> is the new tree, so a failure to
    # delete the backup is a leftover directory rather than a broken corpus. Warned
    # about and carried past, deliberately: dying here would skip the SOURCES.md
    # write and leave the attribution file describing the previous run, which is the
    # defect N5 named. The next run removes the leftover in phase 1.
    if (Test-Path $item.Backup) {
        try {
            Remove-Item -LiteralPath $item.Backup -Recurse -Force
        }
        catch {
            Write-Warn "the $name swap succeeded but $($item.Backup) could not be deleted ($(Get-FailureMessage $_)). corpus/vendor/$name is the new tree; remove that leftover directory before committing corpus/."
        }
    }

    # @() wrapped: an enumeration that yields nothing is $null in PS 5.1, and
    # $null.Count under Set-StrictMode -Version Latest throws
    # PropertyNotFoundStrict instead of reporting 0 - a confusing error in place of
    # a clear one. Counted after the swap, over the tree that is actually there, so
    # the census in SOURCES.md is a measurement of the destination rather than of
    # the staging copy.
    $vendored = @(Get-ChildItem -LiteralPath $item.Dest -Recurse -File)
    $fileCount = $vendored.Count
    $byteCount = ($vendored | Measure-Object -Property Length -Sum).Sum
    Write-Ok "$name vendored ($fileCount files, $byteCount bytes, license text $($item.License))"

    $lines.Add("## $name")
    $lines.Add('')
    $lines.Add("- Upstream: <$($src.url)>")
    $lines.Add("- Commit: ``$($src.commit)`` (ref ``$($src.ref)``)")
    $lines.Add("- License: $($src.license), upstream file ``$($item.License)`` retained at ``corpus/vendor/$name/$($item.License)``")
    $lines.Add("- Pin verified against upstream: $($src.pin_verified_utc)")
    $lines.Add("- Retrieved (vendored): $($src.retrieved_utc)")
    $lines.Add("- Vendored subtree: ``$($src.subtree)``")
    $lines.Add("- Vendored tree: ``corpus/vendor/$name/`` ($fileCount files, $byteCount bytes, license text included)")
    # -ccontains, not -contains: :114 and :164 both use the case-sensitive operator
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
