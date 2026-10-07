"""tfsec: the scanner whose resource field is absolute-pathed and sometimes attribute-suffixed.

tfsec's `resource` string is a `<type>.<name>` Terraform address on 118 of 119
corpus v0 findings, and on the 119th (`AVD-AWS-0180`) carries a third,
attribute-naming component: `aws_db_instance.default.publicly_accessible`.
Unlike checkov's `resource`, tfsec's never carries a Dockerfile path, a
provider block or a secret hash in corpus v0 (measured: every one of the 119
values matches the `<type>.<name>[.attribute]` shape) - tfsec only ever
flags real Terraform resources, so this module's identity resolution has
one recognized shape and one fallback, not checkov's five-way classifier.

tfsec is also the one scanner whose paths need real work before they can join
anything: `location.filename` is an absolute Windows path on all 119 findings
(`D:\\Research\\corpus\\vendor\\terragoat\\terraform\\aws\\db-app.tf`), where
checkov emits `/ec2.tf` and trivy emits `ec2.tf` for the same file. Gate 3
(design spec §10) is the assertion that `rebase_to_scan_root` closes that gap
for every one of the 119, not just for one hand-picked example.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from iacrisk import identity, rubric, taxonomy
from iacrisk.scanners.base import rebase_to_scan_root
from iacrisk.scanners.checkov import CheckovAdapter
from iacrisk.scanners.tfsec import TfsecAdapter, capture_scan_root
from iacrisk.scanners.trivy import TrivyAdapter

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "harvest" / "fixtures"
TERRAFORM_SCAN_ROOT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"
KUBERNETES_SCAN_ROOT = REPO_ROOT / "corpus" / "vendor" / "kubernetes-goat" / "scenarios"


def _load_fixture(name: str) -> Any:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _raw_results(name: str) -> list[dict[str, Any]]:
    """Every `results` entry of one fixture, read independently of `TfsecAdapter`.

    Walks the same JSON shape the adapter walks rather than asking the adapter
    what it saw, so the `in` side of `in == out + dropped` is not the adapter
    grading its own homework - the same reasoning `test_trivy.py` and
    `test_checkov.py` apply to their own `_raw_*` helpers.
    """
    return list(_load_fixture(name)["results"])


def _capture_root() -> Path:
    """The root the terraform fixture was captured under, which is where its absolute
    paths live - not `TERRAFORM_SCAN_ROOT`, unless this checkout happens to sit there.
    """
    return capture_scan_root(_load_fixture("tfsec-terraform.json"), TERRAFORM_SCAN_ROOT, REPO_ROOT)


def _terraform_result() -> Any:
    return TfsecAdapter().parse(_load_fixture("tfsec-terraform.json"), _capture_root(), None)


# --- retention: every input finding becomes exactly one finding or one drop --------


def test_every_finding_is_retained_or_dropped() -> None:
    raw = _raw_results("tfsec-terraform.json")
    result = _terraform_result()
    assert len(raw) == len(result.findings) + len(result.dropped)


def test_nothing_is_dropped_in_corpus_v0() -> None:
    """Every one of the 119 results carries a non-empty `rule_id` (measured),
    so nothing should land in `dropped` for this fixture - unlike the
    constructed drop case below, which needs a hand-built record because
    corpus v0 does not exercise a missing `rule_id`.
    """
    raw = _raw_results("tfsec-terraform.json")
    assert raw
    assert all(r.get("rule_id") for r in raw)
    assert _terraform_result().dropped == ()


def test_a_missing_rule_id_is_dropped_not_raised() -> None:
    """Constructed: corpus v0 never omits `rule_id`, so this guards a shape the
    fixture does not exercise, matching `TrivyAdapter`'s and `CheckovAdapter`'s
    own defensive guards for their equivalent id fields.
    """
    raw = {
        "results": [
            {
                "rule_id": "",
                "rule_description": "made up for this test",
                "resolution": "n/a",
                "severity": "LOW",
                "resource": "aws_made_up_thing.example",
                "location": {
                    "filename": str(TERRAFORM_SCAN_ROOT / "made-up.tf"),
                    "start_line": 1,
                    "end_line": 2,
                },
            }
        ]
    }
    result = TfsecAdapter().parse(raw, TERRAFORM_SCAN_ROOT, None)
    assert result.findings == ()
    assert len(result.dropped) == 1
    assert result.dropped[0][1] == "rule_id missing or empty"


# --- terraform identity: the plain `<type>.<name>` case, grounded in the fixture ---


def test_a_plain_terraform_resource_resolves_with_no_fingerprint() -> None:
    """`aws_db_instance.default` on `AVD-AWS-0177` - one of 6 corpus v0 findings
    on this exact resource string with no attribute suffix (verified against
    the raw fixture, not assumed)."""
    raw = _raw_results("tfsec-terraform.json")
    row = next(r for r in raw if r["rule_id"] == "AVD-AWS-0177")
    assert row["resource"] == "aws_db_instance.default"

    result = _terraform_result()
    finding = next(f for f in result.findings if f.rule_id == "AVD-AWS-0177")
    assert finding.identity_kind == "terraform"
    assert finding.context_eligible is True
    assert finding.resource_identity == identity.terraform_identity("aws_db_instance", "default")
    assert finding.fingerprint is None


# --- terraform identity: the attribute-suffixed case -------------------------------


def test_an_attribute_suffixed_resource_splits_into_identity_and_fingerprint() -> None:
    """`aws_db_instance.default.publicly_accessible` on `AVD-AWS-0180` - the
    single corpus v0 row carrying a third, attribute-naming component
    (measured: 118 of 119 `resource` values carry exactly one dot, this one
    carries two). The trailing component becomes the fingerprint; it must not
    remain part of the identity, or this resource would fail to join the same
    `aws_db_instance.default` other tfsec and trivy findings resolve to.
    """
    raw = _raw_results("tfsec-terraform.json")
    row = next(r for r in raw if r["rule_id"] == "AVD-AWS-0180")
    assert row["resource"] == "aws_db_instance.default.publicly_accessible"

    result = _terraform_result()
    finding = next(f for f in result.findings if f.rule_id == "AVD-AWS-0180")
    assert finding.identity_kind == "terraform"
    assert finding.context_eligible is True
    assert finding.resource_identity == identity.terraform_identity("aws_db_instance", "default")
    assert finding.fingerprint == "publicly_accessible"


def test_the_suffixed_and_plain_findings_share_one_identity() -> None:
    """The whole point of splitting the suffix off: `AVD-AWS-0180` (suffixed)
    and `AVD-AWS-0177` (plain) name the same `aws_db_instance.default`, so
    they must resolve to the identical `resource_identity` string - otherwise
    the dedupe key (`identity.dedupe_key`) would never see them as the same
    resource despite tfsec itself pointing at one.
    """
    result = _terraform_result()
    suffixed = next(f for f in result.findings if f.rule_id == "AVD-AWS-0180")
    plain = next(f for f in result.findings if f.rule_id == "AVD-AWS-0177")
    assert suffixed.resource_identity == plain.resource_identity


# --- terraform identity: data sources (S1 §5.1) - constructed, not corpus-observed -


def test_a_data_source_resource_strips_the_data_prefix_per_s1_section_5_1() -> None:
    """Fixed round. Constructed: none of corpus v0's 119 tfsec `resource`
    values carries a `data.` prefix (measured), so this shape has to be
    built by hand rather than found in the fixture - but it is not
    hypothetical. checkov already flags the identical Terraform `data` block
    in this corpus (`aws_iam_policy_document.policy` in `es.tf`, verified
    against the raw checkov fixture below) and renders it with no `data`
    component anywhere in the string - exactly what S1 §5.1 prescribes for a
    scanner-flagged data source ("`type.name` with no instance key"). A
    tfsec finding on that same resource must resolve to the identical
    identity, or the two scanners' findings on it could never meet at Task
    8's dedupe key.

    An earlier version of `_resolve_terraform` ran `_TFSEC_RESOURCE_RE`
    directly against the raw string with no `data.` handling at all: it
    matched `data.aws_iam_policy_document.policy` as `type="data"`,
    `name="aws_iam_policy_document"`, `attribute="policy"` - a wrong
    identity that collides every data source of one type into one string,
    and a bogus fingerprint that is really the data source's own name. This
    test is what that regression would fail.
    """
    checkov_raw = json.loads((FIXTURES_DIR / "checkov-terraform.json").read_text(encoding="utf-8"))
    checkov_data_source_rows = [
        c
        for doc in checkov_raw
        for c in (doc.get("results") or {}).get("failed_checks") or []
        if c.get("resource") == "aws_iam_policy_document.policy"
    ]
    assert checkov_data_source_rows  # grounds the construction below in a real corpus fact

    raw = {
        "results": [
            {
                "rule_id": "AVD-AWS-0057",
                "rule_description": "made up for this test",
                "resolution": "n/a",
                "severity": "LOW",
                "resource": "data.aws_iam_policy_document.policy",
                "location": {
                    "filename": str(TERRAFORM_SCAN_ROOT / "made-up.tf"),
                    "start_line": 1,
                    "end_line": 2,
                },
            }
        ]
    }
    result = TfsecAdapter().parse(raw, TERRAFORM_SCAN_ROOT, None)
    (finding,) = result.findings
    assert finding.identity_kind == "terraform"
    assert finding.context_eligible is True
    assert finding.fingerprint is None
    assert finding.resource_identity == identity.terraform_identity(
        "aws_iam_policy_document", "policy"
    )
    # The point of the fix: this must equal checkov's own rendering of the
    # identical resource, not merely "look like" a terraform identity.
    assert finding.resource_identity == checkov_data_source_rows[0]["resource"]


def test_a_four_component_data_source_still_splits_off_the_fingerprint() -> None:
    """Constructed: corpus v0 exercises neither a `data.`-prefixed resource nor
    an attribute-suffixed one together at once. S1 §5.1 gives a data source
    the same bare `type.name` form a managed resource takes, so the same
    attribute-splitting rule that applies to `aws_db_instance.default.
    publicly_accessible` (three components) must also apply one component
    further in, once the leading `data.` is stripped.
    """
    raw = {
        "results": [
            {
                "rule_id": "AVD-AWS-0057",
                "rule_description": "made up for this test",
                "resolution": "n/a",
                "severity": "LOW",
                "resource": "data.aws_iam_policy_document.policy.statement",
                "location": {
                    "filename": str(TERRAFORM_SCAN_ROOT / "made-up.tf"),
                    "start_line": 1,
                    "end_line": 2,
                },
            }
        ]
    }
    result = TfsecAdapter().parse(raw, TERRAFORM_SCAN_ROOT, None)
    (finding,) = result.findings
    assert finding.identity_kind == "terraform"
    assert finding.resource_identity == identity.terraform_identity(
        "aws_iam_policy_document", "policy"
    )
    assert finding.fingerprint == "statement"


# --- terraform identity: unrecognized resource shapes are unresolved, not guessed --


def test_a_missing_resource_is_unresolved_and_context_ineligible() -> None:
    """Constructed: all 119 corpus v0 results carry a non-empty `resource`
    (measured), so this exercises a shape the fixture does not - a `resource`
    that is absent must not be guessed at as terraform, or S3b would extract
    context for a resource this adapter never actually identified.
    """
    raw = {
        "results": [
            {
                "rule_id": "AVD-AWS-9999",
                "rule_description": "made up for this test",
                "resolution": "n/a",
                "severity": "LOW",
                "location": {
                    "filename": str(TERRAFORM_SCAN_ROOT / "made-up.tf"),
                    "start_line": 1,
                    "end_line": 2,
                },
            }
        ]
    }
    result = TfsecAdapter().parse(raw, TERRAFORM_SCAN_ROOT, None)
    (finding,) = result.findings
    assert finding.resource_identity == identity.UNRESOLVED
    assert finding.identity_kind == "unresolved"
    assert finding.context_eligible is False
    assert finding.fingerprint is None


def test_a_resource_with_two_extra_components_is_unresolved() -> None:
    """Constructed: corpus v0's one attribute-suffixed value carries exactly one
    extra component (previous tests); a value with two is a shape this module
    has never seen tfsec emit, so it must fall to `<unresolved>` rather than
    guess which of the two trailing components is the real attribute.
    """
    raw = {
        "results": [
            {
                "rule_id": "AVD-AWS-9998",
                "rule_description": "made up for this test",
                "resolution": "n/a",
                "severity": "LOW",
                "resource": "aws_db_instance.default.tags.Name",
                "location": {
                    "filename": str(TERRAFORM_SCAN_ROOT / "made-up.tf"),
                    "start_line": 1,
                    "end_line": 2,
                },
            }
        ]
    }
    result = TfsecAdapter().parse(raw, TERRAFORM_SCAN_ROOT, None)
    (finding,) = result.findings
    assert finding.resource_identity == identity.UNRESOLVED
    assert finding.identity_kind == "unresolved"
    assert finding.context_eligible is False


# --- tfsec is terraform-only: the off-matrix probe yields nothing, not a crash -----


def test_the_kubernetes_off_matrix_probe_yields_zero_findings_and_does_not_raise() -> None:
    """`tfsec-kubernetes.json` is the 19-byte `{"results": []}` capture S0 took
    running tfsec against the Kubernetes scan root, which `tools/scanners.lock.json`
    declares out of tfsec's platform matrix (`platforms: ["terraform"]`). Parsing
    it must not raise and must produce nothing to normalize - there is no
    finding here to carry a platform at all.
    """
    raw = _load_fixture("tfsec-kubernetes.json")
    assert raw == {"results": []}

    result = TfsecAdapter().parse(raw, KUBERNETES_SCAN_ROOT, None)
    assert result.findings == ()
    assert result.dropped == ()


def test_every_finding_from_the_terraform_fixture_is_platform_terraform() -> None:
    """tfsec declares only `["terraform"]` in the lockfile's platform matrix, so
    every finding this adapter produces is terraform - there is no per-run
    platform detection to get wrong the way checkov's and trivy's `_platform_of`
    have to, because tfsec is never run against a mixed-platform block.
    """
    result = _terraform_result()
    assert result.findings
    assert all(f.platform == "terraform" for f in result.findings)


# --- fingerprint: resolved only where the resource string actually carries one ----


def test_fingerprint_is_none_for_every_plain_resource() -> None:
    """Every finding but the one attribute-suffixed row (`AVD-AWS-0180`, the
    fixture's only `resource` value carrying a suffix - confirmed above) must
    carry `fingerprint is None` - the explicit unresolved state (spec §6:
    "tfsec - the attribute split off the `resource` field where present;
    otherwise unresolved"), never a placeholder string. Expressed as "all
    findings minus the one known exception" rather than a restated `118`, so
    a re-capture that changes the total moves what this test expects instead
    of leaving a stale count standing.
    """
    result = _terraform_result()
    assert result.findings
    unsuffixed = [f for f in result.findings if f.rule_id != "AVD-AWS-0180"]
    assert len(unsuffixed) == len(result.findings) - 1
    assert all(f.fingerprint is None for f in unsuffixed)


# --- taxonomy: canonical_rule_id joins a tfsec rule to its trivy twin --------------


def test_canonical_rule_id_strips_avd_so_a_tfsec_rule_shares_its_trivy_twins_id() -> None:
    """`AVD-AWS-0028` (tfsec) and `AWS-0028` (trivy) are a real corpus v0 twin
    pair on the identical resource `aws_instance.db_app` in `db-app.tf`
    (verified against both raw fixtures, not assumed) - one of the 45 twin
    pairs `canonical_rule_id` exists to join (S1 §2.2). Both the canonical id
    and the taxonomy class it resolves to must agree, or the twin pair would
    canonicalize without actually sharing a class.
    """
    tfsec_raw = _raw_results("tfsec-terraform.json")
    tfsec_row = next(
        r
        for r in tfsec_raw
        if r["rule_id"] == "AVD-AWS-0028" and r["resource"] == "aws_instance.db_app"
    )
    assert "db-app.tf" in tfsec_row["location"]["filename"]

    trivy_ids = set()
    for block in _load_fixture("trivy-terraform.json")["Results"]:
        for m in block.get("Misconfigurations") or []:
            trivy_ids.add(m["ID"])
    assert "AWS-0028" in trivy_ids

    result = _terraform_result()
    finding = next(
        f
        for f in result.findings
        if f.rule_id == "AVD-AWS-0028"
        and f.resource_identity == identity.terraform_identity("aws_instance", "db_app")
    )
    assert finding.canonical_rule_id == "AWS-0028"
    assert finding.canonical_rule_id == taxonomy.canonical_rule_id("AWS-0028")
    assert finding.issue_class == taxonomy.class_for("trivy", "AWS-0028")


def test_no_finding_is_unmapped_in_corpus_v0() -> None:
    """All 48 distinct `AVD-AWS-*` ids tfsec emits in corpus v0 are rows the
    committed taxonomy already carries (S1 §1's 255-of-255 coverage claim), so
    no finding here should take the `unmapped:` fallback.
    """
    result = _terraform_result()
    assert result.findings
    assert not any(f.is_unmapped for f in result.findings)


def test_an_unrecognized_rule_id_takes_the_unmapped_fallback() -> None:
    """Corpus v0 maps every rule id tfsec emits (previous test), so this id has
    to be invented rather than found, matching `test_trivy.py`'s and
    `test_checkov.py`'s own equivalent tests.
    """
    raw = {
        "results": [
            {
                "rule_id": "AVD-AWS-INVENTED-999999",
                "rule_description": "not a real tfsec rule",
                "resolution": "n/a",
                "severity": "LOW",
                "resource": "aws_made_up_thing.example",
                "location": {
                    "filename": str(TERRAFORM_SCAN_ROOT / "made-up.tf"),
                    "start_line": 1,
                    "end_line": 2,
                },
            }
        ]
    }
    result = TfsecAdapter().parse(raw, TERRAFORM_SCAN_ROOT, None)
    (finding,) = result.findings
    assert finding.is_unmapped
    assert finding.issue_class == "unmapped:tfsec:AVD-AWS-INVENTED-999999"


# --- severity: tfsec supplies one on every corpus v0 finding -----------------------


def test_severity_is_always_present_and_matches_the_rubric() -> None:
    """Measured: every one of the 119 `results` carries a `severity` token, and
    the four tokens observed are exactly `{CRITICAL, HIGH, MEDIUM, LOW}` - the
    same four-level vocabulary CLAUDE.md's "Severity in corpus v0, measured"
    reports for trivy. Checked per finding against `rubric.normalize_severity`
    directly, not only against the token vocabulary, so a mapping defect for
    any one token is caught.
    """
    raw = _raw_results("tfsec-terraform.json")
    assert raw
    assert all(r.get("severity") for r in raw)
    assert {r["severity"] for r in raw} == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    result = _terraform_result()
    assert result.findings
    for finding in result.findings:
        assert finding.native_severity is not None
        assert finding.severity_level != "unknown"
        assert finding.severity_level == rubric.normalize_severity("tfsec", finding.native_severity)


# --- title / remediation: read off tfsec's own rule-level fields -------------------


def test_title_and_remediation_come_from_tfsecs_own_fields() -> None:
    """`rule_description` is constant across every occurrence of one rule id in
    corpus v0 (measured: 0 of 48 distinct rule ids vary), the same rule-level
    constancy trivy's own `Title` has across `test_trivy.py`'s fixture - so it
    is the title, not the per-instance `description`, which varies for 3 of 48
    rule ids and would make `title` read as though it changed per resource
    rather than per rule. `resolution` is tfsec's own remediation field, read
    unchanged.
    """
    raw = _raw_results("tfsec-terraform.json")
    row = next(r for r in raw if r["rule_id"] == "AVD-AWS-0177")

    result = _terraform_result()
    finding = next(f for f in result.findings if f.rule_id == "AVD-AWS-0177")
    assert finding.title == row["rule_description"]
    assert finding.remediation == row["resolution"]


# --- path handling: gate 3 - the whole point of this task --------------------------


def test_every_tfsec_finding_rebases_to_an_absolute_windows_path() -> None:
    """Ground the gate-3 fixture assumption itself: `location.filename` really is
    absolute on every row (measured; design spec §1 consequence 1), so the
    rebasing this task adds is exercised by every finding, not a handful. The
    point is "every row, not just a sample" - `assert raw` plus the `all(...)`
    below already say that; the row count itself is not this test's claim, so
    it is deliberately not restated here as a hardcoded `119`.
    """
    raw = _raw_results("tfsec-terraform.json")
    assert raw
    assert all(r["location"]["filename"][1:3] == ":\\" for r in raw)


def test_tfsec_paths_are_a_subset_of_both_checkovs_and_trivys_paths_for_the_same_files() -> None:
    """Acceptance gate 3 (design spec §10): every one of the 119 tfsec findings
    must rebase to a scan-root-relative path string-equal to what checkov and
    trivy report for the same file - asserted as set equality over the files
    tfsec touches, not merely "the paths look relative" (a path that still
    carried a drive letter, a leading separator, or the wrong case would
    "look relative" while joining nothing).

    Each scanner's path set is built independently through its own adapter
    against its own fixture, so this is a real cross-scanner join check, not
    tfsec compared to a restatement of itself. If `TfsecAdapter` stopped
    rebasing (e.g. returned `location.filename` verbatim), `tfsec_paths` would
    hold absolute strings like `d:/research/corpus/vendor/terragoat/terraform/
    aws/db-app.tf` that appear in neither other set, the intersection would
    drop to the empty set, and the non-triviality assertion below (that the
    intersection is non-empty and matches `tfsec_paths` exactly) would fail -
    this is what makes the test actually sensitive to a rebasing regression
    rather than passing vacuously.
    """
    tfsec_result = _terraform_result()
    tfsec_paths = {f.file_path for f in tfsec_result.findings}

    checkov_result = CheckovAdapter().parse(
        _load_fixture("checkov-terraform.json"), TERRAFORM_SCAN_ROOT, None
    )
    checkov_paths = {f.file_path for f in checkov_result.findings if f.file_path}

    trivy_result = TrivyAdapter().parse(
        _load_fixture("trivy-terraform.json"), TERRAFORM_SCAN_ROOT, None
    )
    trivy_paths = {f.file_path for f in trivy_result.findings if f.file_path}

    # Non-triviality guard: an empty tfsec_paths would make the equality
    # assertions below pass vacuously (set() == set() & anything).
    assert tfsec_paths
    assert not any(f.file_path.startswith(("/", "\\")) for f in tfsec_result.findings)
    assert not any(":" in f.file_path for f in tfsec_result.findings)

    assert tfsec_paths & checkov_paths == tfsec_paths
    assert tfsec_paths & trivy_paths == tfsec_paths


def test_tfsec_paths_equal_the_rebase_to_scan_root_reference_computation() -> None:
    """Cross-checks the adapter's own rebasing against `rebase_to_scan_root`
    called directly on the raw fixture, independently of `TfsecAdapter` -
    the same "don't let the adapter grade its own homework" reasoning the
    retention tests apply, here applied to path handling specifically.
    """
    raw = _raw_results("tfsec-terraform.json")
    expected = {rebase_to_scan_root(r["location"]["filename"], _capture_root()) for r in raw}
    result = _terraform_result()
    actual = {f.file_path for f in result.findings}
    assert actual == expected


# --- replaying a recorded run: the capture root, not this checkout's ---------------


def test_capture_scan_root_recovers_the_frame_every_fixture_filename_lies_under() -> None:
    """The fixture's paths are absolute under the host that captured it, so the
    root it replays against has to come from the fixture. Asserted against the
    raw rows independently of the adapter: the recovered root ends exactly at
    the repo-relative scan root, and every row lies under it.
    """
    raw = _raw_results("tfsec-terraform.json")
    root = _capture_root().as_posix().lower()
    relative = TERRAFORM_SCAN_ROOT.relative_to(REPO_ROOT).as_posix().lower()

    assert raw
    assert root.endswith(f"/{relative}")
    assert all(
        r["location"]["filename"].replace("\\", "/").lower().startswith(f"{root}/") for r in raw
    )


def test_capture_scan_root_recovers_a_root_from_another_host() -> None:
    """Constructed, so the property does not depend on where the committed
    fixture happened to be captured or on where this checkout sits.
    """
    foreign = "E:\\elsewhere\\checkout\\corpus\\vendor\\terragoat\\terraform\\aws\\made-up.tf"
    raw = {"results": [{"location": {"filename": foreign}}]}

    root = capture_scan_root(raw, TERRAFORM_SCAN_ROOT, REPO_ROOT)

    assert root.as_posix() == "E:/elsewhere/checkout/corpus/vendor/terragoat/terraform/aws"
    assert rebase_to_scan_root(foreign, root) == "made-up.tf"


def test_capture_scan_root_returns_the_given_root_when_no_filename_contains_it() -> None:
    """The fallback is what keeps a foreign path loud: with the root unchanged,
    `rebase_to_scan_root` still raises on it. A sibling directory sharing the
    root's name as a prefix (`aws-legacy`) is not a match - the cut is on a
    path boundary.
    """
    sibling = "E:\\x\\corpus\\vendor\\terragoat\\terraform\\aws-legacy\\main.tf"
    raw = {"results": [{"location": {"filename": sibling}}]}

    assert capture_scan_root(raw, TERRAFORM_SCAN_ROOT, REPO_ROOT) == TERRAFORM_SCAN_ROOT
    assert capture_scan_root({}, TERRAFORM_SCAN_ROOT, REPO_ROOT) == TERRAFORM_SCAN_ROOT
    assert capture_scan_root(None, TERRAFORM_SCAN_ROOT, REPO_ROOT) == TERRAFORM_SCAN_ROOT


def test_capture_scan_root_returns_a_scan_root_outside_the_repository_unchanged(
    tmp_path: Path,
) -> None:
    """Recovery works by finding the scan root's repo-relative path inside a recorded
    filename, so it has nothing to look for when the scan root is not under the
    repository - a live scan of some other directory. That used to raise `ValueError`
    out of `relative_to`; it now means "nothing to recover".
    """
    outside = tmp_path / "some-other-project"
    raw = {"results": [{"location": {"filename": str(outside / "main.tf")}}]}

    assert capture_scan_root(raw, outside, REPO_ROOT) == outside


def test_module_level_conformance_guard_exists() -> None:
    """`tfsec.py` declares `_conforms: ScannerAdapter = TfsecAdapter()` as a
    mypy-checked structural-conformance assertion, matching `checkov.py`'s and
    `trivy.py`'s own guards - checked here only as "the attribute exists and
    is a TfsecAdapter", since the type-checking itself is mypy's job, not a
    runtime assertion this test could perform.
    """
    from iacrisk.scanners import tfsec as tfsec_module

    assert isinstance(tfsec_module._conforms, TfsecAdapter)
