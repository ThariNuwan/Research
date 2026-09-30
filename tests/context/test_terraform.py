from pathlib import Path

from iacrisk.context.terraform import (
    TerraformResource,
    attribute,
    build_index,
    is_literal,
    unquote,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TERRAGOAT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"


def test_unquote_strips_the_quotes_python_hcl2_leaves_on() -> None:
    """Measured on python-hcl2 8.1.4 against this corpus: block keys and string
    values retain their surrounding quotes, so `'"aws_security_group"'` is what a
    caller actually receives. Every read strips them or matches nothing, silently.
    """
    assert unquote('"aws_security_group"') == "aws_security_group"
    assert unquote('"0.0.0.0/0"') == "0.0.0.0/0"
    assert unquote("already-bare") == "already-bare"
    assert unquote('"') == '"'  # a lone quote is not a quoted string


def test_is_literal_rejects_interpolation_anywhere_in_a_nested_value() -> None:
    """Literals-only (PLAN Q9). The nested-list case is the one that matters: the
    corpus case sgr-ingress-vpc-interpolated carries its interpolation inside a
    one-element list, so a top-level-only check would pass it as literal and score
    a resolved exposure from a value nobody resolved.
    """
    assert is_literal('"0.0.0.0/0"') is True
    assert is_literal(['"0.0.0.0/0"']) is True
    assert is_literal('"${aws_vpc.web_vpc.cidr_block}"') is False
    assert is_literal(['"${aws_vpc.web_vpc.cidr_block}"']) is False
    assert is_literal({"a": ['"${var.x}"']}) is False
    assert is_literal(True) is True
    assert is_literal(None) is True


def test_the_index_is_keyed_on_canonical_identity_over_the_real_corpus() -> None:
    files = sorted(TERRAGOAT.glob("*.tf"))
    index = build_index(files, TERRAGOAT)
    assert "aws_security_group.default" in index
    assert "aws_security_group_rule.ingress" in index
    assert "aws_security_group_rule.egress" in index
    sg = index["aws_security_group.default"]
    assert isinstance(sg, TerraformResource)
    assert sg.type == "aws_security_group"
    assert sg.name == "default"
    assert sg.file_path.endswith("db-app.tf")


def test_the_two_corpus_cidr_cases_are_distinguished_exactly_as_the_ground_truth_says() -> None:
    """corpus-v1.json's networking scenario rests on precisely this distinction:
    sgr-ingress-vpc-interpolated must be unresolved and sgr-egress-unrestricted must
    be a resolved 0.0.0.0/0. If this test fails, that scenario's expected ordering is
    unreproducible.
    """
    index = build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)

    ingress = attribute(index["aws_security_group_rule.ingress"], "cidr_blocks")
    assert is_literal(ingress) is False

    egress = attribute(index["aws_security_group_rule.egress"], "cidr_blocks")
    assert is_literal(egress) is True
    assert isinstance(egress, list)
    assert [unquote(c) for c in egress] == ["0.0.0.0/0"]


def test_attribute_returns_none_for_an_absent_attribute() -> None:
    index = build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)
    assert attribute(index["aws_security_group.default"], "no_such_attribute") is None


def test_an_unparseable_file_is_skipped_and_named_not_raised(tmp_path: Path) -> None:
    """S3a's retention report already counts unparseable files as an unresolved cause.
    A parse failure here must not abort the whole index, or one malformed file in a
    corpus removes every resource in it from context extraction.
    """
    good = tmp_path / "good.tf"
    good.write_text('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n', encoding="utf-8")
    bad = tmp_path / "bad.tf"
    bad.write_text(
        'resource "aws_s3_bucket" "c" {\n  policy = <<EOF\n{ unterminated\n', encoding="utf-8"
    )

    index = build_index([good, bad], tmp_path)
    assert "aws_s3_bucket.b" in index
    assert len(index) == 1
