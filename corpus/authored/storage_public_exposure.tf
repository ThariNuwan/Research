# Hand-crafted for S2's second exposure contrastive pair (design spec section 4).
#
# Two buckets identical in every respect except that one is publicly exposed, so
# their issue-class sets differ by exactly {storage-public-accessibility} - a class
# the rubric's Public Exposure pattern list explicitly supports ("public storage
# (public-access-block disabled or public ACL/policy)") and which the factor's own
# level 5 describes directly.
#
# Corpus v0 cannot supply this pair: zero same-type resource pairs in it differ only
# in a class the exposure pattern list supports (design spec section 1.1). The mined
# candidate that was committed first - aws_security_group_rule.egress against
# .ingress - rested on networking-egress-exposure, which the taxonomy itself calls
# "a distinct property from inbound exposure" and which appears in no level of the
# Public Exposure factor.
#
# Not security groups: the scanners flag network exposure binary, so a narrow public
# CIDR draws no finding at all and could not be the low side of any pair.

resource "aws_s3_bucket" "private_baseline" {
  bucket = "s2-fixture-private-baseline"
}

resource "aws_s3_bucket_public_access_block" "private_baseline" {
  bucket                  = aws_s3_bucket.private_baseline.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "public_exposed" {
  bucket = "s2-fixture-public-exposed"
}

resource "aws_s3_bucket_public_access_block" "public_exposed" {
  bucket                  = aws_s3_bucket.public_exposed.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_exposed" {
  bucket = aws_s3_bucket.public_exposed.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadGetObject"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::s2-fixture-public-exposed/*"
    }]
  })
}
