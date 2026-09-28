resource "aws_iam_policy" "s3_bucket_scope" {
  name = "s2-s3-bucket-scope"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = "arn:aws:s3:::s2-fixture-bucket/*"
    }]
  })
}

resource "aws_iam_policy" "s3_account_scope" {
  name = "s2-s3-account-scope"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_policy" "unrestricted_scope" {
  name = "s2-unrestricted-scope"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["*"]
      Resource = "*"
    }]
  })
}
