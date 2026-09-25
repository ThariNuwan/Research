resource "aws_iam_policy" "narrow_scope" {
  name = "s2-narrow-scope"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sts:GetSessionToken"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_policy" "moderate_scope" {
  name = "s2-moderate-scope"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = "arn:aws:s3:::s2-fixture-bucket/*"
    }]
  })
}

resource "aws_iam_policy" "broad_scope" {
  name = "s2-broad-scope"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["*"]
      Resource = "*"
    }]
  })
}
