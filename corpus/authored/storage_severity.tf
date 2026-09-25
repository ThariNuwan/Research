resource "aws_ebs_volume" "unencrypted_scratch" {
  availability_zone = "us-west-2a"
  size              = 1
}

resource "aws_s3_bucket" "no_cmk" {
  bucket = "s2-fixture-no-cmk"
}
