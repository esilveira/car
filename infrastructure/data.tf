data "terraform_remote_state" "career-center-environment" {
  backend = "s3"

  config = {
    bucket = "career-center-s3-backend-tf-state"
    key    = "career-center.tfstate"
    region = "us-east-1"
  }
}

data "aws_caller_identity" "current" {}
