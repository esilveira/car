terraform {
  required_version = "~> 1.4.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket = "career-center-s3-backend-tf-state"
    key    = "backend-api.tfstate"
    region = "us-east-1"
  }
}
