provider "aws" {
  region  = "ap-southeast-1"
  profile = "huy"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}