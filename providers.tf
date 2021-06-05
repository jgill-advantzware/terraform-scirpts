terraform {
  backend "s3" {
    bucket   = "terraform-us-east-1"
    key      = "terraform/us-east-1/vpc/xxxxxxxxxx.tfstate"
    region   = "us-east-1"
    role_arn = "arn:aws:iam::xxxxxxxxxxx:role/Jenkins"
  }
}
