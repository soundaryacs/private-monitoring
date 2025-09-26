terraform {
backend "s3" {
bucket = "your-tfstate-bucket"
key = "private-monitoring/terraform.tfstate"
region = "ap-south-1"
dynamodb_table = "your-tf-locks"
encrypt = true
}
}