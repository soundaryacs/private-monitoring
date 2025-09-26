variable "project" {
    description = "Name prefix for all resources"
    type = string
    default = "priv-mon"
}


variable "region" {
    description = "AWS region"
    type = string
    default = "ap-south-1"
}


variable "vpc_cidr" {
    description = "VPC CIDR"
    type = string
    default = "10.20.0.0/16"
}


variable "instance_type" {
    description = "EC2 instance type"
    type = string
    default = "t3.small"
}


variable "prometheus_version" {
    description = "Prometheus version"
    type = string
    default = "2.55.1"
}


# For ALB OIDC (optional)
    variable "acm_certificate_arn" {
    description = "ACM cert ARN for internal ALB (optional)"
    type = string
    default = null
}