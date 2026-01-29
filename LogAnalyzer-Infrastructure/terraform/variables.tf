variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "ap-southeast-1"
}

variable "project_name" {
  description = "Project name for resource tagging"
  type        = string
  default     = "loganalyzer"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "app_instance_type" {
  description = "EC2 instance type for application server"
  type        = string
  default     = "t3.medium"  # 2 vCPU, 4GB RAM
}

variable "jenkins_instance_type" {
  description = "EC2 instance type for Jenkins server"
  type        = string
  default     = "t3.small"   # 2 vCPU, 2GB RAM
}

variable "key_name" {
  description = "SSH key pair name"
  type        = string
  default     = "loganalyzer-key"
}

variable "allowed_ssh_ips" {
  description = "List of IPs allowed to SSH (CHANGE THIS to your IP!)"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Allow all - SECURITY RISK, change to your IP!
}
