# VPC and Subnets
variable "cidr" {}
variable "pub_sn1" {}
variable "pub_sn2" {}
variable "prv_sn1" {}
variable "prv_sn2" {}
variable "all_cidr" {
  type = list(string)
}

# Ports
variable "sshport" {}
variable "mysqlport" {}
variable "httpport" {}
variable "httpsport" {}
variable "appport" {}

# Database
variable "db_identifier" {}
variable "dbname" {}
variable "dbusername" {}
variable "dbpassword" {}

# EC2
variable "redhat_ami" {}
variable "instance_type" {}

# Domain
variable "domain" {}
