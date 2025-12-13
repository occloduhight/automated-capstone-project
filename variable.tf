# VPC and Subnets
# variable "cidr" {}
# variable "pub_sn1" {}
# variable "pub_sn2" {}
# variable "prv_sn1" {}
# variable "prv_sn2" {}
# variable "all_cidr" {
#   type = list(string)
# }
# VPC and Subnets
variable "cidr" {
  type = string
}

variable "pub_sn1" {
  type = string
}

variable "pub_sn2" {
  type = string
}

variable "prv_sn1" {
  type = string
}

variable "prv_sn2" {
  type = string
}

variable "all_cidr" {
  type = string
}

# DB credentials as an object
variable "db_cred" {
  description = "Database credentials for RDS instance"
  type = object({
    username = string
    password = string
  })
  sensitive = true
}

# Ports
variable "sshport" {}
variable "mysqlport" {}
variable "httpport" {}
variable "httpsport" {}
variable "appport" {}

# Database
variable "db-identifier" {}
variable "dbname" {}
variable "dbusername" {}
variable "dbpassword" {}

# EC2
variable "redhat_ami" {}
variable "instance_type" {}

# Domain
variable "domain" {}
