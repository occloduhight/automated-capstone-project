variable "cidr" {}
variable "pub_sn1" {}
variable "pub_sn2" {}
variable "prv_sn1" {}
variable "prv_sn2" {}
variable "redhat_ami" {}
variable "instance_type" {}
variable "db_name" {}
variable "dbcred" {
  type = map(string)
}
variable "alert_email" {}
