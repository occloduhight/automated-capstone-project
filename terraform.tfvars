# VPC and Subnets
cidr     = "0.0.0.0/0"
pub_sn1  = "10.0.1.0/24"
pub_sn2  = "10.0.2.0/24"
prv_sn1  = "10.0.3.0/24"
prv_sn2  = "10.0.4.0/24"
all_cidr = "10.0.0.0/16"  # list format for private route table

# Ports
sshport   = 22
mysqlport = 3306
httpport  = 80
httpsport = 443
appport   = 8000

# Database
db_identifier = "wordpress-db"
dbname        = "wordpress"
dbusername    = "admin"
dbpassword    = "admin123"

# EC2
redhat_ami    = "ami-04cdc5e4b2145a4a5"
instance_type = "t3.micro"

# Domain
domain = "odochidevops.space"
