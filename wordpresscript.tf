// wordpress_script.tf
locals {
  wordpress_script = <<-EOF
#!/bin/bash

# Update and upgrade system packages
sudo yum update -y
sudo yum upgrade -y

# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
sudo yum install unzip -y
unzip awscliv2.zip
sudo ./aws/install

# Install Apache, PHP, and MySQL packages
sudo yum install httpd php php-mysqlnd wget -y

# Set up web directory
cd /var/www/html
touch indextest.html
echo "This is a test file" > indextest.html

# Download and extract WordPress
wget https://wordpress.org/wordpress-6.3.1.tar.gz
tar -xzf wordpress-6.3.1.tar.gz
cp -r wordpress/* /var/www/html/
rm -rf wordpress wordpress-6.3.1.tar.gz

# Set permissions
chmod -R 755 wp-content
chown -R apache:apache wp-content

# Configure WordPress database connection
cd /var/www/html
mv wp-config-sample.php wp-config.php
sed -i "s@define( 'DB_NAME', 'database_name_here' )@define( 'DB_NAME', '${var.dbname}' )@g" wp-config.php
sed -i "s@define( 'DB_USER', 'username_here' )@define( 'DB_USER', '${local.db_cred.username}' )@g" wp-config.php
sed -i "s@define( 'DB_PASSWORD', 'password_here' )@define( 'DB_PASSWORD', '${local.db_cred.password}' )@g" wp-config.php
sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST', '${aws_db_instance.wordpress_db.endpoint}' )@g" wp-config.php

# Configure Apache
sudo sed -i -e '154aAllowOverride All' -e '154d' /etc/httpd/conf/httpd.conf

# Create .htaccess for CloudFront rewrite
cat <<HTACCESS > /var/www/html/.htaccess
Options +FollowSymlinks
RewriteEngine on
RewriteRule ^wp-content/uploads/(.*)$ http://${aws_cloudfront_distribution.s3_distribution.domain_name}/\$1 [R=301,NC]
# BEGIN WordPress
# END WordPress
HTACCESS

# Sync with S3 buckets
aws s3 cp --recursive /var/www/html/ s3://autocap-code-bucket
aws s3 sync /var/www/html/ s3://autocap-code-bucket

# Add cron jobs for continuous syncing
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync s3://autocap-code-bucket /var/www/html/" >> /etc/crontab
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync /var/www/html/wp-content/uploads/ s3://autocap-media" >> /etc/crontab

# Start and enable Apache
sudo chkconfig httpd on
sudo service httpd start

# Disable SELinux enforcement
sudo setenforce 0

# Set hostname
sudo hostnamectl set-hostname webserver

EOF
}
