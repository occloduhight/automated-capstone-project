#!/bin/bash
# set -e

# Update system
sudo yum update -y
sudo yum upgrade -y

# Install AWS CLI
# curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
# sudo yum install unzip -y
# unzip awscliv2.zip
# sudo ./aws/install
# sudo ./aws/install --update
sudo yum install -y awscli

# Install Apache, PHP, and MySQL packages
sudo yum install httpd php php-mysqlnd wget -y

# Prepare web root
cd /var/www/html
echo "This is a test file" > indextest.html
echo "This is a test file" | sudo tee /var/www/html/indextest.html
sudo chown -R ec2-user:ec2-user /var/www/html


# Download and install WordPress
wget https://wordpress.org/wordpress-6.3.1.tar.gz
tar -xzf wordpress-6.3.1.tar.gz
cp -r wordpress/* /var/www/html/
rm -rf wordpress wordpress-6.3.1.tar.gz

# Set permissions
# sudo chmod -R 755 wp-content
# sudo chown -R apache:apache wp-content
sudo mkdir -p /var/www/html/wp-content/uploads
sudo chown -R apache:apache /var/www/html/wp-content/uploads
sudo chmod -R 755 /var/www/html/wp-content/uploads
# Configure wp-config.php
cd /var/www/html
mv wp-config-sample.php wp-config.php
sudo sed -i "s@define( 'DB_NAME', 'autocap_wordpress_db' )@define( 'DB_NAME', '${db_name}' )@g" wp-config.php
sudo sed -i "s@define( 'DB_USER', 'admin' )@define( 'DB_USER', '${db_username}' )@g" wp-config.php
sudo sed -i "s@define( 'DB_PASSWORD', 'admin123' )@define( 'DB_PASSWORD', '${db_password}' )@g" wp-config.php
sudo sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST', '${db_host}' )@g" wp-config.php

# Update Apache config
sudo sed -i "s/AllowOverride None/AllowOverride All/" /etc/httpd/conf/httpd.conf

# Create .htaccess
# cat <<EOT> /var/www/html/.htaccess
# Options +FollowSymlinks
# RewriteEngine on
# RewriteRule ^wp-content/uploads/(.*)$ http://${cloudfront_domain}/\$1 [R=301,NC,L]

# BEGIN WordPress
# END WordPress
# EOT
sudo tee /var/www/html/.htaccess > /dev/null <<EOT
Options +FollowSymlinks
RewriteEngine on
RewriteRule ^wp-content/uploads/(.*)$ http://${cloudfront_domain}/\$1 [R=301,NC,L]

# BEGIN WordPress
# END WordPress
EOT

# Sync website to S3
# aws s3 cp --recursive /var/www/html/ s3://autocap_code_bucket
# aws s3 sync /var/www/html/ s3://autocap_code_bucket

aws s3 cp --recursive /var/www/html/ s3://autocap-code-bucket
aws s3 sync /var/www/html/ s3://autocap-code-bucket
aws s3 sync /var/www/html/wp-content/uploads/ s3://autocap-media

# Setup cron jobs for sync
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync s3://autocap_code_bucket /var/www/html/" > /etc/crontab
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync /var/www/html/wp-content/uploads/ s3://autocap_media" >> /etc/crontab

# Start Apache
# sudo chkconfig httpd on
# sudo service httpd start
s:udo systemctl enable httpd
sudo systemctl start httpd
sudo systemctl status httpd

# Disable SELinux enforcement
sudo setenforce 0

# Set hostname
sudo hostnamectl set-hostname webserver
