locals {
  wordpress_script = <<-EOF
#!/bin/bash
# Update system packages
yum update -y
yum upgrade -y

# Install required tools
yum install -y unzip wget httpd php php-mysqlnd mod_ssl

# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install

# Create test file
cd /var/www/html
echo "This is a test file" > indextest.html

# Download and extract WordPress
wget https://wordpress.org/wordpress-6.3.1.tar.gz
tar -xzf wordpress-6.3.1.tar.gz
cp -r wordpress/* /var/www/html/
rm -rf wordpress wordpress-6.3.1.tar.gz

# Set permissions and ownership
chmod -R 755 wp-content
chown -R apache:apache wp-content
mv wp-config-sample.php wp-config.php

# Configure the WordPress database connection
sed -i "s@define( 'DB_NAME', 'wordpress_db' )@define( 'DB_NAME', '${var.db_name}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_USER', 'admin' )@define( 'DB_USER', '${var.db_username}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_PASSWORD', 'admin123' )@define( 'DB_PASSWORD', '${var.db_password}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST', 'autocap-wordpress-db.c184icugqfwq.eu-west-3.rds.amazonaws.com')@g" /var/www/html/wp-config.php

# Enable .htaccess overrides
sed -i -e '154aAllowOverride All' -e '154d' /etc/httpd/conf/httpd.conf

# Create .htaccess for uploads (CloudFront optional)
cat <<EOT > /var/www/html/.htaccess
Options +FollowSymlinks
RewriteEngine on
RewriteRule ^wp-content/uploads/(.*)$ https://${data.aws_cloudfront_distribution.cloudfront.domain_name}/\$1 [R=301,NC]
# BEGIN WordPress
# END WordPress
EOT

# Sync WordPress files to S3 buckets
aws s3 cp --recursive /var/www/html/ s3://code-bucket
aws s3 sync /var/www/html/ s3://code-bucket

# Setup cron jobs for S3 sync
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync s3://code-bucket /var/www/html/" >> /etc/crontab
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync /var/www/html/wp-content/uploads/ s3://media-bucket" >> /etc/crontab

# Start Apache and set host configuration
chkconfig httpd on
service httpd start
setenforce 0
hostnamectl set-hostname webserver
EOF
}
