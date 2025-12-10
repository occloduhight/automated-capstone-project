locals {
  wordpress_script = <<-EOF
#!/bin/bash
# Update system packages
sudo yum update -y
sudo yum upgrade -y

# Install required tools
sudo yum install -y unzip wget httpd php php-mysqlnd mod_ssl
sudo yum install -y httpd php php-mysqlnd mariadb
# Install AWS CLI
sudo curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
sudo unzip /tmp/awscliv2.zip -d /tmp
sudo /tmp/aws/install

# Create test file
cd /var/www/html
echo "This is a test file" > indextest.html

# Download and extract WordPress
wget https://wordpress.org/wordpress-6.3.1.tar.gz -O /tmp/wordpress.tar.gz
tar -xzf /tmp/wordpress.tar.gz -C /tmp
cp -r /tmp/wordpress/* /var/www/html/
rm -rf /tmp/wordpress /tmp/wordpress.tar.gz

# Set permissions and ownership
chmod -R 755 /var/www/html
chown -R apache:apache /var/www/html
mv /var/www/html/wp-config-sample.php /var/www/html/wp-config.php

# Configure the WordPress database connection
sed -i "s@define( 'DB_NAME', 'wordpress_db' )@define( 'DB_NAME', '${var.db_name}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_USER', 'admin' )@define( 'DB_USER', '${var.dbcred["username"]}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_PASSWORD', 'admin123' )@define( 'DB_PASSWORD', '${var.dbcred["password"]}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST', '${element(split(":", aws_db_instance.autocap_wordpress_db.endpoint), 0)}')@g" /var/www/html/wp-config.php

sudo sed -i  -e '154aAllowOverride All' -e '154d' /etc/httpd/conf/httpd.conf
cat <<EOT > /var/www/html/.htaccess
Options +FollowSymlinks
RewriteEngine on
RewriteRule ^wp-content/uploads/(.*)$ https://${data.aws_cloudfront_distribution.cloudfront.domain_name}/$1 [r=301,nc]
# BEGIN WordPress
# END WordPress
EOT
aws s3 cp --recursive /var/www/html/ s3://code-bucket
aws s3 sync /var/www/html/ s3://code-bucket
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync s3://code-bucket /var/www/html/" > /etc/crontab
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync /var/www/html/wp-content/uploads/ s3://media-bucket" >> /etc/crontab
sudo systemctl enable httpd
sudo systemctl start httpd
sudo setenforce 0
sudo sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
sudo hostnamectl set-hostname webserver
EOF
}