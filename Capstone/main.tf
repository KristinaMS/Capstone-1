#Create a VPC
resource "aws_vpc" "Group4_VPC" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "Group4_VPC"
  }
}

#Create a Public Subnet01
resource "aws_subnet" "G4Pub_SN01" {
  vpc_id            = aws_vpc.Group4_VPC.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "G4Pub_SN01"
  }
}

#Create a Private Subnet01
resource "aws_subnet" "G4Prvt_SN01" {
  vpc_id            = aws_vpc.Group4_VPC.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "G4Prvt_SN01"
  }
}

#Create a Public Subnet02
resource "aws_subnet" "G4Pub_SN02" {
  vpc_id            = aws_vpc.Group4_VPC.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "G4Pub_SN02"
  }
}

#Create a Private Subnet02
resource "aws_subnet" "G4Prvt_SN02" {
  vpc_id            = aws_vpc.Group4_VPC.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "G4Prvt_SN02"
  }
}

#Create IGW
resource "aws_internet_gateway" "Group4_IGW" {
  vpc_id = aws_vpc.Group4_VPC.id

  tags = {
    Name = "Group4_IGW"
  }
}

#Create Elastic IP (for NAT Gateway)
resource "aws_eip" "G4_EIP" {
  vpc = true
}

#Create NAT Gateway
resource "aws_nat_gateway" "G4_NAT" {
  allocation_id = aws_eip.G4_EIP.id
  subnet_id     = aws_subnet.G4Pub_SN01.id

  tags = {
    Name = "G4_NAT"
  }
}

#Create Public Route Table 
resource "aws_route_table" "G4_pub_RT" {
  vpc_id = aws_vpc.Group4_VPC.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.Group4_IGW.id
  }

  tags = {
    Name = "G4_pub_RT"
  }
}

#Create Private Route Table 
resource "aws_route_table" "G4_prvt_RT" {
  vpc_id = aws_vpc.Group4_VPC.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.G4_NAT.id
  }

  tags = {
    Name = "G4_prvt_RT"
  }
}

#Create Public01 RT Association 
resource "aws_route_table_association" "RT_association_pub01" {
  subnet_id      = aws_subnet.G4Pub_SN01.id
  route_table_id = aws_route_table.G4_pub_RT.id
}

#Create Public02 RT Association 
resource "aws_route_table_association" "RT_association_pub02" {
  subnet_id      = aws_subnet.G4Pub_SN02.id
  route_table_id = aws_route_table.G4_pub_RT.id
}

#Create Private01 RT Association 
resource "aws_route_table_association" "RT_association_prv01" {
  subnet_id      = aws_subnet.G4Prvt_SN01.id
  route_table_id = aws_route_table.G4_prvt_RT.id
}

#Create Private02 RT Association 
resource "aws_route_table_association" "RT_association_prv02" {
  subnet_id      = aws_subnet.G4Prvt_SN02.id
  route_table_id = aws_route_table.G4_prvt_RT.id
}

#Create FrontEnd Security Group
resource "aws_security_group" "front_end_security_group" {
  name        = "front_end_security_group"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.Group4_VPC.id

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "front_end_security_group"
  }
}

#Create BackEnd Security Group
resource "aws_security_group" "back_end_security_group" {
  name        = "back_end_security_group"
  description = "Allow SSH and MySQL inbound traffic"
  vpc_id      = aws_vpc.Group4_VPC.id

  ingress {
    description     = "SSH from VPC"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.front_end_security_group.id]
  }

  ingress {
    description     = "MYSQL from VPC"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.front_end_security_group.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "back_end_security_group"
  }
}

#Create Database Subnet Group
resource "aws_db_subnet_group" "group4_database_subnet_group" {
  name       = "group4_db_sng"
  subnet_ids = ["${aws_subnet.G4Prvt_SN01.id}", "${aws_subnet.G4Prvt_SN02.id}"]
}

#Create MySQL Database
resource "aws_db_instance" "Group4_DB" {
  allocated_storage      = 10
  engine                 = "mysql"
  engine_version         = "8.0.27"
  instance_class         = "db.t2.micro"
  name                   = "Group4_DB_Host"
  username               = "admin"
  password               = "Admin123"
  vpc_security_group_ids = [aws_security_group.back_end_security_group.id]
  parameter_group_name   = "default.mysql8.0"
  port                   = 3306
  skip_final_snapshot    = true
  multi_az               = false
  db_subnet_group_name   = aws_db_subnet_group.group4_database_subnet_group.name
}

#Create media s3 bucket
resource "aws_s3_bucket" "grp4-s3-mediabuck" {
  bucket        = "grp4-s3-mediabuck"
  acl           = "public-read"
  force_destroy = true

  tags = {
    Name = "grp4-s3-mediabuck"
  }
}

# Update media s3 bucket public read/get object policy
resource "aws_s3_bucket_policy" "grp4-s3-mediabuck" {
  bucket = aws_s3_bucket.grp4-s3-mediabuck.id


  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "PublicReadGetObject",
        "Effect" : "Allow",
        "Principal" = {

          AWS = "*"

        }
        "Action" : [
          "s3:*Object"
        ],
        "Resource" : [
          "arn:aws:s3:::grp4-s3-mediabuck/*"
        ]
      }
    ]
  })
}

#Create media S3 bucket public access block
resource "aws_s3_bucket_public_access_block" "grp4-s3-mediabuck_public_access_block" {
  bucket = aws_s3_bucket.grp4-s3-mediabuck.id

  block_public_acls   = false
  block_public_policy = false
}

data "aws_cloudfront_distribution" "s3_cloudfront_distribution" {
  id = aws_cloudfront_distribution.s3_cloudfront_distribution.id
}

#Create Content Delivery Network (Cloudfront)
locals {
  s3_origin_id = "aws_s3_bucket.grp4-s3-mediabuck.id"
}

# resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
#   comment = "grp4-s3-mediabuck"
# }

resource "aws_cloudfront_distribution" "s3_cloudfront_distribution" {
  origin {
    domain_name = aws_s3_bucket.grp4-s3-mediabuck.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    # s3_origin_config {
    #   origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
    # }
  }

  enabled             = true
  default_root_object = "epa.jpeg"

  #aliases = ["bgmtayo.online"]

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  price_class = "PriceClass_All"
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }


  tags = {
    Name = "s3_cloudfront_distribution"
  }

  # depends_on = [aws_s3_bucket.grp4-s3-mediabuck]
}

#Create code S3 bucket
resource "aws_s3_bucket" "grp4-s3-codebuck" {
  bucket = "grp4-s3-codebuck"
  acl    = "private"

  tags = {
    Name = "grp4-s3-codebuck"
  }
}

#Create code S3 bucket public access block
resource "aws_s3_bucket_public_access_block" "grp4-s3-codebuck_public_access_block" {
  bucket = aws_s3_bucket.grp4-s3-codebuck.id

  block_public_acls   = true
  block_public_policy = true
}

#Create Key Pair
resource "aws_key_pair" "Grp4KeyPair" {
  key_name   = "Grp4KeyPair"
  public_key = file(var.path_to_public_key)
}

# Create EC2-S3 Full Access IAM Role
resource "aws_iam_role" "ec2_S3_Full_Access_iam_role" {
  name               = "ec2_S3_Full_Access_iam_role"
  description        = "S3 Full Permission"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": "S3FullAccess"
    }
  ]
}
EOF
}

# Attach EC2-S3 Full Access IAM Role to Existing AWS S3 Full Access Policy
resource "aws_iam_policy_attachment" "ec2_s3_media_bucket_access_policy_role" {
  name       = "ec2_s3_media_bucket_access_policy_role_attachment"
  roles      = [aws_iam_role.ec2_S3_Full_Access_iam_role.name]
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

#Create EC2-S3 Full Access IAM Instance Profile
resource "aws_iam_instance_profile" "ec2_S3_Full_Access_iam_instance_profile" {
  name = "ec2_S3_Full_Access_iam_instance_profile"
  role = aws_iam_role.ec2_S3_Full_Access_iam_role.name
}

# Create EC2 Instance
resource "aws_instance" "grp4_web_app_server" {
  ami                         = "ami-0b0af3577fe5e3532"
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.G4Pub_SN01.id
  vpc_security_group_ids      = ["${aws_security_group.front_end_security_group.id}"]
  associate_public_ip_address = true
  availability_zone           = "us-east-1a"
  key_name                    = aws_key_pair.Grp4KeyPair.key_name
  iam_instance_profile        = aws_iam_instance_profile.ec2_S3_Full_Access_iam_instance_profile.id

  user_data = <<-EOF
#!/bin/bash
yum install httpd php php-mysqlnd -y
cd /var/www/html
echo "This is a test file" > indextest.html
yum install wget -y
wget https://wordpress.org/wordpress-5.1.1.tar.gz
tar -xzf wordpress-5.1.1.tar.gz
cp -r wordpress/* /var/www/html/
rm -rf wordpress
rm -rf wordpress-5.1.1.tar.gz
chmod -R 755 wp-content
chown -R apache:apache wp-content
wget https://s3.amazonaws.com/bucketforwordpresslab-donotdelete/htaccess.txt
mv htaccess.txt .htaccess
cd /var/www/html && mv wp-config-sample.php wp-config.php
sed -i "s@define( 'DB_NAME', 'database_name_here' )@define( 'DB_NAME', 'Group4_DB_Host' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_USER', 'username_here' )@define( 'DB_USER', 'admin' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_PASSWORD', 'password_here' )@define( 'DB_PASSWORD', 'Admin123' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST', '${aws_db_instance.Group4_DB.endpoint}' )@g" /var/www/html/wp-config.php
cd ~
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
yum install unzip -y
unzip awscliv2.zip
./aws/install
cat <<EOT> /var/www/html/.htaccess
Options +FollowSymlinks
RewriteEngine on
rewriterule ^wp-content/uploads/(.*)$ http://${data.aws_cloudfront_distribution.s3_cloudfront_distribution.domain_name}/\$1 [r=301,nc]
# BEGIN WordPress
# END WordPress
EOT
cd /var/www/html
aws s3 cp --recursive /var/www/html/ s3://grp4-s3-codebuck
aws s3 sync /var/www/html/ s3://grp4-s3-codebuck
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync --delete s3://grp4-s3-codebuck /var/www/html/" >> /etc/crontab
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync --delete /var/www/html/wp-content/uploads/ s3://grp4-s3-mediabuck" >> /etc/crontab
cd /etc
service httpd start
cat <<EOT> /etc/httpd/conf/httpd.conf
ServerRoot "/etc/httpd"
Listen 80
Include conf.modules.d/*.conf
User apache
Group apache
ServerAdmin root@localhost
<Directory />
    AllowOverride none
    Require all denied
</Directory>
DocumentRoot "/var/www/html"
<Directory "/var/www">
    AllowOverride None
    Require all granted
</Directory>
<Directory "/var/www/html">
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
<IfModule dir_module>
    DirectoryIndex index.html
</IfModule>
<Files ".ht*">
    Require all denied
</Files>
ErrorLog "logs/error_log"
LogLevel warn
<IfModule alias_module>
    ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"
</IfModule>
<Directory "/var/www/cgi-bin">
    AllowOverride None
    Options None
    Require all granted
</Directory>
<IfModule mime_module>
    TypesConfig /etc/mime.types
    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz
    AddType text/html .shtml
    AddOutputFilter INCLUDES .shtml
</IfModule>
AddDefaultCharset UTF-8
<IfModule mime_magic_module>
    MIMEMagicFile conf/magic
</IfModule>
EnableSendfile on
IncludeOptional conf.d/*.conf
EOT
service httpd restart
chmod -R 777 html/
chkconfig httpd on
sudo sed -i 's/enforcing/disabled/g' /etc/selinux/config /etc/selinux/config
sudo reboot
EOF

  tags = {
    Name = "grp4_web_app_server"
  }
}

#Create AMI
# resource "aws_ami_from_instance" "AMI_web_app_server" {
#   name                    = "AMI_web_app_server"
#   source_instance_id      = aws_instance.grp4_web_app_server.id
#   snapshot_without_reboot = true
#   depends_on              = [aws_instance.grp4_web_app_server]
#   timeouts {
#     create = "20m"
#   }
# }

#Create Launch Configuration
resource "aws_launch_configuration" "grp4_launch_configuration" {
  name_prefix                 = "grp4_launch_configuration"
  image_id                    = "ami-0b0af3577fe5e3532"
  instance_type               = "t2.micro"
  key_name                    = aws_key_pair.Grp4KeyPair.key_name
  security_groups             = ["${aws_security_group.front_end_security_group.id}"]
  associate_public_ip_address = true
  user_data                   = <<-EOF
#!/bin/bash
yum install httpd php php-mysqlnd -y
cd /var/www/html
echo "This is a test file" > indextest.html
yum install wget -y
wget https://wordpress.org/wordpress-5.1.1.tar.gz
tar -xzf wordpress-5.1.1.tar.gz
cp -r wordpress/* /var/www/html/
rm -rf wordpress
rm -rf wordpress-5.1.1.tar.gz
chmod -R 755 wp-content
chown -R apache:apache wp-content
wget https://s3.amazonaws.com/bucketforwordpresslab-donotdelete/htaccess.txt
mv htaccess.txt .htaccess
cd /var/www/html && mv wp-config-sample.php wp-config.php
sed -i "s@define( 'DB_NAME', 'database_name_here' )@define( 'DB_NAME', 'Group4_DB_Host' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_USER', 'username_here' )@define( 'DB_USER', 'admin' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_PASSWORD', 'password_here' )@define( 'DB_PASSWORD', 'Admin123' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST', '${aws_db_instance.Group4_DB.endpoint}' )@g" /var/www/html/wp-config.php
cd ~
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
yum install unzip -y
unzip awscliv2.zip
./aws/install
cat <<EOT> /var/www/html/.htaccess
Options +FollowSymlinks
RewriteEngine on
rewriterule ^wp-content/uploads/(.*)$ http://${data.aws_cloudfront_distribution.s3_cloudfront_distribution.domain_name}/\$1 [r=301,nc]
# BEGIN WordPress
# END WordPress
EOT
cd /var/www/html
aws s3 cp --recursive /var/www/html/ s3://grp4-s3-codebuck
aws s3 sync /var/www/html/ s3://grp4-s3-codebuck
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync --delete s3://grp4-s3-codebuck /var/www/html/" >> /etc/crontab
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync --delete /var/www/html/wp-content/uploads/ s3://grp4-s3-mediabuck" >> /etc/crontab
cd /etc
service httpd start
cat <<EOT> /etc/httpd/conf/httpd.conf
ServerRoot "/etc/httpd"
Listen 80
Include conf.modules.d/*.conf
User apache
Group apache
ServerAdmin root@localhost
<Directory />
    AllowOverride none
    Require all denied
</Directory>
DocumentRoot "/var/www/html"
<Directory "/var/www">
    AllowOverride None
    Require all granted
</Directory>
<Directory "/var/www/html">
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
<IfModule dir_module>
    DirectoryIndex index.html
</IfModule>
<Files ".ht*">
    Require all denied
</Files>
ErrorLog "logs/error_log"
LogLevel warn
<IfModule alias_module>
    ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"
</IfModule>
<Directory "/var/www/cgi-bin">
    AllowOverride None
    Options None
    Require all granted
</Directory>
<IfModule mime_module>
    TypesConfig /etc/mime.types
    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz
    AddType text/html .shtml
    AddOutputFilter INCLUDES .shtml
</IfModule>
AddDefaultCharset UTF-8
<IfModule mime_magic_module>
    MIMEMagicFile conf/magic
</IfModule>
EnableSendfile on
IncludeOptional conf.d/*.conf
EOT
service httpd restart
chmod -R 777 html/
chkconfig httpd on
sudo sed -i 's/enforcing/disabled/g' /etc/selinux/config /etc/selinux/config
sudo reboot
EOF

  lifecycle {
    create_before_destroy = true
  }
}

#Create Target Group (Instance Target Group)
resource "aws_lb_target_group" "g4TG" {
  name        = "g4TG"
  target_type = "instance"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.Group4_VPC.id

  stickiness {
    type            = "lb_cookie"
    cookie_duration = 1800
    enabled         = true
  }
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 4
    timeout             = 5
    interval            = 10
    path                = "/indextest.html"
    port                = 80
    protocol            = "HTTP"
  }
}

#Create Application Load Balancer (ALB)
resource "aws_lb" "grp4-lb" {
  name               = "grp4-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.front_end_security_group.id}"]
  subnets = [
    "${aws_subnet.G4Pub_SN01.id}",
    "${aws_subnet.G4Pub_SN02.id}"
  ]
  ip_address_type            = "ipv4"
  enable_deletion_protection = false

}

resource "aws_lb_listener" "grp4-lb-listener" {
  load_balancer_arn = aws_lb.grp4-lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.g4TG.arn
  }
}

resource "aws_lb_listener_rule" "grp4-lb-listener-rule-static" {
  depends_on   = [aws_lb_target_group.g4TG]
  listener_arn = aws_lb_listener.grp4-lb-listener.arn
  priority     = "100"
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.g4TG.id
  }
  condition {
    path_pattern {
      values = ["/static/*"]
    }
  }
}

#Create Auto Scaling Group
resource "aws_autoscaling_group" "grp4_auto_scaling_group" {
  name                      = "${aws_launch_configuration.grp4_launch_configuration.name}-asg"
  min_size                  = 1
  desired_capacity          = 1
  max_size                  = 2
  health_check_grace_period = 1200
  health_check_type         = "ELB"
  target_group_arns         = ["${aws_lb_target_group.g4TG.arn}"]
  launch_configuration      = aws_launch_configuration.grp4_launch_configuration.name
  enabled_metrics = [
    "GroupMinSize",
    "GroupMaxSize",
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupTotalInstances"
  ]
  metrics_granularity = "1Minute"
  vpc_zone_identifier = [
    "${aws_subnet.G4Pub_SN01.id}",
    "${aws_subnet.G4Pub_SN02.id}"
  ]
  # Required to redeploy without an outage.
  lifecycle {
    create_before_destroy = true
  }
  tag {
    key                 = "Name"
    value               = "grp4_auto_scaling_group"
    propagate_at_launch = true
  }
}

#Create Auto Scaling Policy
resource "aws_autoscaling_policy" "grp4_auto_scaling_group_policy_up" {
  name                   = "grp4_auto_scaling_group_policy_up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.grp4_auto_scaling_group.name
}
resource "aws_cloudwatch_metric_alarm" "grp4_cpu_alarm_up" {
  alarm_name          = "grp4_cpu_alarm_up"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "70"
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.grp4_auto_scaling_group.name}"
  }
  alarm_description = "This metric monitors EC2 instance CPU utilization to determine scale out"
  alarm_actions     = ["${aws_autoscaling_policy.grp4_auto_scaling_group_policy_up.arn}"]
}
resource "aws_autoscaling_policy" "grp4_policy_down" {
  name                   = "grp4_policy_down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.grp4_auto_scaling_group.name
}
resource "aws_cloudwatch_metric_alarm" "grp4_cpu_alarm_down" {
  alarm_name          = "grp4_cpu_alarm_down"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "30"
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.grp4_auto_scaling_group.name}"
  }
  alarm_description = "This metric monitor EC2 instance CPU utilization to determine scale in"
  alarm_actions     = ["${aws_autoscaling_policy.grp4_policy_down.arn}"]
}

#Attach Target Group to Autoscaling Group
resource "aws_autoscaling_attachment" "Grp4_autoscaling_grp_target_grp_attachment" {
  alb_target_group_arn   = aws_lb_target_group.g4TG.arn
  autoscaling_group_name = aws_autoscaling_group.grp4_auto_scaling_group.id
}

#Attach Target Group to Instance
resource "aws_alb_target_group_attachment" "Grp4_instance_target_grp_attachment" {
  target_group_arn = aws_lb_target_group.g4TG.arn
  target_id        = aws_instance.grp4_web_app_server.id
  port             = 80
  depends_on       = [aws_instance.grp4_web_app_server]
}

# Creation of Route 53 Zone
resource "aws_route53_zone" "grpe4_route53_zone" {
  name = "bgmtayo.online"
  tags = {
    Name = "grpe4_route53_zone"
  }
}

# Creation of Route 53 "A" records and attaching the load balancer as the source
resource "aws_route53_record" "group4_route53_A_record" {
  zone_id = aws_route53_zone.grpe4_route53_zone.zone_id
  name    = "bgmtayo.online"
  type    = "A"
  alias {
    name                   = aws_lb.grp4-lb.dns_name
    zone_id                = aws_lb.grp4-lb.zone_id
    evaluate_target_health = false
  }
}

#Create Infrastructure Monitoring via Cloudwatch
resource "aws_cloudwatch_dashboard" "grp4-web-dashboard" {
  dashboard_name = "grp4-web-dashboard"
  dashboard_body = <<EOF
{
  "widgets": [
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          [
            "AWS/EC2",
            "CPUUtilization",
            "InstanceId",
            "${aws_instance.grp4_web_app_server.id}"
          ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "us-east-1",
        "title": "EC2 Instance CPU"
      }
    },
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          [
            "AWS/EC2",
            "NetworkIn",
            "InstanceId",
            "${aws_instance.grp4_web_app_server.id}"
          ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "us-east-1",
        "title": "EC2 Network In"
      }
    }
  ]
 }
EOF
}

# Create SNS Alarm topic 
resource "aws_sns_topic" "grp4-sns-alarms-topic" {
  name            = "grp4-sns-alarms-topic"
  delivery_policy = <<EOF
{
  "http": {
    "defaultHealthyRetryPolicy": {
      "minDelayTarget": 20,
      "maxDelayTarget": 20,
      "numRetries": 3,
      "numMaxDelayRetries": 0,
      "numNoDelayRetries": 0,
      "numMinDelayRetries": 0,
      "backoffFunction": "linear"
    },
    "disableSubscriptionOverrides": false,
    "defaultThrottlePolicy": {
      "maxReceivesPerSecond": 1
    }
  }
}
EOF
}