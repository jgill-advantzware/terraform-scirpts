resource "aws_vpc" "first" {
  cidr_block                       = var.first_cidr
  enable_dns_support               = "true"
  enable_dns_hostnames             = "true"
  assign_generated_ipv6_cidr_block = "false"
  tags = merge(
    {
      "Name" = format("first-%s", var.environment_name)
    },
    var.tags,
  )
}

resource "aws_subnet" "private_first" {
  for_each                        = var.availability_zones
  vpc_id                          = aws_vpc.first.id
  availability_zone               = each.key
  assign_ipv6_address_on_creation = "false"
  cidr_block                      = var.private_subnets_first[each.key]
  tags = merge(
    {
      "Name"       = format("%s-pri", var.environment_name)
      "SubnetType" = "private"
    },
    var.tags,
  )
  depends_on = [aws_vpc.first]
}

resource "aws_subnet" "public_first" {
  for_each                        = var.availability_zones
  vpc_id                          = aws_vpc.first.id
  availability_zone               = each.key
  assign_ipv6_address_on_creation = "false"
  cidr_block                      = var.public_subnets_first[each.key]
  tags = merge(
    {
      "Name"       = format("%s-pub", var.environment_name)
      "SubnetType" = "public"
    },
    var.tags,
  )
  depends_on = [aws_vpc.first]
}


resource "aws_internet_gateway" "first" {
  vpc_id = aws_vpc.first.id
  tags = {
    Name = "first internet Gateway"
  }
}

##NAT GATEWAY##
resource "aws_eip" "first-aza" {
  vpc = true
}
resource "aws_nat_gateway" "first-aza" {
  allocation_id = aws_eip.first-aza.id
  subnet_id     = aws_subnet.public_first["us-east-1a"].id
  tags = {
    Name = "first AZA NAT Gateway"
  }
  depends_on = [aws_internet_gateway.first]
}

resource "aws_eip" "first-azb" {
  vpc = true
}
resource "aws_nat_gateway" "first-azb" {
  allocation_id = aws_eip.first-azb.id
  subnet_id     = aws_subnet.public_first["us-east-1b"].id
  tags = {
    Name = "first AZB NAT Gateway"
  }
  depends_on = [aws_internet_gateway.first]
}

resource "aws_route_table" "private-route" {
  vpc_id = aws_vpc.first.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.first-aza.id
  }
  tags = {
    Name = "private-routes-first"
  }
  propagating_vgws = [aws_vpn_gateway.personal-first.id]
}
resource "aws_route_table_association" "private-route" {
  for_each       = var.availability_zones
  subnet_id      = aws_subnet.private_first[each.key].id
  route_table_id = aws_route_table.private-route.id
}

resource "aws_route_table" "public-route" {
  vpc_id = aws_vpc.first.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.first.id
  }
  tags = {
    Name = "public-routes-first"
  }
  depends_on = [aws_internet_gateway.first]
}
resource "aws_route_table_association" "public-route" {
  for_each       = var.availability_zones
  subnet_id      = aws_subnet.public_first[each.key].id
  route_table_id = aws_route_table.public-route.id
}


#VPN GateWay
resource "aws_vpn_gateway" "personal-first" {
  tags = {
    Name = "personal-first"
  }
}
resource "aws_vpn_gateway_attachment" "vpn_attachment" {
  vpc_id         = aws_vpc.first.id
  vpn_gateway_id = aws_vpn_gateway.personal-first.id
}

##Customer Gateway ASHBURN
resource "aws_customer_gateway" "personal-ash" {
  bgp_asn    = 65112
  ip_address = var.ash_dc_ip
  type       = "ipsec.1"
  tags = {
    Name = "personal-ASH"
  }
}
##Customer Gateway SJO
resource "aws_customer_gateway" "personal-sjo" {
  bgp_asn    = 65112
  ip_address = var.sjo_dc_ip
  type       = "ipsec.1"
  tags = {
    Name = "personal-SJO"
  }
}

#VPN connections
resource "aws_vpn_connection" "personal-aws-ash" {
  vpn_gateway_id      = aws_vpn_gateway.personal-first.id
  customer_gateway_id = aws_customer_gateway.personal-ash.id
  type                = "ipsec.1"
  tags = {
    Name = "AWS-ASH-VPN"
  }
}
resource "aws_vpn_connection" "personal-aws-sjo" {
  vpn_gateway_id      = aws_vpn_gateway.personal-first.id
  customer_gateway_id = aws_customer_gateway.personal-sjo.id
  type                = "ipsec.1"
  tags = {
    Name = "AWS-SJO-VPN"
  }
}

resource "aws_iam_instance_profile" "first-test" {
  name = format("%s-first", var.environment_name)
  role = aws_iam_role.first.name
}

resource "aws_iam_role" "first" {
  name               = format("%s-first", var.environment_name)
  assume_role_policy = data.aws_iam_policy_document.instance_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "first-KajeetEC2RoleForSSM" {
  role       = aws_iam_role.first.name
  policy_arn = data.aws_iam_policy.KajeetEC2RoleforSSM.arn
}

resource "aws_iam_role_policy_attachment" "first-KajeetEC2Introspection" {
  role       = aws_iam_role.first.name
  policy_arn = data.aws_iam_policy.KajeetEC2Introspection.arn
}

resource "aws_iam_role_policy_attachment" "first-KajeetEC2SSMInstanceProvisioningArtifactReader" {
  role       = aws_iam_role.first.name
  policy_arn = data.aws_iam_policy.KajeetEC2SSMInstanceProvisioningArtifactReader.arn
}

resource "aws_security_group" "all_instances_first" {
  name   = format("%s-first", var.environment_name)
  vpc_id = aws_vpc.first.id
}

resource "aws_security_group_rule" "all_instances_first_allow_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["x.x.x.x/0"]
  security_group_id = aws_security_group.all_instances_first.id
}

resource "aws_security_group_rule" "first_test_lb_allow_ssh" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.first-test-lb.id
  security_group_id        = aws_security_group.all_instances_first.id
}

resource "aws_security_group_rule" "all_instances_first_allow_ping" {
  type              = "ingress"
  from_port         = 8
  to_port           = 0
  protocol          = "icmp"
  cidr_blocks       = ["x.x.x.x/0"]
  security_group_id = aws_security_group.all_instances_first.id
}

resource "aws_security_group_rule" "first-egress-allow-all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.all_instances_first.id
}

resource "aws_instance" "first-test" {
  ami                         = var.rhel8_ami[var.region]
  instance_type               = "t2.medium"
  monitoring                  = true
  key_name                    = var.instance_ssh_keypair
  subnet_id                   = aws_subnet.private_first["us-east-1a"].id
  vpc_security_group_ids      = [aws_security_group.all_instances_first.id]
  associate_public_ip_address = false
  disable_api_termination     = "true"
  iam_instance_profile        = aws_iam_instance_profile.first-test.id
  user_data                   = file("userdata_rhel8.sh")

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 150
    delete_on_termination = false
  }

  tags = merge(
    {
      "Name"             = format("%sxxxxxx%s01.%s", var.hostname_region_prefix[var.region], var.environment, var.domain_name)
      "InstanceFunction" = "first-Test"
      "NamedHost"        = "true"
    },
    var.tags,
  )

  lifecycle {
    ignore_changes = [user_data]
  }
}

resource "aws_security_group" "first-test-lb" {
  name   = format("%s-first-test-lb", var.environment_name)
  vpc_id = aws_vpc.first.id
}
resource "aws_security_group_rule" "first-egress-allow-all-lb" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.first-test-lb.id
}
resource "aws_security_group_rule" "inbound-8432-first" {
  type              = "ingress"
  from_port         = 8432
  to_port           = 8432
  protocol          = "tcp"
  cidr_blocks       = ["x.x.x.x/0"]
  security_group_id = aws_security_group.first-test-lb.id
}

resource "aws_elb" "first-test" {
  name                        = format("%ssentfirst", var.environment)
  subnets                     = values(aws_subnet.public_first)[*].id
  security_groups             = [aws_security_group.first-test-lb.id]
  instances                   = [aws_instance.first-test.id]
  cross_zone_load_balancing   = true
  idle_timeout                = 120
  connection_draining         = true
  connection_draining_timeout = 60
  internal                    = false
  access_logs {
    bucket        = data.terraform_remote_state.personal_nonprod.outputs.logs_bucket_id
    bucket_prefix = data.terraform_remote_state.personal_nonprod.outputs.logs_bucket_alb_logs_prefix
    interval      = 5
  }
  listener {
    instance_port      = 22
    instance_protocol  = "tcp"
    lb_port            = 8432
    lb_protocol        = "tcp"
    ssl_certificate_id = ""
  }
  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    target              = "TCP:22"
    timeout             = 3
  }
  tags = merge(
    var.tags,
  )
}

resource "aws_route53_record" "firsttestlb" {
  provider = aws.dns
  zone_id  = data.aws_route53_zone.public_domain_name_zone.zone_id
  name     = var.personal_first_fqdn
  type     = "A"
  alias {
    name                   = aws_elb.first-test.dns_name
    zone_id                = aws_elb.first-test.zone_id
    evaluate_target_health = false
  }
}
