# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

locals {
  zones = {
    for index, zone in var.availability_zones : zone => {
      private_cidr = var.private_subnet_cidrs[index]
      public_cidr  = var.public_egress_subnet_cidrs[index]
      zone         = zone
    }
  }
}

resource "aws_vpc" "fabric" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "fabric" {
  vpc_id = aws_vpc.fabric.id

  tags = {
    Name = "${var.name_prefix}-igw"
  }
}

resource "aws_subnet" "public_egress" {
  for_each = local.zones

  vpc_id                  = aws_vpc.fabric.id
  availability_zone       = each.value.zone
  cidr_block              = each.value.public_cidr
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name_prefix}-egress-${each.value.zone}"
  }
}

resource "aws_subnet" "private" {
  for_each = local.zones

  vpc_id                  = aws_vpc.fabric.id
  availability_zone       = each.value.zone
  cidr_block              = each.value.private_cidr
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name_prefix}-private-${each.value.zone}"
  }
}

resource "aws_route_table" "public_egress" {
  vpc_id = aws_vpc.fabric.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.fabric.id
  }

  tags = {
    Name = "${var.name_prefix}-egress"
  }
}

resource "aws_route_table_association" "public_egress" {
  for_each = aws_subnet.public_egress

  route_table_id = aws_route_table.public_egress.id
  subnet_id      = each.value.id
}

resource "aws_eip" "nat" {
  for_each = local.zones
  domain   = "vpc"

  tags = {
    Name = "${var.name_prefix}-nat-${each.key}"
  }
}

resource "aws_nat_gateway" "fabric" {
  for_each      = local.zones
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.public_egress[each.key].id

  depends_on = [aws_internet_gateway.fabric]

  tags = {
    Name = "${var.name_prefix}-nat-${each.key}"
  }
}

resource "aws_route_table" "private" {
  for_each = local.zones
  vpc_id   = aws_vpc.fabric.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.fabric[each.key].id
  }

  tags = {
    Name = "${var.name_prefix}-private-${each.key}"
  }
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  route_table_id = aws_route_table.private[each.key].id
  subnet_id      = each.value.id
}

resource "aws_security_group" "service" {
  name_prefix = "${var.name_prefix}-service-"
  description = "FCP Fabric staging host: no inbound application or SSH access"
  vpc_id      = aws_vpc.fabric.id

  egress {
    description = "HTTPS to Cloudflare Tunnel and required cloud services"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Cloudflare Tunnel TCP connectivity"
    from_port   = 7844
    to_port     = 7844
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Cloudflare Tunnel QUIC connectivity"
    from_port   = 7844
    to_port     = 7844
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-service"
  }
}

resource "aws_security_group" "endpoints" {
  name_prefix = "${var.name_prefix}-endpoints-"
  description = "PrivateLink endpoints accept HTTPS only from Fabric service hosts"
  vpc_id      = aws_vpc.fabric.id

  ingress {
    description     = "HTTPS from Fabric service hosts"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.service.id]
  }

  tags = {
    Name = "${var.name_prefix}-endpoints"
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.fabric.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = values(aws_route_table.private)[*].id

  tags = {
    Name = "${var.name_prefix}-s3"
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = toset([
    "ssm",
    "ssmmessages",
    "ec2messages",
    "logs",
    "kms",
    "secretsmanager",
  ])

  vpc_id              = aws_vpc.fabric.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = values(aws_subnet.private)[*].id
  security_group_ids  = [aws_security_group.endpoints.id]

  tags = {
    Name = "${var.name_prefix}-${each.value}"
  }
}
