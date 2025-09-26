# -------------------------
# Security Groups
# -------------------------
resource "aws_security_group" "prom" {
  name        = "${local.name_prefix}-sg-prom"
  description = "Prometheus"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "From Grafana SG to Prometheus"
    from_port       = 9090
    to_port         = 9090
    protocol        = "tcp"
    security_groups = [aws_security_group.grafana.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { 
    Name = "${local.name_prefix}-sg-prom" 
    }
}

resource "aws_security_group" "grafana" {
  name        = "${local.name_prefix}-sg-grafana"
  description = "Grafana"
  vpc_id      = aws_vpc.this.id

  # No general inbound; SSM port-forward creates a local tunnel
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-sg-grafana" }
}

# -------------------------
# IAM for EC2 (SSM + Prometheus EC2 SD)
# -------------------------
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "ec2_role" {
  name               = "${local.name_prefix}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

# SSM managed
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Prometheus EC2 Service Discovery permissions
data "aws_iam_policy_document" "prom_sd" {
  statement {
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeTags"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "prom_sd" {
  name        = "${local.name_prefix}-prom-ec2-sd"
  description = "Allow EC2 Describe for Prometheus service discovery"
  policy      = data.aws_iam_policy_document.prom_sd.json
}

resource "aws_iam_role_policy_attachment" "prom_sd_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.prom_sd.arn
}

# -------------------------
# Read dashboard JSON (needs the 'local' provider)
# -------------------------
# providers.tf should include:
# required_providers {
#   local = {
#     source  = "hashicorp/local"
#     version = ">= 2.4.0"
#   }
# }

data "local_file" "node_dash" {
  filename = "${path.module}/grafana/dashboards/node-system.json"
}

# (Optional) sed token replacement; define this var if you keep it.
variable "sed_newline_escape" {
  description = "Escape helper for sed replacement; usually left empty."
  type        = string
  default     = ""
}

resource "null_resource" "embed_dashboard" {
  triggers = {
    dash_hash = md5(data.local_file.node_dash.content)
  }

  provisioner "local-exec" {
    command = <<EOT
sed -i \
  -e "s#__DASHBOARD_JSON__#$(printf %s "${replace(replace(data.local_file.node_dash.content, "\\", "\\\\"), var.sed_newline_escape)}")#g" \
  ${path.module}/user_data/grafana.sh
EOT
  }
}
