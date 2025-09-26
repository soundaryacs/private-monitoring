# AWS Private Prometheus + Grafana 

A production‑ready starter to deploy Prometheus + Grafana on private EC2 in a private VPC. Access is provided via AWS SSM port forwarding (no public IPs). Optional blocks for internal ALB + Cognito and Client VPN are included but disabled by default.



# AWS Private Prometheus + Grafana (Terraform Starter)

A production‑ready starter to deploy **Prometheus + Grafana on private EC2** in a private VPC. Access is provided via **AWS SSM port forwarding** (no public IPs). Optional blocks for internal ALB + Cognito and Client VPN are included but disabled by default.

> Default region: `ap-south-1` (Mumbai). Change via `var.region`.

---

## Folder structure

```
private-monitoring/
├─ main.tf
├─ providers.tf
├─ backend.tf            # ← optional: fill your S3/DynamoDB
├─ variables.tf
├─ outputs.tf
├─ user_data/
│   ├─ grafana.sh
│   └─ prometheus.sh
├─ prometheus/
│   └─ prometheus.yml.tmpl   # ← NEW: rendered into /etc/prometheus/prometheus.yml
└─ grafana/
    ├─ provisioning/
    │   └─ datasources/prometheus.yaml.tmpl
    └─ dashboards/
        └─ node-system.json
```

---

## main.tf

```hcl
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50"
    }
    template = {
      source  = "hashicorp/template"
      version = ">= 2.2.0"
    }
  }
}

locals {
  name_prefix          = var.project
  azs                  = slice(data.aws_availability_zones.available.names, 0, 2)
  prometheus_version   = var.prometheus_version
  node_exporter_port   = 9100
}

# -------------------------
# Networking (VPC + subnets)
# -------------------------
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "${local.name_prefix}-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${local.name_prefix}-igw" }
}

resource "aws_subnet" "public" {
  for_each = { for idx, az in local.azs : idx => az }
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, each.key)
  availability_zone       = each.value
  map_public_ip_on_launch = true
  tags = { Name = "${local.name_prefix}-public-${each.value}" }
}

resource "aws_subnet" "private" {
  for_each = { for idx, az in local.azs : idx => az }
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, each.key + 8)
  availability_zone = each.value
  tags = { Name = "${local.name_prefix}-private-${each.value}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "${local.name_prefix}-rtb-public" }
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# NAT (optional). If you prefer NO outbound internet, remove NAT and use SSM only.
resource "aws_eip" "nat" {
  vpc = true
  tags = { Name = "${local.name_prefix}-nat-eip" }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = values(aws_subnet.public)[0].id
  tags          = { Name = "${local.name_prefix}-nat" }
  depends_on    = [aws_internet_gateway.igw]
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = { Name = "${local.name_prefix}-rtb-private" }
}

resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}

# -------------------------
# Security Groups
# -------------------------
# Grafana can reach Prometheus (9090). End‑user access is via SSM port‑forward, so no inbound from internet.
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

  tags = { Name = "${local.name_prefix}-sg-prom" }
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
resource "aws_iam_role" "ec2_role" {
  name               = "${local.name_prefix}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

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

# SSM managed + DescribeInstances for Prometheus SD
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_policy" "prom_sd" {
  name        = "${local.name_prefix}-prom-ec2-sd"
  description = "Allow EC2 Describe for Prometheus service discovery"
  policy      = data.aws_iam_policy_document.prom_sd.json
}

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

resource "aws_iam_role_policy_attachment" "prom_sd_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.prom_sd.arn
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${local.name_prefix}-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# -------------------------
# AMI Lookup (Ubuntu 22.04 LTS)
# -------------------------
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# -------------------------
# Prometheus EC2 (private)
# -------------------------
resource "aws_instance" "prometheus" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = values(aws_subnet.private)[0].id
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  vpc_security_group_ids      = [aws_security_group.prom.id]

  # Render user_data and inject a templated prometheus.yml
  user_data = templatefile("${path.module}/user_data/prometheus.sh", {
    prometheus_config = templatefile("${path.module}/prometheus/prometheus.yml.tmpl", {
      region = var.region
    })
  })

  tags = {
    Name        = "${local.name_prefix}-prometheus"
    Monitoring  = "true"
    Component   = "prometheus"
  }
}

# -------------------------
# Grafana EC2 (private)
# -------------------------
resource "aws_instance" "grafana" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = values(aws_subnet.private)[1].id
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  vpc_security_group_ids      = [aws_security_group.grafana.id]

  # Render the datasource template with Prometheus private IP
  user_data = templatefile("${path.module}/user_data/grafana.sh", {
    prometheus_url = "http://${aws_instance.prometheus.private_ip}:9090"
  })

  tags = {
    Name      = "${local.name_prefix}-grafana"
    Component = "grafana"
  }
}

# -------------------------
# (Optional) Internal ALB + Cognito – disabled by default
# Uncomment and configure if you prefer ALB + OIDC SSO instead of SSM
# -------------------------
# resource "aws_lb" "internal" {
#   name               = "${local.name_prefix}-alb-int"
#   internal           = true
#   load_balancer_type = "application"
#   security_groups    = [aws_security_group.grafana.id]
#   subnets            = [for s in aws_subnet.private : s.id]
# }

# resource "aws_lb_target_group" "grafana_tg" {
#   name     = "${local.name_prefix}-tg-grafana"
#   port     = 3000
#   protocol = "HTTP"
#   vpc_id   = aws_vpc.this.id
#   health_check {
#     path                = "/login"
#     healthy_threshold   = 2
#     unhealthy_threshold = 2
#     timeout             = 5
#     interval            = 15
#     matcher             = "200-399"
#   }
# }

# resource "aws_lb_target_group_attachment" "grafana_attach" {
#   target_group_arn = aws_lb_target_group.grafana_tg.arn
#   target_id        = aws_instance.grafana.id
#   port             = 3000
# }

# resource "aws_lb_listener" "https" {
#   load_balancer_arn = aws_lb.internal.arn
#   port              = 443
#   protocol          = "HTTPS"
#   ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
#   certificate_arn   = var.acm_certificate_arn
#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.grafana_tg.arn
#   }
# }
```

---

## providers.tf

```hcl
provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}
```

---

## backend.tf (optional – fill with your S3/DynamoDB)

```hcl
# terraform {
#   backend "s3" {
#     bucket         = "your-tfstate-bucket"
#     key            = "private-monitoring/terraform.tfstate"
#     region         = "ap-south-1"
#     dynamodb_table = "your-tf-locks"
#     encrypt        = true
#   }
# }
```

---

## variables.tf

```hcl
variable "project" {
  description = "Name prefix for all resources"
  type        = string
  default     = "priv-mon"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "ap-south-1"
}

variable "vpc_cidr" {
  description = "VPC CIDR"
  type        = string
  default     = "10.20.0.0/16"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.small"
}

variable "prometheus_version" {
  description = "Prometheus version"
  type        = string
  default     = "2.55.1"
}

# For ALB OIDC (optional)
variable "acm_certificate_arn" {
  description = "ACM cert ARN for internal ALB (optional)"
  type        = string
  default     = null
}
```

---

## outputs.tf

```hcl
output "vpc_id" { value = aws_vpc.this.id }

output "prometheus_private_ip" {
  value = aws_instance.prometheus.private_ip
}

output "grafana_private_ip" {
  value = aws_instance.grafana.private_ip
}

output "grafana_ssm_id" {
  value = aws_instance.grafana.id
}

output "prometheus_ssm_id" {
  value = aws_instance.prometheus.id
}
```

---

## user_data/prometheus.sh

```bash
#!/usr/bin/env bash
set -euo pipefail

# Basic packages
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl jq tar

# Create user and dirs
id -u prometheus &>/dev/null || useradd --no-create-home --shell /usr/sbin/nologin prometheus
mkdir -p /etc/prometheus /var/lib/prometheus

VER="2.55.1"
cd /tmp
curl -sS -L -o prometheus.tgz "https://github.com/prometheus/prometheus/releases/download/v${VER}/prometheus-${VER}.linux-amd64.tar.gz"
tar xzf prometheus.tgz
cd prometheus-${VER}.linux-amd64
cp prometheus promtool /usr/local/bin/
cp -r consoles console_libraries /etc/prometheus/

# Write templated config passed from Terraform
cat > /etc/prometheus/prometheus.yml <<'YAML'
${prometheus_config}
YAML

# Systemd unit
cat >/etc/systemd/system/prometheus.service <<'UNIT'
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/var/lib/prometheus \
  --web.listen-address=0.0.0.0:9090 \
  --storage.tsdb.retention.time=15d

[Install]
WantedBy=multi-user.target
UNIT

chown -R prometheus:prometheus /etc/prometheus /var/lib/prometheus
systemctl daemon-reload
systemctl enable --now prometheus
```

---

## user_data/grafana.sh (templated)

```bash
#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y software-properties-common wget gpg

mkdir -p /etc/apt/keyrings
wget -q -O - https://packages.grafana.com/gpg.key | gpg --dearmor -o /etc/apt/keyrings/grafana.gpg

echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://packages.grafana.com/oss/deb stable main" \
  > /etc/apt/sources.list.d/grafana.list

apt-get update -y && apt-get install -y grafana jq

# Provision Prometheus datasource
mkdir -p /etc/grafana/provisioning/datasources
cat >/etc/grafana/provisioning/datasources/prometheus.yaml <<'YAML'
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: "${prometheus_url}"
    isDefault: true
YAML

# Provision a starter dashboard
mkdir -p /var/lib/grafana/dashboards
cat >/var/lib/grafana/dashboards/node-system.json <<'JSON'
__DASHBOARD_JSON__
JSON

mkdir -p /etc/grafana/provisioning/dashboards
cat >/etc/grafana/provisioning/dashboards/dashboards.yaml <<'YAML'
apiVersion: 1
providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /var/lib/grafana/dashboards
YAML

systemctl enable --now grafana-server
```

> Note: Terraform’s `templatefile()` will replace `${prometheus_url}` in the datasource above. The special token `__DASHBOARD_JSON__` will be replaced during `terraform apply` with the JSON below.

---

## grafana/dashboards/node-system.json (minimal example)

A compact, safe-to-share dashboard showing CPU, memory, disk, and load from Node Exporter metrics.

```json
{
  "id": null,
  "title": "Node System Overview (Starter)",
  "timezone": "browser",
  "schemaVersion": 38,
  "version": 1,
  "refresh": "10s",
  "panels": [
    { "type": "timeseries", "title": "CPU Usage %", "targets": [{ "expr": "100 - (avg by(instance) (irate(node_cpu_seconds_total{mode=\\"idle\\"}[5m])) * 100)", "legendFormat": "{{instance}}" }], "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0} },
    { "type": "timeseries", "title": "Memory Used %", "targets": [{ "expr": "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100", "legendFormat": "{{instance}}" }], "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0} },
    { "type": "timeseries", "title": "Root FS Used %", "targets": [{ "expr": "(node_filesystem_size_bytes{mountpoint=\\"/\\",fstype!~\\"tmpfs|devtmpfs\\"} - node_filesystem_free_bytes{mountpoint=\\"/\\",fstype!~\\"tmpfs|devtmpfs\\"}) / node_filesystem_size_bytes{mountpoint=\\"/\\",fstype!~\\"tmpfs|devtmpfs\\"} * 100", "legendFormat": "{{instance}}" }], "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8} },
    { "type": "timeseries", "title": "Load 1m", "targets": [{ "expr": "node_load1", "legendFormat": "{{instance}}" }], "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8} }
  ],
  "templating": {"list": []}
}
```

---

## prometheus/prometheus.yml.tmpl (NEW)

Rendered into `/etc/prometheus/prometheus.yml` via `templatefile()`.

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets: []

rule_files:
  # - "alert.rules"

scrape_configs:
  # Prometheus itself
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  # EC2 node exporters (dynamic discovery)
  - job_name: 'ec2-node-exporters'
    ec2_sd_configs:
      - region: ${region}
        port: 9100
        filters:
          - name: tag:Monitoring
            values: ["true"]
    relabel_configs:
      - source_labels: [__meta_ec2_private_ip]
        target_label: instance
      - source_labels: [__meta_ec2_tag_Name]
        target_label: instance_name
```

---

## Post‑apply step: inject dashboard JSON via Terraform

Add this to the end of **main.tf** to replace the `__DASHBOARD_JSON__` token inside user_data at apply‑time.

```hcl
# Read dashboard JSON
data "local_file" "node_dash" {
  filename = "${path.module}/grafana/dashboards/node-system.json"
}

# Replace token in grafana user_data (works because templatefile already rendered datasource)
resource "null_resource" "embed_dashboard" {
  triggers = {
    dash_hash = md5(data.local_file.node_dash.content)
  }

  provisioner "local-exec" {
    command = <<EOT
      sed -i \
        -e "s#__DASHBOARD_JSON__#$(printf %s "${replace(replace(data.local_file.node_dash.content, "\\", "\\\\"),
        var.sed_newline_escape)}")#g" \
        ${path.module}/user_data/grafana.sh
    EOT
  }
}
```

> **Note:** For simplicity, you can also paste the JSON directly into `user_data/grafana.sh` where the token is.

---

## How to use

1. **Init & apply**

```bash
cd private-monitoring
terraform init
terraform apply -auto-approve
```

2. **Get outputs**

```bash
terraform output
```

3. **Access via SSM port forward**

```bash
# Grafana (open localhost:3000)
aws ssm start-session \
  --target $(terraform output -raw grafana_ssm_id) \
  --document-name AWS-StartPortForwardingSession \
  --parameters "portNumber=3000,localPortNumber=3000"

# Prometheus (open localhost:9090)
aws ssm start-session \
  --target $(terraform output -raw prometheus_ssm_id) \
  --document-name AWS-StartPortForwardingSession \
  --parameters "portNumber=9090,localPortNumber=9090"
```

4. **Add more EC2 targets**: install **Node Exporter** and tag the instance with `Monitoring=true`. Prometheus will auto‑discover.

---

## Hardening checklist

* Change Grafana admin password (or enable OIDC via internal ALB).
* Keep Prometheus UI private; never expose 9090 publicly.
* Patch OS regularly (SSM Patch Manager).
* Snapshot EBS for Prometheus; back up `/var/lib/grafana`.

---

## Troubleshooting

* **No targets in Prometheus** → ensure Node Exporter is running and instance tagged `Monitoring=true`.
* **SSM connect fails** → instance profile must include `AmazonSSMManagedInstanceCore`; check VPC endpoints if you removed NAT.
* **Grafana empty panels** → Verify Prometheus datasource URL in `/etc/grafana/provisioning/datasources/prometheus.yaml`.

---

### Notes

* If you want a *fully managed* control plane, consider **Amazon Managed Service for Prometheus** and **Amazon Managed Grafana**; keep agents private.
* Swap NAT for **VPC Endpoints** (SSM, EC2, S3) to go fully egress‑restricted.
