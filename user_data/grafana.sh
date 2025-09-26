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