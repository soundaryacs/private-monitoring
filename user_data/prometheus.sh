#!/usr/bin/env bash
tar xzf prometheus.tgz
cd prometheus-${VER}.linux-amd64
cp prometheus promtool /usr/local/bin/
cp -r consoles console_libraries /etc/prometheus/


# Prometheus config
cat >/etc/prometheus/prometheus.yml <<'YAML'
global:
scrape_interval: 15s
evaluation_interval: 15s


scrape_configs:
- job_name: 'prometheus'
static_configs:
- targets: ['localhost:9090']


- job_name: 'ec2-node-exporters'
ec2_sd_configs:
- region: ap-south-1
port: 9100
filters:
- name: tag:Monitoring
values: ["true"]
relabel_configs:
- source_labels: [__meta_ec2_private_ip]
target_label: instance
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