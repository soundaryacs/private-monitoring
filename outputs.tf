output "vpc_id" { 
    value = aws_vpc.this.id 
    }


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