# DNS — Route53 records

resource "aws_route53_zone" "cerberus" {
  name = var.domain

  tags = {
    Name        = "cerberus-zone"
    Environment = var.environment
  }
}

resource "aws_route53_record" "api" {
  zone_id = aws_route53_zone.cerberus.zone_id
  name    = "api.${var.domain}"
  type    = "A"

  alias {
    name                   = aws_lb.cerberus.dns_name
    zone_id                = aws_lb.cerberus.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "app" {
  zone_id = aws_route53_zone.cerberus.zone_id
  name    = var.domain
  type    = "A"

  alias {
    name                   = aws_lb.cerberus.dns_name
    zone_id                = aws_lb.cerberus.zone_id
    evaluate_target_health = true
  }
}
