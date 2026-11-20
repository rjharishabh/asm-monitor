from django.db import models


class Target(models.Model):
    target_value = models.CharField(max_length=255, unique=True, help_text="Enter a domain or an IP address")
    target_type = models.CharField(max_length=16, blank=True, default="DOMAIN")  # DOMAIN or IP
    is_active = models.BooleanField(default=True)
    registrar = models.CharField(max_length=255, blank=True, default="")
    whois_expiry = models.DateTimeField(null=True, blank=True)
    nameservers = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.target_value


class Asset(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name="assets")
    hostname = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    is_alive = models.BooleanField(default=True)
    last_scanned = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ("target", "hostname")

    def __str__(self):
        return self.hostname


class DNSRecord(models.Model):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="dns_records")
    record_type = models.CharField(max_length=16)  # A, AAAA, CNAME, MX, TXT, NS, PTR
    value = models.TextField()
    is_dangling = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.asset.hostname} [{self.record_type}] {self.value}"


class ServicePort(models.Model):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="ports")
    port = models.IntegerField()
    service = models.CharField(max_length=100, default="unknown")
    tls_issuer = models.CharField(max_length=255, blank=True, default="")
    tls_expiry = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.asset.hostname}:{self.port} ({self.service})"


class ChangeAlert(models.Model):
    ALERT_TYPES = [
        ("SUBDOMAIN", "New Subdomain"),
        ("DANGLING_DNS", "Dangling DNS"),
        ("PORT_CHANGE", "Port Change"),
        ("TLS_EXPIRY", "TLS Certificate Expiry"),
        ("DOMAIN_EXPIRY", "Domain WHOIS Expiry"),
    ]
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name="alerts")
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, null=True, blank=True)
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPES)
    message = models.CharField(max_length=255)
    is_false_positive = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = "Security Alert"
        verbose_name_plural = "Security Alerts"

    def __str__(self):
        return f"[{self.alert_type}] {self.message}"
