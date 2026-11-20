import json
import socket
import ssl
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen

import dns.resolver
import whois
from cryptography import x509
from django.utils import timezone as dj_timezone

from .models import Asset, ChangeAlert, DNSRecord, ServicePort, Target

COMMON_SUBDOMAINS = [
    "www", "api", "dev", "staging", "test", "admin", "mail", "portal", "app", "vpn"
]
COMMON_PORTS = [21, 22, 25, 53, 80, 443, 3306, 5432, 8080, 8443]
DANGLING_SUFFIXES = (
    ".azurewebsites.net",
    ".herokuapp.com",
    ".s3.amazonaws.com",
    ".github.io",
    ".pantheonsite.io",
    ".myshopify.com",
)


def _create_alert(target: Target, asset: Asset | None, alert_type: str, message: str):
    """Create alert unless an identical false-positive alert was already suppressed."""
    if ChangeAlert.objects.filter(
        target=target, asset=asset, alert_type=alert_type, message=message, is_false_positive=True
    ).exists():
        return
    ChangeAlert.objects.get_or_create(
        target=target, asset=asset, alert_type=alert_type, message=message
    )


def scan_whois(target: Target):
    """Fetch WHOIS registrar, nameservers, and expiry date for a target domain."""
    try:
        info = whois.whois(target.domain)
        expiry = info.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if isinstance(expiry, datetime):
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            target.whois_expiry = expiry
            if expiry <= datetime.now(timezone.utc) + timedelta(days=30):
                _create_alert(
                    target, None, "DOMAIN_EXPIRY",
                    f"Domain {target.domain} expires on {expiry.date()}"
                )

        target.registrar = str(info.registrar or "")[:255]
        ns = info.name_servers or []
        if isinstance(ns, list):
            target.nameservers = ", ".join(sorted({str(x).lower() for x in ns}))
        target.save(update_fields=["registrar", "whois_expiry", "nameservers"])
    except Exception:
        pass


def enumerate_subdomains(target: Target) -> list[Asset]:
    """Enumerate subdomains via Certificate Transparency (crt.sh) + common wordlist."""
    discovered = {target.domain}

    try:
        url = f"https://crt.sh/?q=%25.{target.domain}&output=json"
        req = Request(url, headers={"User-Agent": "ASM-Scanner/1.0"})
        with urlopen(req, timeout=8) as resp:
            rows = json.loads(resp.read().decode("utf-8", errors="ignore"))
            for row in rows:
                for name in str(row.get("name_value", "")).splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name == target.domain or name.endswith(f".{target.domain}"):
                        discovered.add(name)
    except Exception:
        pass

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2.0
    for sub in COMMON_SUBDOMAINS:
        candidate = f"{sub}.{target.domain}"
        try:
            resolver.resolve(candidate, "A")
            discovered.add(candidate)
        except Exception:
            continue

    assets = []
    for host in sorted(discovered):
        asset, created = Asset.objects.get_or_create(target=target, hostname=host)
        if created:
            _create_alert(target, asset, "SUBDOMAIN", f"New subdomain discovered: {host}")
        assets.append(asset)
    return assets


def scan_dns(asset: Asset) -> list[dict]:
    """Query DNS records (A, AAAA, CNAME, MX, TXT, NS) and detect dangling CNAMEs."""
    DNSRecord.objects.filter(asset=asset).delete()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    records = []

    try:
        ip = resolver.resolve(asset.hostname, "A")[0].to_text()
        asset.ip_address = ip
        asset.is_alive = True
    except Exception:
        asset.is_alive = False
    asset.save(update_fields=["ip_address", "is_alive"])

    for rtype in ("A", "AAAA", "CNAME", "MX", "TXT", "NS"):
        try:
            for ans in resolver.resolve(asset.hostname, rtype):
                val = ans.to_text().strip(".")
                dangling = False

                if rtype == "CNAME" and val.lower().endswith(DANGLING_SUFFIXES):
                    try:
                        resolver.resolve(val, "A")
                    except Exception:
                        dangling = True
                        _create_alert(
                            asset.target, asset, "DANGLING_DNS",
                            f"Dangling CNAME on {asset.hostname} -> {val}"
                        )

                DNSRecord.objects.create(
                    asset=asset, record_type=rtype, value=val, is_dangling=dangling
                )
                records.append({"type": rtype, "value": val, "dangling": dangling})
        except Exception:
            continue

    return records


def _inspect_tls(hostname: str, port: int) -> tuple[str, datetime | None]:
    """Retrieve TLS certificate issuer and expiration timestamp."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=2.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return "", None
                cert = x509.load_der_x509_certificate(der_cert)
                issuer = cert.issuer.rfc4514_string()[:255]
                return issuer, cert.not_valid_after_utc
    except Exception:
        return "", None


def scan_ports(asset: Asset, ports: list[int] | None = None) -> list[dict]:
    """Scan TCP ports, inspect TLS certificates, and alert on port/cert changes."""
    ports = ports or COMMON_PORTS
    host = asset.ip_address or asset.hostname
    previous_ports = set(ServicePort.objects.filter(asset=asset).values_list("port", flat=True))
    ServicePort.objects.filter(asset=asset).delete()

    open_services = []
    current_ports = set()

    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=1.5):
                current_ports.add(port)
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"

                issuer, expiry = ("", None)
                if port in (443, 8443):
                    issuer, expiry = _inspect_tls(asset.hostname, port)

                ServicePort.objects.create(
                    asset=asset,
                    port=port,
                    service=service,
                    tls_issuer=issuer,
                    tls_expiry=expiry,
                )
                open_services.append({
                    "port": port,
                    "service": service,
                    "tls_expiry": expiry.isoformat() if expiry else None,
                })

                if port not in previous_ports:
                    _create_alert(
                        asset.target, asset, "PORT_CHANGE",
                        f"New open port {port}/{service} exposed on {asset.hostname}"
                    )

                if expiry and expiry <= datetime.now(timezone.utc) + timedelta(days=14):
                    _create_alert(
                        asset.target, asset, "TLS_EXPIRY",
                        f"TLS cert on {asset.hostname}:{port} expires {expiry.date()}"
                    )
        except Exception:
            continue

    for closed_port in previous_ports - current_ports:
        _create_alert(
            asset.target, asset, "PORT_CHANGE",
            f"Previously open port {closed_port} closed on {asset.hostname}"
        )

    asset.last_scanned = dj_timezone.now()
    asset.save(update_fields=["last_scanned"])
    return open_services


def scan_asset_recursive(asset: Asset) -> dict:
    """Scan DNS records and open ports/TLS for a single asset."""
    dns_records = scan_dns(asset)
    open_ports = scan_ports(asset)
    return {
        "hostname": asset.hostname,
        "ip": asset.ip_address,
        "dns_records": dns_records,
        "open_ports": open_ports,
    }


def scan_target_recursive(target: Target) -> dict:
    """Run WHOIS, enumerate subdomains, and recursively scan every asset."""
    scan_whois(target)
    assets = enumerate_subdomains(target)
    results = [scan_asset_recursive(asset) for asset in assets]
    return {
        "target": target.domain,
        "assets_scanned": len(results),
        "results": results,
    }