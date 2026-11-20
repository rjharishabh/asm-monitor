import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import Asset, Target
from .scanner import (
    enumerate_subdomains,
    scan_asset_recursive,
    scan_dns,
    scan_ports,
    scan_target_recursive,
)


def _body(request) -> dict:
    try:
        return json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return {}


def _get_or_create_asset(hostname: str, domain: str | None = None) -> Asset:
    hostname = hostname.strip().lower()
    root = (domain or (".".join(hostname.split(".")[-2:]) if "." in hostname else hostname)).strip().lower()
    target, _ = Target.objects.get_or_create(domain=root)
    asset, _ = Asset.objects.get_or_create(target=target, hostname=hostname)
    return asset


@csrf_exempt
@require_POST
def api_subdomains(request):
    domain = (_body(request).get("domain") or "").strip().lower()
    if not domain:
        return JsonResponse({"error": "domain is required"}, status=400)

    target, _ = Target.objects.get_or_create(domain=domain)
    assets = enumerate_subdomains(target)
    return JsonResponse({"domain": target.domain, "subdomains": [a.hostname for a in assets]})


@csrf_exempt
@require_POST
def api_dns(request):
    hostname = (_body(request).get("hostname") or "").strip().lower()
    if not hostname:
        return JsonResponse({"error": "hostname is required"}, status=400)

    asset = _get_or_create_asset(hostname)
    records = scan_dns(asset)
    return JsonResponse({"hostname": asset.hostname, "ip": asset.ip_address, "dns_records": records})


@csrf_exempt
@require_POST
def api_ports(request):
    data = _body(request)
    hostname = (data.get("hostname") or "").strip().lower()
    ports = data.get("ports")
    if not hostname:
        return JsonResponse({"error": "hostname is required"}, status=400)

    asset = _get_or_create_asset(hostname)
    open_ports = scan_ports(asset, ports=ports)
    return JsonResponse({"hostname": asset.hostname, "open_ports": open_ports})


@csrf_exempt
@require_POST
def api_recursive(request):
    data = _body(request)
    domain = (data.get("domain") or "").strip().lower()
    hostname = (data.get("hostname") or "").strip().lower()

    if hostname:
        asset = _get_or_create_asset(hostname, domain or None)
        return JsonResponse(scan_asset_recursive(asset))

    if not domain:
        return JsonResponse({"error": "domain or hostname is required"}, status=400)

    target, _ = Target.objects.get_or_create(domain=domain)
    return JsonResponse(scan_target_recursive(target))