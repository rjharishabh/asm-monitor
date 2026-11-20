import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import Asset, Target
from .scanner import (
    enumerate_subdomains,
    is_ip_value,
    scan_asset_recursive,
    scan_dns,
    scan_ports,
    scan_target_recursive,
    sync_target_type,
)


def _body(request) -> dict:
    try:
        return json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return {}


def _get_or_create_target(val: str) -> Target:
    cleaned = val.strip()
    if not is_ip_value(cleaned):
        cleaned = cleaned.lower()
    target, _ = Target.objects.get_or_create(target_value=cleaned)
    sync_target_type(target)
    return target


def _get_or_create_asset(hostname: str) -> Asset:
    cleaned = hostname.strip()
    if not is_ip_value(cleaned):
        cleaned = cleaned.lower()
        root = ".".join(cleaned.split(".")[-2:]) if "." in cleaned else cleaned
    else:
        root = cleaned
    target = _get_or_create_target(root)
    asset, _ = Asset.objects.get_or_create(target=target, hostname=cleaned)
    return asset


@csrf_exempt
@require_POST
def api_subdomains(request):
    val = (_body(request).get("target") or _body(request).get("domain") or "").strip()
    if not val:
        return JsonResponse({"error": "target is required"}, status=400)

    target = _get_or_create_target(val)
    assets = enumerate_subdomains(target)
    return JsonResponse({
        "target": target.target_value,
        "target_type": target.target_type,
        "is_active": target.is_active,
        "subdomains": [a.hostname for a in assets],
    })


@csrf_exempt
@require_POST
def api_dns(request):
    hostname = (_body(request).get("hostname") or _body(request).get("target") or "").strip()
    if not hostname:
        return JsonResponse({"error": "hostname is required"}, status=400)

    asset = _get_or_create_asset(hostname)
    records = scan_dns(asset)
    return JsonResponse({"hostname": asset.hostname, "ip": asset.ip_address, "dns_records": records})


@csrf_exempt
@require_POST
def api_ports(request):
    data = _body(request)
    hostname = (data.get("hostname") or data.get("target") or "").strip()
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
    val = (data.get("target") or data.get("domain") or data.get("hostname") or "").strip()
    if not val:
        return JsonResponse({"error": "target is required"}, status=400)

    if is_ip_value(val) or ("." in val and len(val.split(".")) > 2 and not data.get("force_target")):
        asset = _get_or_create_asset(val)
        return JsonResponse(scan_asset_recursive(asset))

    target = _get_or_create_target(val)
    return JsonResponse(scan_target_recursive(target))
