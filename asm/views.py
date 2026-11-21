from django.db.models import Count
from django.shortcuts import render
from .models import Asset, ChangeAlert, DNSRecord, ServicePort, Target


def index(request):
    context = {
        "active_targets": Target.objects.filter(is_active=True).count(),
        "total_targets": Target.objects.count(),
        "total_assets": Asset.objects.count(),
        "alive_assets": Asset.objects.filter(is_alive=True).count(),
        "dangling_dns": DNSRecord.objects.filter(is_dangling=True).count(),
        "open_ports": ServicePort.objects.count(),
        "active_alerts": ChangeAlert.objects.filter(is_false_positive=False).count(),
        "targets_list": Target.objects.order_by("-is_active", "target_value")[:10],
        "recent_alerts": ChangeAlert.objects.select_related("target", "asset")
        .filter(is_false_positive=False)
        .order_by("-created_at")[:8],
        "dangling_records": DNSRecord.objects.select_related("asset", "asset__target")
        .filter(is_dangling=True)
        .order_by("id")[:8],
        "top_ports": ServicePort.objects.values("port", "service")
        .annotate(total=Count("id"))
        .order_by("-total", "port")[:8],
    }
    return render(request, "asm/index.html", context)
