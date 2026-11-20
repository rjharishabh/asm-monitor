from django.contrib import admin, messages
from unfold.admin import ModelAdmin
from unfold.decorators import display

from .models import Asset, ChangeAlert, DNSRecord, ServicePort, Target
from .scanner import scan_asset_recursive, scan_target_recursive


def open_alerts_badge(request):
    count = ChangeAlert.objects.filter(is_false_positive=False).count()
    return count if count > 0 else None


@admin.action(description="Run scan on active selected targets")
def run_target_scan(modeladmin, request, queryset):
    active_targets = queryset.filter(is_active=True)
    skipped_count = queryset.filter(is_active=False).count()

    scanned_count = 0
    for target in active_targets:
        scan_target_recursive(target)
        scanned_count += 1

    if scanned_count:
        messages.success(request, f"Completed scan for {scanned_count} active target(s).")
    if skipped_count:
        messages.warning(request, f"Skipped {skipped_count} inactive target(s) (is_active=False).")


@admin.action(description="Run DNS + Port scan on selected assets (active targets only)")
def run_asset_scan(modeladmin, request, queryset):
    scanned = 0
    skipped = 0
    for asset in queryset.select_related("target"):
        if not asset.target.is_active:
            skipped += 1
            continue
        scan_asset_recursive(asset)
        scanned += 1

    if scanned:
        messages.success(request, f"Scanned {scanned} asset(s).")
    if skipped:
        messages.warning(request, f"Skipped {skipped} asset(s) belonging to inactive targets.")


@admin.action(description="Toggle Dangling / Not Dangling on selected DNS records")
def toggle_dangling(modeladmin, request, queryset):
    for record in queryset:
        record.is_dangling = not record.is_dangling
        record.save(update_fields=["is_dangling"])
    messages.success(request, f"Toggled dangling status on {queryset.count()} DNS record(s).")


@admin.action(description="Mark selected alerts as False Positive")
def mark_false_positive(modeladmin, request, queryset):
    queryset.update(is_false_positive=True)


@admin.register(Target)
class TargetAdmin(ModelAdmin):
    list_display = ("domain", "ip_address", "is_active", "registrar", "whois_expiry", "created_at")
    list_filter = ("is_active",)
    search_fields = ("domain", "ip_address", "registrar")
    fields = ("domain", "ip_address", "is_active", "registrar", "whois_expiry", "nameservers", "created_at")
    readonly_fields = ("registrar", "whois_expiry", "nameservers", "created_at")
    actions = [run_target_scan]


@admin.register(Asset)
class AssetAdmin(ModelAdmin):
    list_display = ("hostname", "target", "ip_address", "alive_badge", "last_scanned")
    list_filter = ("target", "is_alive")
    search_fields = ("hostname", "ip_address")
    actions = [run_asset_scan]

    @display(description="Status", ordering="is_alive", label={"true": "success", "false": "danger"})
    def alive_badge(self, obj):
        return ("true", "Alive") if obj.is_alive else ("false", "Down")


@admin.register(DNSRecord)
class DNSRecordAdmin(ModelAdmin):
    list_display = ("asset", "record_type", "value", "dangling_badge")
    list_filter = ("record_type", "is_dangling")
    search_fields = ("asset__hostname", "value")
    fields = ("asset", "record_type", "value", "is_dangling")
    actions = [toggle_dangling]

    @display(description="Dangling", ordering="is_dangling", label={"true": "danger", "false": "success"})
    def dangling_badge(self, obj):
        return ("true", "Dangling") if obj.is_dangling else ("false", "Not Dangling")


@admin.register(ServicePort)
class ServicePortAdmin(ModelAdmin):
    list_display = ("asset", "port", "service", "tls_issuer", "tls_expiry")
    list_filter = ("port", "service")
    search_fields = ("asset__hostname", "tls_issuer")


@admin.register(ChangeAlert)
class ChangeAlertAdmin(ModelAdmin):
    list_display = ("alert_type_badge", "target", "asset", "message", "fp_badge", "created_at")
    list_filter = ("alert_type", "is_false_positive", "target")
    search_fields = ("message", "asset__hostname")
    actions = [mark_false_positive]

    @display(
        description="Type",
        ordering="alert_type",
        label={
            "SUBDOMAIN": "info",
            "DANGLING_DNS": "danger",
            "PORT_CHANGE": "warning",
            "TLS_EXPIRY": "danger",
            "DOMAIN_EXPIRY": "warning",
        },
    )
    def alert_type_badge(self, obj):
        return obj.alert_type, obj.get_alert_type_display()

    @display(description="FP Status", ordering="is_false_positive", label={"true": "info", "false": "danger"})
    def fp_badge(self, obj):
        return ("true", "False Positive") if obj.is_false_positive else ("false", "Not False Positive")
