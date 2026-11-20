from django.contrib import admin
from .models import Asset, ChangeAlert, DNSRecord, ServicePort, Target
from .scanner import scan_asset_recursive, scan_target_recursive


@admin.action(description="Run full recursive scan on selected targets")
def run_target_scan(modeladmin, request, queryset):
    for target in queryset:
        scan_target_recursive(target)


@admin.action(description="Run DNS + Port scan on selected assets")
def run_asset_scan(modeladmin, request, queryset):
    for asset in queryset:
        scan_asset_recursive(asset)


@admin.action(description="Mark selected alerts as False Positive")
def mark_false_positive(modeladmin, request, queryset):
    queryset.update(is_false_positive=True)


@admin.register(Target)
class TargetAdmin(admin.ModelAdmin):
    list_display = ("domain", "registrar", "whois_expiry", "created_at")
    search_fields = ("domain", "registrar")
    actions = [run_target_scan]


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ("hostname", "target", "ip_address", "is_alive", "last_scanned")
    list_filter = ("target", "is_alive")
    search_fields = ("hostname", "ip_address")
    actions = [run_asset_scan]


@admin.register(DNSRecord)
class DNSRecordAdmin(admin.ModelAdmin):
    list_display = ("asset", "record_type", "value", "is_dangling")
    list_filter = ("record_type", "is_dangling")
    search_fields = ("asset__hostname", "value")


@admin.register(ServicePort)
class ServicePortAdmin(admin.ModelAdmin):
    list_display = ("asset", "port", "service", "tls_issuer", "tls_expiry")
    list_filter = ("port", "service")
    search_fields = ("asset__hostname", "tls_issuer")


@admin.register(ChangeAlert)
class ChangeAlertAdmin(admin.ModelAdmin):
    list_display = ("alert_type", "target", "asset", "message", "is_false_positive", "created_at")
    list_filter = ("alert_type", "is_false_positive", "target")
    search_fields = ("message", "asset__hostname")
    actions = [mark_false_positive]