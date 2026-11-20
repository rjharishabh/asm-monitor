from django.core.management.base import BaseCommand
from asm.models import Target
from asm.scanner import scan_target_recursive


class Command(BaseCommand):
    help = "Run scans across all active targets (is_active=True)"

    def handle(self, *args, **options):
        active_targets = Target.objects.filter(is_active=True)
        for target in active_targets:
            self.stdout.write(f"Scanning active target {target.domain}...")
            res = scan_target_recursive(target)
            self.stdout.write(
                self.style.SUCCESS(f"Completed {target.domain} ({res['assets_scanned']} assets)")
            )
