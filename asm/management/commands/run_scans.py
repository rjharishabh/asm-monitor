from django.core.management.base import BaseCommand
from asm.models import Target
from asm.scanner import scan_target_recursive


class Command(BaseCommand):
    help = "Run scheduled attack-surface scans across all approved targets"

    def handle(self, *args, **options):
        for target in Target.objects.all():
            self.stdout.write(f"Scanning {target.domain}...")
            res = scan_target_recursive(target)
            self.stdout.write(self.style.SUCCESS(f"Completed {target.domain} ({res['assets_scanned']} assets)"))