# PS-011: Authorised Attack-Surface Inventory and Change Monitor

A Python/Django-based Attack Surface Monitoring (ASM) system designed to discover, inventory, and continuously monitor approved domains and IP targets for exposure and configuration changes.

### Authors: Rishabh Ranjan Jha (264101037), Satyam Kumar Singh (264101045)
### Project ID: PS-011
---
## 1. Overview & Features
Modern organizations accumulate forgotten subdomains, dangling DNS records, and unexpected open ports over time. This system monitors only approved scope targets (`is_active=True`) and alerts on critical changes:
- Scope Management (`Target`): Supports both root domains (`DOMAIN`) and single IP addresses (`IP`) via automatic type detection.
- Asset & Subdomain Enumeration (`Asset`):
	- Passive certificate transparency discovery via `crt.sh`.
	- Active DNS enumeration against common subdomain prefixes.
- DNS & Dangling Record Detection (`DNSRecord`): Resolves DNS records (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, etc.) using `dnspython` and flags dangling CNAME/DNS entries (`is_dangling`).
- TCP Port & Service Scanning (`ServicePort`): Scans TCP ports via Python `socket` and maps services using OS service tables with a custom `KNOWN_SERVICES` fallback (e.g., `3306` → `mysql`, `8080` → `http-alt`, `8443` → `https-alt`).
- TLS / HTTPS Inspection: Inspects HTTPS services on discovered assets.
- Change Detection & Alerting (`ChangeAlert`): Tracks newly discovered subdomains and newly exposed open ports, with false-positive suppression (`is_false_positive`) so future scans ignore acknowledged findings.
- Web Dashboard & Admin UI:
	- Overview page at `/` (`index.html`) showing summary cards, active alerts, target scope, top open ports, and dangling DNS records.
	- Administrative interface at `/admin/` powered by `django-unfold` (read-only for scan results, full control over target scope and false-positive flags).
- Scheduled Scanning: Automated background scans via `python manage.py run_scans` scheduled with OS cron / Task Scheduler or `django-crontab`.
---
## 2. Tech Stack & Dependencies
- Language: Python 3.10+
- Web Framework: Django
- Admin UI: `django-unfold`
- DNS Resolution: `dnspython`
- Database: SQLite3 (via Django ORM)
- Scheduler: OS `cron` / Windows Task Scheduler or `django-crontab`
---
## 3. Project Structure
```text
asm_monitor/
├── asm_project/
│   ├── settings.py          # Installed apps, Unfold config, SQLite DB, static settings
│   ├── urls.py              # Root URL routing ("/" and "/admin/")
│   └── wsgi.py
├── asm/
│   ├── management/
│   │   └── commands/
│   │       └── run_scans.py # Management command to scan all active targets
│   ├── migrations/          # Django database migrations
│   ├── static/
│   │   └── asm/
│   │       └── favicon.ico  # Dashboard & Unfold favicon
│   ├── templates/
│   │   └── asm/
│   │       └── index.html   # Overview dashboard template (localhost:8000/)
│   ├── admin.py             # Unfold admin configuration & search fields
│   ├── api.py               # Exposes REST API endpoints for inventory
│   ├── models.py            # Target, Asset, DNSRecord, ServicePort, ChangeAlert
│   ├── scanner.py           # Subdomain, DNS, TCP port, TLS, and drift scan engine
│   └── views.py             # Index dashboard view
├── db.sqlite3               # SQLite database (created after migrate)
├── manage.py
├── requirements.txt
└── README.md
```
---
## 4. Installation Guide
#### Step 1: Copy or Clone the Project
Open a terminal inside the project root (`asm_monitor/`):
```bash
cd /path/to/asm_monitor
```
#### Step 2: Create and Activate a Virtual Environment
Linux / macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
```
Windows (PowerShell):
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```
#### Step 3: Install Required Packages
```bash
pip install -r requirements.txt
```
(Note: On Windows, `django-crontab` is not supported by native Windows cron; use Windows Task Scheduler instead.)
#### Step 4: Initialize the Database
Run migrations to create all SQLite tables (`Target`, `Asset`, `DNSRecord`, `ServicePort`, `ChangeAlert`):
```bash
python manage.py makemigrations
python manage.py migrate
```
#### Step 5: Create an Admin Superuser
Create an administrator account to log into `/admin/`:
```bash
python manage.py createsuperuser
```
#### Step 7: Start the Development Server
```bash
python manage.py runserver
```
#### Overview Dashboard: `http://127.0.0.1:8000/`
#### Admin Dashboard: `http://127.0.0.1:8000/admin/`
---
## 5. Usage Workflow
### 1. Add Targets in Admin (`/admin/asm/target/`):
- Click Add Target and enter a domain (e.g., `example.com`) or IP address (e.g., `8.8.8.8`) in `target_value`.
- Ensure Is active (`is_active`) is checked.
### 2. Run a Scan Manually:
```bash
   python manage.py run_scans
   ```
### 3. Review Results:
- Open `http://127.0.0.1:8000/` for a high-level summary of active alerts, scope status, top open ports, and dangling DNS records.
- Open `http://127.0.0.1:8000/admin/` to inspect discovered assets, DNS records, open service ports, and alerts.
### 4. Manage False Positives:
- In `/admin/asm/changealert/`, open any expected or benign alert and mark `is_false_positive = True` so future scans suppress repeat alerts for that finding.
---
## 6. Setting Up Automated Periodic Scans
#### Option A: `django-crontab` (Linux / macOS)
##### 1. Ensure `"django_crontab"` is in `INSTALLED_APPS` in `asm_project/settings.py`:
```python
   CRONJOBS = [
       ("0 */12 * * *", "django.core.management.call_command", ["run_scans"], {}, ">> scan.log 2>&1"),
   ]
   ```
##### 2. Register the cron job:
```bash
   python manage.py crontab add
   python manage.py crontab show
   ```
---
## 7. Data Models Summary
| Model         | Purpose                                  | Key Fields                                                                    |
| ------------- | ---------------------------------------- | ----------------------------------------------------------------------------- |
| `Target`      | Approved monitoring scope                | `target_value` (unique), `target_type` (`DOMAIN`/`IP`), `is_active`           |
| `Asset`       | Discovered host/subdomain under a target | `target`, `hostname`, `ip_address`, `is_alive`, `last_scanned`                |
| `DNSRecord`   | DNS records & dangling DNS detection     | `asset`, `record_type`, `value`, `is_dangling`                                |
| `ServicePort` | Open TCP ports & resolved service names  | `asset`, `port`, `service`                                                    |
| `ChangeAlert` | Drift & exposure alerts                  | `target`, `asset`, `alert_type`, `message`, `is_false_positive`, `created_at` |
---
## 8. Troubleshooting & Notes
- TCP-Only Port Scanning: The scanner probes TCP ports using `socket.SOCK_STREAM`. Common non-standard ports (such as `3306` and `8080`) are mapped via `KNOWN_SERVICES` in `asm/scanner.py`.
- Large Domains & `crt.sh`: Large domains with many certificates may experience `crt.sh` timeouts or take longer during sequential port scanning.
- Unimplemented Extension:
	- TLS certificate expiry day-threshold alerts remain an unimplemented extension that flags certificates expiring within a configured number of days.