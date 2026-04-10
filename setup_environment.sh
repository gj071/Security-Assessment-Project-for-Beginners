#!/bin/bash
# setup_environment.sh
# Linux/WSL setup script for the File System Security Research Project
# Creates a sandboxed test environment with intentional misconfigurations
# for safe experimentation.
#
# Usage: chmod +x setup_environment.sh && sudo ./setup_environment.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_DIR="$SCRIPT_DIR/test_sandbox"

echo ""
echo "======================================================================"
echo "  FILE SYSTEM SECURITY RESEARCH — ENVIRONMENT SETUP (Linux)"
echo "======================================================================"
echo ""

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "[*] Python 3 not found. Installing..."
    apt-get update -y && apt-get install -y python3
else
    echo "[✓] Python 3 found: $(python3 --version)"
fi

# Clean up previous sandbox
if [ -d "$SANDBOX_DIR" ]; then
    echo "[*] Removing previous sandbox..."
    rm -rf "$SANDBOX_DIR"
fi

echo "[*] Creating test sandbox at: $SANDBOX_DIR"
mkdir -p "$SANDBOX_DIR"

# ──────────────────────────────────────────────────────
# Directory structure
# ──────────────────────────────────────────────────────
mkdir -p "$SANDBOX_DIR/config"
mkdir -p "$SANDBOX_DIR/logs"
mkdir -p "$SANDBOX_DIR/secrets"
mkdir -p "$SANDBOX_DIR/bin"
mkdir -p "$SANDBOX_DIR/public"
mkdir -p "$SANDBOX_DIR/users/alice/documents"
mkdir -p "$SANDBOX_DIR/users/bob/.ssh"
mkdir -p "$SANDBOX_DIR/tmp"

echo "[*] Directory structure created."

# ──────────────────────────────────────────────────────
# Normal files (correctly permissioned)
# ──────────────────────────────────────────────────────
echo "ApplicationName=FileSystemResearch" > "$SANDBOX_DIR/config/app.conf"
echo "DatabaseHost=localhost" >> "$SANDBOX_DIR/config/app.conf"
echo "DatabasePort=5432" >> "$SANDBOX_DIR/config/app.conf"
chmod 644 "$SANDBOX_DIR/config/app.conf"

echo "LogLevel=INFO" > "$SANDBOX_DIR/config/logging.conf"
chmod 644 "$SANDBOX_DIR/config/logging.conf"

echo "[2026-03-01] Application started." > "$SANDBOX_DIR/logs/app.log"
echo "[2026-03-01] User login: alice" >> "$SANDBOX_DIR/logs/app.log"
echo "[2026-03-01] Query executed successfully" >> "$SANDBOX_DIR/logs/app.log"
chmod 640 "$SANDBOX_DIR/logs/app.log"

echo "Welcome to the research sandbox" > "$SANDBOX_DIR/public/index.html"
chmod 644 "$SANDBOX_DIR/public/index.html"

echo "Alice's important document" > "$SANDBOX_DIR/users/alice/documents/report.txt"
chmod 600 "$SANDBOX_DIR/users/alice/documents/report.txt"

echo '#!/bin/bash' > "$SANDBOX_DIR/bin/healthcheck.sh"
echo 'echo "OK"' >> "$SANDBOX_DIR/bin/healthcheck.sh"
chmod 755 "$SANDBOX_DIR/bin/healthcheck.sh"

echo "[✓] Normal files created with correct permissions."

# ──────────────────────────────────────────────────────
# INTENTIONAL MISCONFIGURATIONS (for research detection)
# ──────────────────────────────────────────────────────
echo "[*] Creating intentional misconfigurations..."

# 1. World-writable configuration file
echo "DB_PASSWORD=supersecret123" > "$SANDBOX_DIR/config/database.conf"
echo "DB_USER=admin" >> "$SANDBOX_DIR/config/database.conf"
chmod 666 "$SANDBOX_DIR/config/database.conf"
echo "    [!] World-writable config: config/database.conf (666)"

# 2. Sensitive key file that is world-readable
echo "-----BEGIN RSA PRIVATE KEY-----" > "$SANDBOX_DIR/secrets/server.key"
echo "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF... (DUMMY DATA)" >> "$SANDBOX_DIR/secrets/server.key"
echo "-----END RSA PRIVATE KEY-----" >> "$SANDBOX_DIR/secrets/server.key"
chmod 644 "$SANDBOX_DIR/secrets/server.key"
echo "    [!] World-readable key: secrets/server.key (644)"

# 3. SSH private key with bad permissions
echo "-----BEGIN OPENSSH PRIVATE KEY-----" > "$SANDBOX_DIR/users/bob/.ssh/id_rsa"
echo "b3BlbnNzaC1rZXktdjEAAAAABG... (DUMMY DATA)" >> "$SANDBOX_DIR/users/bob/.ssh/id_rsa"
echo "-----END OPENSSH PRIVATE KEY-----" >> "$SANDBOX_DIR/users/bob/.ssh/id_rsa"
chmod 644 "$SANDBOX_DIR/users/bob/.ssh/id_rsa"
echo "    [!] World-readable SSH key: users/bob/.ssh/id_rsa (644)"

# 4. Password/shadow file that is too permissive
echo "root:x:0:0:root:/root:/bin/bash" > "$SANDBOX_DIR/secrets/shadow_backup"
echo "admin:\$6\$rounds=5000\$salt\$hash:19000:0:99999:7:::" >> "$SANDBOX_DIR/secrets/shadow_backup"
chmod 644 "$SANDBOX_DIR/secrets/shadow_backup"
echo "    [!] Readable shadow backup: secrets/shadow_backup (644)"

# 5. World-writable directory WITHOUT sticky bit
chmod 777 "$SANDBOX_DIR/tmp"
chmod -t "$SANDBOX_DIR/tmp" 2>/dev/null || true
echo "    [!] World-writable /tmp without sticky bit"

# 6. World-writable script (simulates writable cron job)
echo '#!/bin/bash' > "$SANDBOX_DIR/bin/backup_cron.sh"
echo 'tar czf /backup/data.tar.gz /data' >> "$SANDBOX_DIR/bin/backup_cron.sh"
chmod 777 "$SANDBOX_DIR/bin/backup_cron.sh"
echo "    [!] World-writable script: bin/backup_cron.sh (777)"

# 7. Environment file with secrets exposed
echo "API_KEY=sk-live-abc123def456ghi789" > "$SANDBOX_DIR/config/.env"
echo "JWT_SECRET=mysupersecretjwttoken" >> "$SANDBOX_DIR/config/.env"
echo "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY" >> "$SANDBOX_DIR/config/.env"
chmod 644 "$SANDBOX_DIR/config/.env"
echo "    [!] World-readable .env: config/.env (644)"

# 8. Certificate file with overly broad permissions
echo "-----BEGIN CERTIFICATE-----" > "$SANDBOX_DIR/secrets/cert.pem"
echo "MIIFazCCA1OgAwIBAgIUD... (DUMMY DATA)" >> "$SANDBOX_DIR/secrets/cert.pem"
echo "-----END CERTIFICATE-----" >> "$SANDBOX_DIR/secrets/cert.pem"
chmod 666 "$SANDBOX_DIR/secrets/cert.pem"
echo "    [!] World-writable cert: secrets/cert.pem (666)"

# 9. Executable with SUID bit (simulated)
cp /usr/bin/env "$SANDBOX_DIR/bin/suid_helper" 2>/dev/null || echo '#!/bin/bash' > "$SANDBOX_DIR/bin/suid_helper"
chmod 4755 "$SANDBOX_DIR/bin/suid_helper"
echo "    [!] SUID binary: bin/suid_helper (4755)"

# 10. Token file in public directory
echo '{"access_token":"eyJhbGciOiJIUzI1NiIs...","refresh_token":"dGhpcyBpcyBhIGR1bW15"}' > "$SANDBOX_DIR/public/api_token.json"
chmod 644 "$SANDBOX_DIR/public/api_token.json"
echo "    [!] Token in public dir: public/api_token.json (644)"

echo ""
echo "[✓] Sandbox created with 10 intentional misconfigurations."
echo ""
echo "======================================================================"
echo "  NEXT STEPS"
echo "======================================================================"
echo ""
echo "  Run the research experiments:"
echo ""
echo "  1. Permission Audit:"
echo "     python3 scripts/01_permission_audit.py ./test_sandbox"
echo ""
echo "  2. Integrity Monitor (initialize baseline):"
echo "     python3 scripts/02_integrity_monitor.py --init ./test_sandbox"
echo ""
echo "  3. Integrity Monitor (check after changes):"
echo "     python3 scripts/02_integrity_monitor.py --check ./test_sandbox"
echo ""
echo "  4. Access Pattern Analyzer:"
echo "     python3 scripts/03_access_pattern_analyzer.py data/sample_audit_log.txt"
echo ""
echo "  5. Privilege Escalation Check:"
echo "     python3 scripts/04_privilege_escalation_check.py ./test_sandbox"
echo ""
echo "  6. Forensic Timeline:"
echo "     python3 scripts/05_forensic_timeline.py ./test_sandbox"
echo ""
echo "======================================================================"
