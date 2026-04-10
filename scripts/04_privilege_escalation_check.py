#!/usr/bin/env python3
"""
04_privilege_escalation_check.py - Privilege Escalation Pathway Detection

Research Experiment E4: Identify file system conditions that create
exploitable privilege escalation pathways.

Checks performed:
  - SUID/SGID binaries cross-referenced against GTFOBins exploitable list
  - World-writable directories in $PATH (binary planting)
  - Writable cron directories and scripts
  - Writable service configuration files
  - Insecure /tmp patterns (predictable names, missing sticky bit)
  - Sensitive files with overly permissive access

Usage:
  python 04_privilege_escalation_check.py [target_directory]

Author: File System Security Research Project
"""

import os
import sys
import stat
import platform
from datetime import datetime
from pathlib import Path

# GTFOBins SUID exploitable binaries (subset)
GTFOBINS_SUID = {
    'aria2c', 'ash', 'awk', 'base32', 'base64', 'bash', 'busybox', 'cat',
    'chmod', 'chown', 'cp', 'csh', 'curl', 'cut', 'dash', 'dd', 'diff',
    'docker', 'ed', 'emacs', 'env', 'expand', 'expect', 'file', 'find',
    'flock', 'fmt', 'fold', 'gawk', 'gdb', 'gimp', 'grep', 'head', 'hex',
    'highlight', 'iconv', 'ionice', 'ip', 'jq', 'ksh', 'ld.so', 'less',
    'logsave', 'look', 'lua', 'make', 'mawk', 'more', 'mv', 'nano',
    'nawk', 'nc', 'nice', 'nl', 'nmap', 'node', 'nohup', 'od', 'openssl',
    'perl', 'pg', 'php', 'pico', 'python', 'python2', 'python3', 'readelf',
    'restic', 'rev', 'rlwrap', 'rsync', 'ruby', 'run-parts', 'rview',
    'rvim', 'scp', 'sed', 'setarch', 'shuf', 'socat', 'sort', 'sqlite3',
    'ssh', 'start-stop-daemon', 'stdbuf', 'strace', 'tail', 'tar', 'tclsh',
    'tee', 'tftp', 'time', 'timeout', 'ul', 'unexpand', 'uniq', 'unshare',
    'vi', 'vim', 'watch', 'wget', 'wish', 'xargs', 'xxd', 'zsh',
}

# Common paths to check for SUID binaries
SUID_SEARCH_DIRS = ['/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin',
                     '/bin', '/sbin', '/snap/bin']

# Cron directories to check for writable files
CRON_DIRS = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly',
             '/etc/cron.monthly', '/etc/cron.weekly', '/var/spool/cron',
             '/var/spool/cron/crontabs']

# Service config directories
SERVICE_DIRS = ['/etc/systemd/system', '/etc/init.d', '/lib/systemd/system',
                '/usr/lib/systemd/system']

# Sensitive files that should be restricted
SENSITIVE_FILES = {
    '/etc/shadow': '0640', '/etc/gshadow': '0640',
    '/etc/passwd': '0644', '/etc/group': '0644',
    '/etc/sudoers': '0440', '/etc/ssh/sshd_config': '0600',
    '/etc/crontab': '0644',
}


def check_suid_sgid(search_dirs=None):
    """Find SUID/SGID binaries and check against GTFOBins."""
    findings = []
    dirs = search_dirs or SUID_SEARCH_DIRS

    for search_dir in dirs:
        if not os.path.isdir(search_dir):
            continue
        for root, _, files in os.walk(search_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    fstat = os.stat(fpath)
                    mode = fstat.st_mode
                    is_suid = bool(mode & stat.S_ISUID)
                    is_sgid = bool(mode & stat.S_ISGID)

                    if is_suid or is_sgid:
                        binary_name = fname.lower()
                        exploitable = binary_name in GTFOBINS_SUID
                        flags = []
                        if is_suid:
                            flags.append('SUID')
                        if is_sgid:
                            flags.append('SGID')

                        severity = 'CRITICAL' if exploitable else 'MEDIUM'
                        findings.append({
                            'type': 'SUID_SGID_BINARY',
                            'severity': severity,
                            'path': fpath,
                            'flags': ', '.join(flags),
                            'exploitable': exploitable,
                            'permissions': oct(mode)[-4:],
                            'owner_uid': fstat.st_uid,
                        })
                except (PermissionError, OSError):
                    pass
    return findings


def check_writable_path_dirs():
    """Check for world-writable directories in $PATH."""
    findings = []
    path_env = os.environ.get('PATH', '')
    path_dirs = path_env.split(os.pathsep)

    for d in path_dirs:
        if not os.path.isdir(d):
            continue
        try:
            dstat = os.stat(d)
            if dstat.st_mode & stat.S_IWOTH:
                findings.append({
                    'type': 'WRITABLE_PATH_DIR',
                    'severity': 'CRITICAL',
                    'path': d,
                    'permissions': oct(dstat.st_mode)[-4:],
                    'note': 'World-writable PATH dir enables binary planting attacks',
                })
        except (PermissionError, OSError):
            pass
    return findings


def check_cron_security():
    """Check cron directories for writable scripts."""
    findings = []
    for cron_dir in CRON_DIRS:
        if not os.path.isdir(cron_dir):
            continue
        try:
            dstat = os.stat(cron_dir)
            if dstat.st_mode & stat.S_IWOTH:
                findings.append({
                    'type': 'WRITABLE_CRON_DIR',
                    'severity': 'CRITICAL',
                    'path': cron_dir,
                    'permissions': oct(dstat.st_mode)[-4:],
                })
        except (PermissionError, OSError):
            pass

        for root, _, files in os.walk(cron_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    fstat = os.stat(fpath)
                    if fstat.st_mode & stat.S_IWOTH:
                        findings.append({
                            'type': 'WRITABLE_CRON_SCRIPT',
                            'severity': 'CRITICAL',
                            'path': fpath,
                            'permissions': oct(fstat.st_mode)[-4:],
                        })
                except (PermissionError, OSError):
                    pass
    return findings


def check_service_configs():
    """Check service configuration files for insecure permissions."""
    findings = []
    for svc_dir in SERVICE_DIRS:
        if not os.path.isdir(svc_dir):
            continue
        for root, _, files in os.walk(svc_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    fstat = os.stat(fpath)
                    if fstat.st_mode & stat.S_IWOTH:
                        findings.append({
                            'type': 'WRITABLE_SERVICE_CONFIG',
                            'severity': 'CRITICAL',
                            'path': fpath,
                            'permissions': oct(fstat.st_mode)[-4:],
                        })
                    elif fstat.st_mode & stat.S_IWGRP:
                        findings.append({
                            'type': 'GROUP_WRITABLE_SERVICE_CONFIG',
                            'severity': 'HIGH',
                            'path': fpath,
                            'permissions': oct(fstat.st_mode)[-4:],
                        })
                except (PermissionError, OSError):
                    pass
    return findings


def check_sensitive_perms():
    """Check sensitive system files have correct permissions."""
    findings = []
    for fpath, expected in SENSITIVE_FILES.items():
        if not os.path.exists(fpath):
            continue
        try:
            fstat = os.stat(fpath)
            actual = oct(fstat.st_mode)[-4:]
            if actual != expected:
                findings.append({
                    'type': 'SENSITIVE_FILE_PERMS',
                    'severity': 'HIGH',
                    'path': fpath,
                    'expected': expected,
                    'actual': actual,
                })
        except (PermissionError, OSError):
            pass
    return findings


def check_tmp_security():
    """Check /tmp and similar directories for security issues."""
    findings = []
    tmp_dirs = ['/tmp', '/var/tmp', '/dev/shm']
    for tmp in tmp_dirs:
        if not os.path.isdir(tmp):
            continue
        try:
            tstat = os.stat(tmp)
            if not (tstat.st_mode & stat.S_ISVTX):
                findings.append({
                    'type': 'TMP_NO_STICKY_BIT',
                    'severity': 'HIGH',
                    'path': tmp,
                    'permissions': oct(tstat.st_mode)[-4:],
                })
        except (PermissionError, OSError):
            pass
    return findings


def check_sandbox(target_dir):
    """Run checks against a specific sandbox directory (cross-platform)."""
    findings = []
    if not os.path.isdir(target_dir):
        return findings

    for root, dirs, files in os.walk(target_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                fstat = os.stat(fpath)
                mode = fstat.st_mode

                if mode & stat.S_IWOTH:
                    findings.append({
                        'type': 'WORLD_WRITABLE_IN_SANDBOX',
                        'severity': 'HIGH',
                        'path': fpath,
                        'permissions': oct(mode)[-4:],
                    })

                if mode & stat.S_ISUID:
                    bname = fname.lower()
                    findings.append({
                        'type': 'SUID_IN_SANDBOX',
                        'severity': 'CRITICAL' if bname in GTFOBINS_SUID else 'MEDIUM',
                        'path': fpath,
                        'exploitable': bname in GTFOBINS_SUID,
                        'permissions': oct(mode)[-4:],
                    })
            except (PermissionError, OSError):
                pass

        for dname in dirs:
            dpath = os.path.join(root, dname)
            try:
                dstat = os.stat(dpath)
                if dstat.st_mode & stat.S_IWOTH and not (dstat.st_mode & stat.S_ISVTX):
                    findings.append({
                        'type': 'WRITABLE_DIR_NO_STICKY',
                        'severity': 'HIGH',
                        'path': dpath,
                        'permissions': oct(dstat.st_mode)[-4:],
                    })
            except (PermissionError, OSError):
                pass
    return findings


def generate_report(all_findings, output_file):
    """Generate the privilege escalation report."""
    lines = []
    lines.append('=' * 70)
    lines.append('  PRIVILEGE ESCALATION PATHWAY REPORT')
    lines.append('=' * 70)
    lines.append(f'  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    lines.append(f'  Platform:  {platform.system()} {platform.release()}')
    lines.append(f'  Findings:  {len(all_findings)}')

    from collections import defaultdict
    sev = defaultdict(int)
    for f in all_findings:
        sev[f['severity']] += 1
    lines.extend([f'  Critical:  {sev.get("CRITICAL",0)}', f'  High:      {sev.get("HIGH",0)}',
                  f'  Medium:    {sev.get("MEDIUM",0)}', '-' * 70])

    # Group by type
    by_type = defaultdict(list)
    for f in all_findings:
        by_type[f['type']].append(f)

    for ftype, findings in sorted(by_type.items()):
        lines.append(f'\n  [{findings[0]["severity"]}] {ftype} ({len(findings)} found)')
        lines.append('  ' + '-' * 48)
        for f in findings[:20]:
            extra = ''
            if f.get('exploitable'):
                extra = ' <- EXPLOITABLE (GTFOBins)'
            if f.get('expected'):
                extra = f' (expected {f["expected"]}, actual {f["actual"]})'
            if f.get('note'):
                extra = f' — {f["note"]}'
            lines.append(f'    {f.get("permissions", "----")}  {f["path"]}{extra}')
        if len(findings) > 20:
            lines.append(f'    ... and {len(findings) - 20} more')

    if not all_findings:
        lines.append('\n  No privilege escalation pathways detected.')
        lines.append('  (Note: some checks require Linux and root permissions)')

    lines.append('\n' + '=' * 70)

    report = '\n'.join(lines)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)
    print(report)
    print(f'\n  Report saved to: {output_file}\n')


def main():
    target_dir = sys.argv[1] if len(sys.argv) > 1 else None

    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    output = os.path.join(project_dir, 'results', 'privesc_report.txt')

    print(f"\n{'='*70}")
    print(f"  PRIVILEGE ESCALATION PATHWAY SCANNER")
    print(f"  Platform: {platform.system()} {platform.release()}")
    print(f"  Started:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")

    all_findings = []

    if platform.system() == 'Linux':
        print("  [*] Checking SUID/SGID binaries...")
        all_findings.extend(check_suid_sgid())
        print("  [*] Checking writable PATH directories...")
        all_findings.extend(check_writable_path_dirs())
        print("  [*] Checking cron security...")
        all_findings.extend(check_cron_security())
        print("  [*] Checking service configurations...")
        all_findings.extend(check_service_configs())
        print("  [*] Checking sensitive file permissions...")
        all_findings.extend(check_sensitive_perms())
        print("  [*] Checking /tmp security...")
        all_findings.extend(check_tmp_security())
    else:
        print("  [*] Running on non-Linux platform — system checks limited")
        print("  [*] Checking writable PATH directories...")
        all_findings.extend(check_writable_path_dirs())

    if target_dir and os.path.isdir(target_dir):
        print(f"  [*] Scanning sandbox: {target_dir}")
        all_findings.extend(check_sandbox(target_dir))

    generate_report(all_findings, output)


if __name__ == '__main__':
    main()
