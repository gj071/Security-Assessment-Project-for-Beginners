#!/usr/bin/env python3
"""
01_permission_audit.py - File System Permission Auditing Tool

Research Experiment E1: Systematically scan a directory tree to identify
permission misconfigurations that could lead to security vulnerabilities.

This script detects:
  - World-writable files and directories
  - SUID and SGID binaries (Linux)
  - Overly permissive sensitive files (keys, configs, credentials)
  - Files with unusual permission patterns

Output: CSV report saved to results/permission_audit_report.csv

Usage:
  python 01_permission_audit.py <target_directory>

Author: File System Security Research Project
"""

import os
import sys
import csv
import stat
import time
from datetime import datetime
from pathlib import Path

# Patterns indicating sensitive files that should NOT be world-readable
SENSITIVE_PATTERNS = [
    '*.key', '*.pem', '*.p12', '*.pfx', '*.jks',       # Cryptographic keys
    '*shadow*', '*passwd*',                                # Authentication files
    '*.conf', '*.cfg', '*.ini', '*.yml', '*.yaml',       # Configuration files
    '*credential*', '*secret*', '*token*', '*password*',  # Credential files
    '*id_rsa*', '*id_ed25519*', '*id_ecdsa*',             # SSH keys
    '*.env',                                               # Environment files
]

# Known SUID binaries that can be exploited for privilege escalation
# Reference: GTFOBins (https://gtfobins.github.io/)
KNOWN_EXPLOITABLE_SUID = [
    'find', 'vim', 'vi', 'nano', 'python', 'python3', 'perl', 'ruby',
    'bash', 'dash', 'zsh', 'ksh', 'csh', 'sh',
    'nmap', 'less', 'more', 'man', 'awk', 'gawk',
    'tar', 'zip', 'unzip', 'rsync', 'scp',
    'env', 'strace', 'ltrace', 'gdb', 'node',
    'php', 'lua', 'tclsh', 'wish',
    'cp', 'mv', 'chmod', 'chown', 'dd',
    'wget', 'curl', 'nc', 'ncat', 'socat',
    'docker', 'lxc',
]


def matches_sensitive_pattern(filename):
    """Check if a filename matches any sensitive file pattern."""
    import fnmatch
    name_lower = filename.lower()
    for pattern in SENSITIVE_PATTERNS:
        if fnmatch.fnmatch(name_lower, pattern):
            return True
    return False


def get_permission_string(mode):
    """Convert numeric mode to rwx permission string."""
    perms = ''
    for who in ('USR', 'GRP', 'OTH'):
        for what in ('R', 'W', 'X'):
            flag = getattr(stat, f'S_I{what}{who}')
            perms += what.lower() if mode & flag else '-'
    return perms


def analyze_permissions(filepath, file_stat):
    """Analyze file permissions and return list of identified issues."""
    issues = []
    mode = file_stat.st_mode
    is_dir = stat.S_ISDIR(mode)
    filename = os.path.basename(filepath)

    # Check world-writable
    if mode & stat.S_IWOTH:
        if is_dir:
            # World-writable directory without sticky bit is especially dangerous
            if not (mode & stat.S_ISVTX):
                issues.append('WORLD_WRITABLE_DIR_NO_STICKY_BIT [CRITICAL]')
            else:
                issues.append('WORLD_WRITABLE_DIR (sticky bit set)')
        else:
            issues.append('WORLD_WRITABLE_FILE [HIGH]')

    # Check world-readable (concerning for sensitive files)
    if mode & stat.S_IROTH:
        if matches_sensitive_pattern(filename):
            issues.append('SENSITIVE_FILE_WORLD_READABLE [HIGH]')

    # Check world-executable
    if mode & stat.S_IXOTH and not is_dir:
        issues.append('WORLD_EXECUTABLE')

    # Check SUID (Linux)
    if mode & stat.S_ISUID:
        binary_name = filename.lower()
        if binary_name in KNOWN_EXPLOITABLE_SUID:
            issues.append(f'SUID_EXPLOITABLE_BINARY [CRITICAL] (known: {binary_name})')
        else:
            issues.append('SUID_SET [MEDIUM]')

    # Check SGID
    if mode & stat.S_ISGID:
        if is_dir:
            issues.append('SGID_DIRECTORY')
        else:
            issues.append('SGID_SET [MEDIUM]')

    # Check group-writable sensitive files
    if mode & stat.S_IWGRP and matches_sensitive_pattern(filename):
        issues.append('SENSITIVE_FILE_GROUP_WRITABLE [MEDIUM]')

    # Check for overly permissive (777, 776, 666, etc.)
    perm_octal = oct(mode)[-3:]
    if perm_octal in ('777', '776', '766', '667', '666'):
        issues.append(f'OVERLY_PERMISSIVE ({perm_octal}) [HIGH]')

    return issues


def get_owner_info(file_stat):
    """Get owner and group information."""
    try:
        import pwd
        import grp
        owner = pwd.getpwuid(file_stat.st_uid).pw_name
        group = grp.getgrgid(file_stat.st_gid).gr_name
    except (ImportError, KeyError):
        # Windows or unknown UID/GID
        owner = str(file_stat.st_uid)
        group = str(file_stat.st_gid)
    return owner, group


def scan_directory(target_dir, output_file):
    """Scan a directory recursively and generate a permission audit report."""
    results = []
    stats = {
        'total_files': 0,
        'total_dirs': 0,
        'issues_found': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
    }

    print(f"\n{'='*70}")
    print(f"  FILE SYSTEM PERMISSION AUDIT")
    print(f"  Target: {os.path.abspath(target_dir)}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")

    start_time = time.time()

    for root, dirs, files in os.walk(target_dir):
        # Analyze directories
        for d in dirs:
            dirpath = os.path.join(root, d)
            try:
                dir_stat = os.stat(dirpath)
                stats['total_dirs'] += 1
                issues = analyze_permissions(dirpath, dir_stat)
                owner, group = get_owner_info(dir_stat)
                perm_str = get_permission_string(dir_stat.st_mode)
                perm_octal = oct(dir_stat.st_mode)[-3:]

                if issues:
                    stats['issues_found'] += len(issues)
                    for issue in issues:
                        if 'CRITICAL' in issue:
                            stats['critical'] += 1
                        elif 'HIGH' in issue:
                            stats['high'] += 1
                        elif 'MEDIUM' in issue:
                            stats['medium'] += 1

                results.append({
                    'path': dirpath,
                    'type': 'directory',
                    'permissions_octal': perm_octal,
                    'permissions_rwx': f'd{perm_str}',
                    'owner': owner,
                    'group': group,
                    'size': '-',
                    'issues': '; '.join(issues) if issues else 'NONE',
                })
            except (PermissionError, OSError) as e:
                results.append({
                    'path': dirpath,
                    'type': 'directory',
                    'permissions_octal': 'N/A',
                    'permissions_rwx': 'N/A',
                    'owner': 'N/A',
                    'group': 'N/A',
                    'size': '-',
                    'issues': f'ACCESS_DENIED: {e}',
                })

        # Analyze files
        for f in files:
            filepath = os.path.join(root, f)
            try:
                file_stat = os.stat(filepath)
                stats['total_files'] += 1
                issues = analyze_permissions(filepath, file_stat)
                owner, group = get_owner_info(file_stat)
                perm_str = get_permission_string(file_stat.st_mode)
                perm_octal = oct(file_stat.st_mode)[-3:]

                if issues:
                    stats['issues_found'] += len(issues)
                    for issue in issues:
                        if 'CRITICAL' in issue:
                            stats['critical'] += 1
                        elif 'HIGH' in issue:
                            stats['high'] += 1
                        elif 'MEDIUM' in issue:
                            stats['medium'] += 1

                results.append({
                    'path': filepath,
                    'type': 'file',
                    'permissions_octal': perm_octal,
                    'permissions_rwx': f'-{perm_str}',
                    'owner': owner,
                    'group': group,
                    'size': file_stat.st_size,
                    'issues': '; '.join(issues) if issues else 'NONE',
                })
            except (PermissionError, OSError) as e:
                results.append({
                    'path': filepath,
                    'type': 'file',
                    'permissions_octal': 'N/A',
                    'permissions_rwx': 'N/A',
                    'owner': 'N/A',
                    'group': 'N/A',
                    'size': 'N/A',
                    'issues': f'ACCESS_DENIED: {e}',
                })

    elapsed = time.time() - start_time

    # Write CSV report
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['path', 'type', 'permissions_octal', 'permissions_rwx',
                      'owner', 'group', 'size', 'issues']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    # Print summary
    items_with_issues = [r for r in results if r['issues'] != 'NONE']
    print(f"  SCAN COMPLETE")
    print(f"  {'-'*50}")
    print(f"  Files scanned:    {stats['total_files']}")
    print(f"  Directories:      {stats['total_dirs']}")
    print(f"  Time elapsed:     {elapsed:.2f}s")
    print(f"  {'-'*50}")
    print(f"  FINDINGS SUMMARY")
    print(f"  {'-'*50}")
    print(f"  Total issues:     {stats['issues_found']}")
    print(f"  Critical:         {stats['critical']}")
    print(f"  High:             {stats['high']}")
    print(f"  Medium:           {stats['medium']}")
    print(f"  Items w/ issues:  {len(items_with_issues)}")
    print(f"  {'-'*50}")
    print(f"  Report saved to:  {output_file}")
    print()

    # Print detailed findings
    if items_with_issues:
        print(f"  DETAILED FINDINGS")
        print(f"  {'-'*50}")
        for item in items_with_issues:
            severity_marker = ''
            if 'CRITICAL' in item['issues']:
                severity_marker = '[!!]'
            elif 'HIGH' in item['issues']:
                severity_marker = '[! ]'
            else:
                severity_marker = '[~ ]'
            print(f"  {severity_marker} {item['permissions_rwx']}  {item['path']}")
            print(f"       Issues: {item['issues']}")
        print()

    return stats


def main():
    if len(sys.argv) < 2:
        print("Usage: python 01_permission_audit.py <target_directory>")
        print("\nExample: python 01_permission_audit.py ./test_sandbox")
        sys.exit(1)

    target = sys.argv[1]
    if not os.path.isdir(target):
        print(f"Error: '{target}' is not a valid directory.")
        sys.exit(1)

    # Determine output path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    output_file = os.path.join(project_dir, 'results', 'permission_audit_report.csv')

    stats = scan_directory(target, output_file)

    # Exit with non-zero if critical issues found (useful for CI/CD)
    if stats['critical'] > 0:
        sys.exit(2)


if __name__ == '__main__':
    main()
