#!/usr/bin/env python3
"""
02_integrity_monitor.py - Cryptographic File Integrity Monitoring Tool

Research Experiment E2: Evaluate the effectiveness and performance of
hash-based file integrity monitoring for detecting unauthorized modifications.

Modes:
  --init   Create a SHA-256 baseline of all files in the target directory
  --check  Compare current state against the baseline, report changes

The tool detects:
  - Modified files (content hash mismatch)
  - Added files (on disk but not in baseline)
  - Deleted files (in baseline but not on disk)
  - Metadata changes (size, permissions)

Output: Baseline JSON and check report in results/

Usage:
  python 02_integrity_monitor.py --init <target_directory>
  python 02_integrity_monitor.py --check <target_directory>

Author: File System Security Research Project
"""

import os
import sys
import json
import hashlib
import time
import stat
from datetime import datetime
from pathlib import Path


def compute_sha256(filepath, block_size=65536):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(block_size)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()
    except (PermissionError, OSError):
        return None


def get_file_metadata(filepath):
    """Collect file metadata for integrity record."""
    try:
        file_stat = os.stat(filepath)
        return {
            'size': file_stat.st_size,
            'mode': oct(file_stat.st_mode),
            'mtime': file_stat.st_mtime,
            'uid': file_stat.st_uid,
            'gid': file_stat.st_gid,
        }
    except (PermissionError, OSError):
        return None


def create_baseline(target_dir, baseline_file):
    """Create a SHA-256 baseline of all files in target directory."""
    baseline = {}
    file_count = 0
    total_bytes = 0
    errors = 0

    print(f"\n{'='*70}")
    print(f"  FILE INTEGRITY MONITOR — BASELINE CREATION")
    print(f"  Target: {os.path.abspath(target_dir)}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")

    start_time = time.time()

    for root, dirs, files in os.walk(target_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, target_dir)

            file_hash = compute_sha256(filepath)
            metadata = get_file_metadata(filepath)

            if file_hash and metadata:
                baseline[rel_path] = {
                    'sha256': file_hash,
                    'metadata': metadata,
                }
                file_count += 1
                total_bytes += metadata['size']
                sys.stdout.write(f"\r  Hashing: {file_count} files processed...")
                sys.stdout.flush()
            else:
                errors += 1

    elapsed = time.time() - start_time

    # Save baseline
    baseline_data = {
        'version': '1.0',
        'created': datetime.now().isoformat(),
        'target_directory': os.path.abspath(target_dir),
        'algorithm': 'SHA-256',
        'file_count': file_count,
        'total_bytes': total_bytes,
        'files': baseline,
    }

    os.makedirs(os.path.dirname(baseline_file), exist_ok=True)
    with open(baseline_file, 'w', encoding='utf-8') as f:
        json.dump(baseline_data, f, indent=2)

    print(f"\r  {'-'*50}")
    print(f"  BASELINE CREATED SUCCESSFULLY")
    print(f"  {'-'*50}")
    print(f"  Files hashed:      {file_count}")
    print(f"  Total data:        {total_bytes / 1024:.1f} KB")
    print(f"  Errors:            {errors}")
    print(f"  Time elapsed:      {elapsed:.3f}s")
    print(f"  Hash rate:         {file_count / max(elapsed, 0.001):.0f} files/sec")
    print(f"  Baseline saved:    {baseline_file}")
    print(f"  {'-'*50}\n")

    return file_count


def check_integrity(target_dir, baseline_file, report_file):
    """Check current file system state against baseline."""
    # Load baseline
    if not os.path.exists(baseline_file):
        print(f"  ERROR: No baseline found at {baseline_file}")
        print(f"  Run with --init first to create a baseline.")
        sys.exit(1)

    with open(baseline_file, 'r', encoding='utf-8') as f:
        baseline_data = json.load(f)

    baseline = baseline_data['files']

    print(f"\n{'='*70}")
    print(f"  FILE INTEGRITY MONITOR — INTEGRITY CHECK")
    print(f"  Target: {os.path.abspath(target_dir)}")
    print(f"  Baseline: {baseline_data['created']}")
    print(f"  Algorithm: {baseline_data['algorithm']}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")

    start_time = time.time()

    modified_files = []
    added_files = []
    deleted_files = []
    metadata_changes = []
    checked_paths = set()
    file_count = 0

    # Check all current files
    for root, dirs, files in os.walk(target_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, target_dir)
            checked_paths.add(rel_path)
            file_count += 1

            current_hash = compute_sha256(filepath)
            current_meta = get_file_metadata(filepath)

            if rel_path not in baseline:
                added_files.append({
                    'path': rel_path,
                    'sha256': current_hash,
                    'size': current_meta['size'] if current_meta else 'unknown',
                })
            else:
                baseline_entry = baseline[rel_path]

                # Check content hash
                if current_hash != baseline_entry['sha256']:
                    modified_files.append({
                        'path': rel_path,
                        'old_hash': baseline_entry['sha256'],
                        'new_hash': current_hash,
                        'old_size': baseline_entry['metadata']['size'],
                        'new_size': current_meta['size'] if current_meta else 'unknown',
                    })

                # Check metadata changes (even if content unchanged)
                elif current_meta:
                    changes = []
                    old_meta = baseline_entry['metadata']
                    if current_meta['size'] != old_meta['size']:
                        changes.append(f"size: {old_meta['size']} -> {current_meta['size']}")
                    if current_meta['mode'] != old_meta['mode']:
                        changes.append(f"mode: {old_meta['mode']} -> {current_meta['mode']}")
                    if current_meta['uid'] != old_meta['uid']:
                        changes.append(f"uid: {old_meta['uid']} -> {current_meta['uid']}")
                    if current_meta['gid'] != old_meta['gid']:
                        changes.append(f"gid: {old_meta['gid']} -> {current_meta['gid']}")

                    if changes:
                        metadata_changes.append({
                            'path': rel_path,
                            'changes': changes,
                        })

            sys.stdout.write(f"\r  Checking: {file_count} files verified...")
            sys.stdout.flush()

    # Check for deleted files
    for rel_path in baseline:
        if rel_path not in checked_paths:
            deleted_files.append({
                'path': rel_path,
                'old_hash': baseline[rel_path]['sha256'],
                'old_size': baseline[rel_path]['metadata']['size'],
            })

    elapsed = time.time() - start_time

    # Determine overall status
    is_clean = not (modified_files or added_files or deleted_files)
    status = 'CLEAN — No unauthorized changes detected' if is_clean else 'CHANGES DETECTED — Investigate immediately'

    # Generate report
    report_lines = []
    report_lines.append('=' * 70)
    report_lines.append('  FILE INTEGRITY CHECK REPORT')
    report_lines.append('=' * 70)
    report_lines.append(f'  Generated:     {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    report_lines.append(f'  Target:        {os.path.abspath(target_dir)}')
    report_lines.append(f'  Baseline from: {baseline_data["created"]}')
    report_lines.append(f'  Files checked: {file_count}')
    report_lines.append(f'  Time elapsed:  {elapsed:.3f}s')
    report_lines.append(f'  Status:        {status}')
    report_lines.append('-' * 70)

    if modified_files:
        report_lines.append(f'\n  MODIFIED FILES ({len(modified_files)}):')
        report_lines.append('  ' + '-' * 48)
        for mf in modified_files:
            report_lines.append(f'  [MODIFIED] {mf["path"]}')
            report_lines.append(f'             Old hash: {mf["old_hash"][:16]}...')
            report_lines.append(f'             New hash: {mf["new_hash"][:16]}...')
            report_lines.append(f'             Size: {mf["old_size"]} -> {mf["new_size"]}')

    if added_files:
        report_lines.append(f'\n  ADDED FILES ({len(added_files)}):')
        report_lines.append('  ' + '-' * 48)
        for af in added_files:
            report_lines.append(f'  [ADDED]    {af["path"]}')
            report_lines.append(f'             Hash: {af["sha256"][:16]}...')
            report_lines.append(f'             Size: {af["size"]}')

    if deleted_files:
        report_lines.append(f'\n  DELETED FILES ({len(deleted_files)}):')
        report_lines.append('  ' + '-' * 48)
        for df in deleted_files:
            report_lines.append(f'  [DELETED]  {df["path"]}')
            report_lines.append(f'             Was hash: {df["old_hash"][:16]}...')
            report_lines.append(f'             Was size: {df["old_size"]}')

    if metadata_changes:
        report_lines.append(f'\n  METADATA CHANGES ({len(metadata_changes)}):')
        report_lines.append('  ' + '-' * 48)
        for mc in metadata_changes:
            report_lines.append(f'  [META]     {mc["path"]}')
            for change in mc['changes']:
                report_lines.append(f'             {change}')

    if is_clean:
        report_lines.append('\n  [OK] All files match their baseline hashes.')
        report_lines.append('  [OK] No unauthorized modifications detected.')

    report_lines.append('\n' + '=' * 70)

    report_text = '\n'.join(report_lines)

    # Save report
    os.makedirs(os.path.dirname(report_file), exist_ok=True)
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report_text)

    # Print to console
    print(f"\r{report_text}")
    print(f"\n  Report saved to: {report_file}\n")

    return len(modified_files) + len(added_files) + len(deleted_files)


def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python 02_integrity_monitor.py --init <target_directory>")
        print("  python 02_integrity_monitor.py --check <target_directory>")
        print("\nExample:")
        print("  python 02_integrity_monitor.py --init ./test_sandbox")
        print("  python 02_integrity_monitor.py --check ./test_sandbox")
        sys.exit(1)

    mode = sys.argv[1]
    target = sys.argv[2]

    if not os.path.isdir(target):
        print(f"Error: '{target}' is not a valid directory.")
        sys.exit(1)

    # Determine output paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    results_dir = os.path.join(project_dir, 'results')
    baseline_file = os.path.join(results_dir, 'integrity_baseline.json')
    report_file = os.path.join(results_dir, 'integrity_check_report.txt')

    if mode == '--init':
        create_baseline(target, baseline_file)
    elif mode == '--check':
        changes = check_integrity(target, baseline_file, report_file)
        if changes > 0:
            sys.exit(1)
    else:
        print(f"Unknown mode: {mode}")
        print("Use --init or --check")
        sys.exit(1)


if __name__ == '__main__':
    main()
