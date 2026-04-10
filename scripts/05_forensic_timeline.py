#!/usr/bin/env python3
"""
05_forensic_timeline.py - Forensic Timeline Reconstruction from File Metadata

Research Experiment E5: Build a chronologically sorted forensic timeline
from file system metadata to support incident response investigations.

For each file, generates MACB timeline entries:
  M = Modified (content changed)
  A = Accessed (file read)
  C = Changed (metadata changed / created on Windows)
  B = Born (creation time, where available)

Output: CSV timeline in results/forensic_timeline.csv

Usage:
  python 05_forensic_timeline.py <target_directory>

Author: File System Security Research Project
"""

import os
import sys
import csv
import stat
import platform
import time
from datetime import datetime
from pathlib import Path


def get_file_type(mode):
    """Determine file type from stat mode."""
    if stat.S_ISREG(mode):
        return 'file'
    elif stat.S_ISDIR(mode):
        return 'directory'
    elif stat.S_ISLNK(mode):
        return 'symlink'
    elif stat.S_ISFIFO(mode):
        return 'pipe'
    elif stat.S_ISSOCK(mode):
        return 'socket'
    elif stat.S_ISBLK(mode):
        return 'block_device'
    elif stat.S_ISCHR(mode):
        return 'char_device'
    return 'unknown'


def get_owner_info(file_stat):
    """Get owner information (cross-platform)."""
    try:
        import pwd
        import grp
        owner = pwd.getpwuid(file_stat.st_uid).pw_name
        group = grp.getgrgid(file_stat.st_gid).gr_name
    except (ImportError, KeyError):
        owner = str(file_stat.st_uid)
        group = str(file_stat.st_gid)
    return owner, group


def format_timestamp(ts):
    """Format a unix timestamp to ISO 8601."""
    try:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
    except (OSError, ValueError, OverflowError):
        return 'N/A'


def collect_timeline_entries(target_dir):
    """Walk directory tree and collect MACB timeline entries."""
    entries = []
    file_count = 0
    errors = 0

    for root, dirs, files in os.walk(target_dir):
        all_items = [(d, os.path.join(root, d)) for d in dirs] + \
                    [(f, os.path.join(root, f)) for f in files]

        for name, fpath in all_items:
            try:
                fstat = os.stat(fpath)
                file_count += 1

                rel_path = os.path.relpath(fpath, target_dir)
                ftype = get_file_type(fstat.st_mode)
                perms = oct(fstat.st_mode)[-4:]
                owner, group = get_owner_info(fstat)
                size = fstat.st_size if stat.S_ISREG(fstat.st_mode) else 0

                # M - Modified time (content last changed)
                entries.append({
                    'timestamp': fstat.st_mtime,
                    'timestamp_str': format_timestamp(fstat.st_mtime),
                    'event_type': 'M (Modified)',
                    'path': rel_path,
                    'file_type': ftype,
                    'size': size,
                    'permissions': perms,
                    'owner': owner,
                    'group': group,
                    'details': 'File content last modified',
                })

                # A - Accessed time
                entries.append({
                    'timestamp': fstat.st_atime,
                    'timestamp_str': format_timestamp(fstat.st_atime),
                    'event_type': 'A (Accessed)',
                    'path': rel_path,
                    'file_type': ftype,
                    'size': size,
                    'permissions': perms,
                    'owner': owner,
                    'group': group,
                    'details': 'File last accessed/read',
                })

                # C - Changed (metadata on Linux, created on Windows)
                entries.append({
                    'timestamp': fstat.st_ctime,
                    'timestamp_str': format_timestamp(fstat.st_ctime),
                    'event_type': 'C (Changed/Created)',
                    'path': rel_path,
                    'file_type': ftype,
                    'size': size,
                    'permissions': perms,
                    'owner': owner,
                    'group': group,
                    'details': 'Metadata changed (Linux) or file created (Windows)',
                })

                # B - Born (creation time, Python 3.12+ on some platforms)
                if hasattr(fstat, 'st_birthtime'):
                    entries.append({
                        'timestamp': fstat.st_birthtime,
                        'timestamp_str': format_timestamp(fstat.st_birthtime),
                        'event_type': 'B (Born)',
                        'path': rel_path,
                        'file_type': ftype,
                        'size': size,
                        'permissions': perms,
                        'owner': owner,
                        'group': group,
                        'details': 'File creation time',
                    })

            except (PermissionError, OSError) as e:
                errors += 1

            sys.stdout.write(f'\r  Processing: {file_count} items...')
            sys.stdout.flush()

    return entries, file_count, errors


def analyze_timeline(entries):
    """Perform basic analysis on the timeline."""
    analysis = {}

    if not entries:
        return analysis

    timestamps = [e['timestamp'] for e in entries if e['timestamp_str'] != 'N/A']
    if timestamps:
        analysis['earliest'] = format_timestamp(min(timestamps))
        analysis['latest'] = format_timestamp(max(timestamps))
        analysis['span_seconds'] = max(timestamps) - min(timestamps)
        analysis['span_human'] = _format_duration(analysis['span_seconds'])

    # Find files with suspicious timestamp patterns
    by_path = {}
    for e in entries:
        if e['path'] not in by_path:
            by_path[e['path']] = {}
        by_path[e['path']][e['event_type']] = e['timestamp']

    suspicious = []
    for path, times in by_path.items():
        m_time = times.get('M (Modified)')
        c_time = times.get('C (Changed/Created)')
        a_time = times.get('A (Accessed)')

        # Modified before created (possible timestamp manipulation)
        if m_time and c_time and m_time < c_time - 1:
            suspicious.append({
                'path': path,
                'reason': 'Modified timestamp is before creation timestamp (possible manipulation)',
                'modified': format_timestamp(m_time),
                'created': format_timestamp(c_time),
            })

        # Accessed much before modified (unusual)
        if a_time and m_time and a_time < m_time - 86400:
            suspicious.append({
                'path': path,
                'reason': 'Access time is more than 24h before modification (noatime or manipulation)',
                'accessed': format_timestamp(a_time),
                'modified': format_timestamp(m_time),
            })

    analysis['suspicious_timestamps'] = suspicious
    return analysis


def _format_duration(seconds):
    """Format seconds into human readable duration."""
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    else:
        return f"{seconds/86400:.1f} days"


def generate_output(entries, analysis, file_count, errors, target_dir, csv_file, report_file):
    """Generate CSV timeline and text summary report."""
    # Sort chronologically
    entries.sort(key=lambda e: e['timestamp'])

    # Write CSV
    os.makedirs(os.path.dirname(csv_file), exist_ok=True)
    fieldnames = ['timestamp_str', 'event_type', 'path', 'file_type',
                  'size', 'permissions', 'owner', 'group', 'details']
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            row = {k: entry[k] for k in fieldnames}
            writer.writerow(row)

    # Generate text report
    lines = []
    lines.append('=' * 70)
    lines.append('  FORENSIC TIMELINE RECONSTRUCTION REPORT')
    lines.append('=' * 70)
    lines.append(f'  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    lines.append(f'  Platform:  {platform.system()} {platform.release()}')
    lines.append(f'  Target:    {os.path.abspath(target_dir)}')
    lines.append(f'  Items:     {file_count}')
    lines.append(f'  Events:    {len(entries)}')
    lines.append(f'  Errors:    {errors}')
    lines.append('-' * 70)

    if analysis.get('earliest'):
        lines.append(f'  Earliest event: {analysis["earliest"]}')
        lines.append(f'  Latest event:   {analysis["latest"]}')
        lines.append(f'  Time span:      {analysis["span_human"]}')

    # Show first and last 10 events
    lines.append('\n  EARLIEST 10 EVENTS')
    lines.append('  ' + '-' * 48)
    for e in entries[:10]:
        lines.append(f'  {e["timestamp_str"]}  {e["event_type"]:22s}  {e["path"]}')

    lines.append('\n  LATEST 10 EVENTS')
    lines.append('  ' + '-' * 48)
    for e in entries[-10:]:
        lines.append(f'  {e["timestamp_str"]}  {e["event_type"]:22s}  {e["path"]}')

    # Suspicious timestamps
    suspicious = analysis.get('suspicious_timestamps', [])
    if suspicious:
        lines.append(f'\n  SUSPICIOUS TIMESTAMPS ({len(suspicious)} found)')
        lines.append('  ' + '-' * 48)
        for s in suspicious[:10]:
            lines.append(f'  [!] {s["path"]}')
            lines.append(f'      Reason: {s["reason"]}')

    # Forensic notes
    lines.append('\n  FORENSIC ANALYSIS NOTES')
    lines.append('  ' + '-' * 48)
    if platform.system() == 'Linux':
        lines.append('  * st_ctime = metadata change time (NOT creation time on Linux)')
        lines.append('  * If noatime mount option is used, access times may be stale')
        lines.append('  * ext4 timestamps have nanosecond precision')
    else:
        lines.append('  * st_ctime = creation time on Windows (NTFS)')
        lines.append('  * NTFS stores timestamps in UTC internally')
        lines.append('  * FAT32 has only 2-second timestamp granularity')
    lines.append('  * Timestamps can be spoofed — corroborate with other evidence')
    lines.append('  * Full CSV timeline written for detailed analysis')

    lines.append(f'\n  CSV timeline: {csv_file}')
    lines.append('=' * 70)

    report = '\n'.join(lines)
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f'\r{report}')
    print(f'\n  Reports saved to:\n    CSV:  {csv_file}\n    Text: {report_file}\n')


def main():
    if len(sys.argv) < 2:
        print("Usage: python 05_forensic_timeline.py <target_directory>")
        print("\nExample: python 05_forensic_timeline.py ./test_sandbox")
        sys.exit(1)

    target = sys.argv[1]
    if not os.path.isdir(target):
        print(f"Error: '{target}' is not a valid directory.")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    csv_file = os.path.join(project_dir, 'results', 'forensic_timeline.csv')
    report_file = os.path.join(project_dir, 'results', 'forensic_timeline_report.txt')

    print(f"\n{'='*70}")
    print(f"  FORENSIC TIMELINE RECONSTRUCTION")
    print(f"  Target: {os.path.abspath(target)}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")

    entries, file_count, errors = collect_timeline_entries(target)
    analysis = analyze_timeline(entries)
    generate_output(entries, analysis, file_count, errors, target, csv_file, report_file)


if __name__ == '__main__':
    main()
