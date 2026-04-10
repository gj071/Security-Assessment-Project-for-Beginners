#!/usr/bin/env python3
"""
03_access_pattern_analyzer.py - File Access Pattern Anomaly Detection

Research Experiment E3: Analyze file access audit logs to identify anomalous
patterns indicating insider threats, malware, or unauthorized access.

Usage:
  python 03_access_pattern_analyzer.py <audit_log_file>

Author: File System Security Research Project
"""

import os, sys, re, math
from datetime import datetime
from collections import defaultdict

BUSINESS_HOURS_START = 9
BUSINESS_HOURS_END = 18
ZSCORE_THRESHOLD = 2.0
MIN_EVENTS = 5

SENSITIVE_PATHS = [
    r'/etc/shadow', r'/etc/sudoers', r'/root/\.ssh', r'\.ssh/id_',
    r'\.ssh/authorized_keys', r'/var/lib/secrets', r'credential',
    r'password', r'secret', r'token', r'\.key$', r'\.pem$',
    r'salaries', r'ssn', r'bank_account',
]

RECON_PATHS = [
    '/etc/passwd', '/etc/group', '/etc/hosts', '/etc/resolv.conf',
    '/etc/crontab', '/etc/sudoers', '/proc/version', '/etc/os-release',
]


class AuditEvent:
    def __init__(self, timestamp, user, action, path, result, details):
        self.timestamp = timestamp
        self.user = user
        self.action = action
        self.path = path
        self.result = result
        self.details = details

    def is_after_hours(self):
        return self.timestamp.hour < BUSINESS_HOURS_START or self.timestamp.hour >= BUSINESS_HOURS_END

    def is_sensitive(self):
        return any(re.search(p, self.path, re.IGNORECASE) for p in SENSITIVE_PATHS)

    def is_recon(self):
        return self.path in RECON_PATHS


def parse_log(filepath):
    events = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split('|')
            if len(parts) < 6:
                continue
            try:
                ts = datetime.strptime(parts[0].strip(), '%Y-%m-%d %H:%M:%S')
                events.append(AuditEvent(ts, parts[1].strip(), parts[2].strip(),
                                         parts[3].strip(), parts[4].strip(), parts[5].strip()))
            except (ValueError, IndexError):
                pass
    return events


def analyze_temporal(events):
    after_hours = [e for e in events if e.is_after_hours()]
    by_user = defaultdict(list)
    for e in after_hours:
        by_user[e.user].append(e)
    findings = []
    for user, ue in by_user.items():
        sev = 'CRITICAL' if any(e.is_sensitive() for e in ue) else 'MEDIUM'
        findings.append({'type': 'AFTER_HOURS_ACCESS', 'severity': sev, 'user': user,
                         'count': len(ue), 'sensitive': sum(1 for e in ue if e.is_sensitive()),
                         'events': ue})
    return findings


def analyze_frequency(events):
    user_hourly = defaultdict(lambda: defaultdict(int))
    for e in events:
        user_hourly[e.user][e.timestamp.strftime('%Y-%m-%d %H')] += 1
    findings = []
    for user, hours in user_hourly.items():
        counts = list(hours.values())
        if len(counts) < MIN_EVENTS:
            continue
        mean = sum(counts) / len(counts)
        var = sum((x - mean) ** 2 for x in counts) / (len(counts) - 1) if len(counts) > 1 else 0
        sd = math.sqrt(var) if var > 0 else 0
        if sd == 0:
            continue
        for hk, c in hours.items():
            z = (c - mean) / sd
            if z > ZSCORE_THRESHOLD:
                findings.append({'type': 'ABNORMAL_FREQUENCY', 'severity': 'HIGH' if z > 3 else 'MEDIUM',
                                 'user': user, 'hour': hk, 'count': c, 'z_score': round(z, 2)})
    return findings


def analyze_sensitive(events):
    sensitive = [e for e in events if e.is_sensitive()]
    by_user = defaultdict(list)
    for e in sensitive:
        by_user[e.user].append(e)
    findings = []
    for user, ue in by_user.items():
        denied = [e for e in ue if e.result == 'DENIED']
        if denied:
            findings.append({'type': 'SENSITIVE_ACCESS_DENIED', 'severity': 'CRITICAL' if len(denied) >= 3 else 'HIGH',
                             'user': user, 'denied': len(denied), 'paths': list(set(e.path for e in denied))})
    return findings


def analyze_recon(events):
    by_user = defaultdict(list)
    for e in events:
        if e.is_recon():
            by_user[e.user].append(e)
    findings = []
    for user, ue in by_user.items():
        ue.sort(key=lambda x: x.timestamp)
        for i in range(len(ue)):
            window = [ue[i]]
            for j in range(i + 1, len(ue)):
                if (ue[j].timestamp - ue[i].timestamp).total_seconds() <= 300:
                    window.append(ue[j])
            paths = set(e.path for e in window)
            if len(paths) >= 4:
                findings.append({'type': 'RECON_PATTERN', 'severity': 'CRITICAL', 'user': user,
                                 'paths': sorted(paths), 'window': f"{window[0].timestamp} - {window[-1].timestamp}"})
                break
    return findings


def analyze_suspicious_writes(events):
    findings = []
    for e in events:
        if e.action in ('WRITE', 'CHMOD') and '/tmp/' in e.path and '/.' in e.path:
            findings.append({'type': 'SUSPICIOUS_TEMP_FILE', 'severity': 'HIGH', 'user': e.user,
                             'path': e.path, 'time': str(e.timestamp)})
        if e.action == 'EXEC' and '/tmp/' in e.path:
            findings.append({'type': 'EXEC_FROM_TEMP', 'severity': 'CRITICAL', 'user': e.user,
                             'path': e.path, 'time': str(e.timestamp)})
    return findings


def generate_report(events, findings, output_file):
    lines = ['=' * 70, '  FILE ACCESS PATTERN ANOMALY REPORT', '=' * 70,
             f'  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
             f'  Events analyzed: {len(events)}', f'  Findings: {len(findings)}']

    sev = defaultdict(int)
    for f in findings:
        sev[f['severity']] += 1
    lines.extend([f'  Critical: {sev.get("CRITICAL",0)}', f'  High: {sev.get("HIGH",0)}',
                  f'  Medium: {sev.get("MEDIUM",0)}', '-' * 70])

    # User stats
    users = set(e.user for e in events)
    lines.extend(['\n  EVENT STATISTICS', '  ' + '-' * 48,
                  f'  Unique users: {len(users)} ({", ".join(sorted(users))})'])
    actions = defaultdict(int)
    for e in events:
        actions[e.action] += 1
    for a, c in sorted(actions.items()):
        lines.append(f'  {a:20s} {c} events')

    # Findings detail
    sorted_f = sorted(findings, key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}.get(x['severity'], 3))
    if sorted_f:
        lines.extend(['\n' + '=' * 70, '  DETAILED FINDINGS', '=' * 70])
        for i, f in enumerate(sorted_f, 1):
            lines.append(f'\n  Finding #{i}: [{f["severity"]}] {f["type"]}')
            lines.append(f'  User: {f.get("user", "N/A")}')
            if f['type'] == 'AFTER_HOURS_ACCESS':
                lines.append(f'  Events: {f["count"]} | Sensitive: {f["sensitive"]}')
                for e in f['events'][:5]:
                    lines.append(f'    [{e.result}] {e.action} {e.path} @ {e.timestamp}')
            elif f['type'] == 'ABNORMAL_FREQUENCY':
                lines.append(f'  Hour: {f["hour"]} | Count: {f["count"]} | Z-score: {f["z_score"]}')
            elif f['type'] == 'SENSITIVE_ACCESS_DENIED':
                lines.append(f'  Denied attempts: {f["denied"]}')
                for p in f['paths']:
                    lines.append(f'    -> {p}')
            elif f['type'] == 'RECON_PATTERN':
                lines.append(f'  Window: {f["window"]}')
                for p in f['paths']:
                    lines.append(f'    -> {p}')
            elif f['type'] in ('SUSPICIOUS_TEMP_FILE', 'EXEC_FROM_TEMP'):
                lines.append(f'  Path: {f["path"]} @ {f["time"]}')
    else:
        lines.append('\n  No anomalies detected.')

    # Recommendations
    if sorted_f:
        types = set(f['type'] for f in sorted_f)
        lines.extend(['\n' + '=' * 70, '  RECOMMENDATIONS', '=' * 70])
        if 'AFTER_HOURS_ACCESS' in types:
            lines.append('  * Investigate after-hours access with the user')
        if 'RECON_PATTERN' in types:
            lines.append('  * System recon detected — check for compromised accounts')
        if 'EXEC_FROM_TEMP' in types:
            lines.append('  * Mount /tmp with noexec; investigate executed binary')
        if 'SENSITIVE_ACCESS_DENIED' in types:
            lines.append('  * Multiple denied accesses — review privilege assignments')
        if 'SUSPICIOUS_TEMP_FILE' in types:
            lines.append('  * Inspect hidden files in /tmp')
    lines.append('\n' + '=' * 70)

    report = '\n'.join(lines)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as out:
        out.write(report)
    print(report)
    print(f'\n  Report saved to: {output_file}\n')
    return len(findings)


def main():
    if len(sys.argv) < 2:
        print("Usage: python 03_access_pattern_analyzer.py <audit_log_file>")
        sys.exit(1)
    log_file = sys.argv[1]
    if not os.path.isfile(log_file):
        print(f"Error: '{log_file}' not found.")
        sys.exit(1)

    events = parse_log(log_file)
    if not events:
        print("No valid events found.")
        sys.exit(1)

    print(f"\n  Parsed {len(events)} events. Running anomaly detection...\n")

    findings = []
    findings.extend(analyze_temporal(events))
    findings.extend(analyze_frequency(events))
    findings.extend(analyze_sensitive(events))
    findings.extend(analyze_recon(events))
    findings.extend(analyze_suspicious_writes(events))

    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    output = os.path.join(project_dir, 'results', 'access_anomaly_report.txt')
    generate_report(events, findings, output)


if __name__ == '__main__':
    main()
