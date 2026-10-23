#!/usr/bin/env python3
"""SSH Log Analyzer - a defensive tool that detects brute-force login attempts
in Linux auth logs (e.g. /var/log/auth.log).

Detections:
  1. Brute force: an IP with >= THRESHOLD failed logins inside a time window.
  2. Compromise indicator: a successful login from an IP that earlier failed
     repeatedly (possible successful brute force).
  3. Username enumeration: many distinct invalid usernames from one IP.

Usage:
  python3 Adith.O_SSHLogAnalyzer.py sample_auth.log
  python3 Adith.O_SSHLogAnalyzer.py /var/log/auth.log --threshold 5 --window 300 --json report.json
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime

# Matches syslog-style lines, e.g.
# Oct 22 03:14:07 server sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2
LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")
SUCCESS_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"
)


def parse_time(ts, year=None):
    """Syslog timestamps have no year, so assume the current one."""
    year = year or datetime.now().year
    return datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")


def parse_log(lines, year=None):
    """Yield (time, kind, user, ip) events from raw log lines."""
    for line in lines:
        m = LINE_RE.match(line.strip())
        if not m:
            continue
        try:
            t = parse_time(m.group("ts"), year)
        except ValueError:
            continue
        msg = m.group("msg")
        for kind, rx in (("failed", FAILED_RE), ("invalid", INVALID_RE), ("success", SUCCESS_RE)):
            hit = rx.search(msg)
            if hit:
                yield t, kind, hit.group("user"), hit.group("ip")
                break


def analyze(events, threshold=5, window=300, enum_threshold=3):
    failed = defaultdict(list)       # ip -> [times]
    users = defaultdict(set)         # ip -> usernames tried
    invalid_users = defaultdict(set)
    successes = []                   # (time, user, ip)

    for t, kind, user, ip in events:
        if kind == "failed":
            failed[ip].append(t)
            users[ip].add(user)
        elif kind == "invalid":
            invalid_users[ip].add(user)
        elif kind == "success":
            successes.append((t, user, ip))

    findings = {"brute_force": [], "possible_compromise": [], "user_enumeration": []}

    for ip, times in failed.items():
        times.sort()
        # Sliding window: find the densest burst of failures.
        best, lo = 0, 0
        for hi in range(len(times)):
            while (times[hi] - times[lo]).total_seconds() > window:
                lo += 1
            best = max(best, hi - lo + 1)
        if best >= threshold:
            findings["brute_force"].append({
                "ip": ip,
                "total_failures": len(times),
                "max_in_window": best,
                "usernames_tried": sorted(users[ip]),
                "first_seen": times[0].isoformat(),
                "last_seen": times[-1].isoformat(),
                "severity": "HIGH" if best >= threshold * 3 else "MEDIUM",
            })

    flagged_ips = {f["ip"]: f for f in findings["brute_force"]}
    for t, user, ip in successes:
        if ip in flagged_ips and t >= datetime.fromisoformat(flagged_ips[ip]["first_seen"]):
            findings["possible_compromise"].append({
                "ip": ip, "user": user, "time": t.isoformat(),
                "note": "Successful login after repeated failures - investigate immediately",
                "severity": "CRITICAL",
            })

    for ip, names in invalid_users.items():
        if len(names) >= enum_threshold:
            findings["user_enumeration"].append({
                "ip": ip, "invalid_usernames": sorted(names), "severity": "MEDIUM",
            })

    for key in findings:
        findings[key].sort(key=lambda f: f["ip"])
    return findings


RECOMMENDATIONS = [
    "Block flagged IPs (e.g. `ufw deny from <ip>`) or use fail2ban to automate it.",
    "Disable password login; require SSH keys (PasswordAuthentication no).",
    "Disable root login (PermitRootLogin no) and move/limit SSH exposure.",
    "Enable MFA and rotate credentials for any account in a possible-compromise finding.",
]


def render(findings):
    out = ["=" * 60, " SSH LOG ANALYSIS REPORT", "=" * 60]
    out.append(f"\n[1] Brute-force sources: {len(findings['brute_force'])}")
    for f in findings["brute_force"]:
        out.append(
            f"  [{f['severity']}] {f['ip']}: {f['total_failures']} failures "
            f"({f['max_in_window']} in one window), users: {', '.join(f['usernames_tried'])}"
        )
    out.append(f"\n[2] Possible compromises: {len(findings['possible_compromise'])}")
    for f in findings["possible_compromise"]:
        out.append(f"  [{f['severity']}] {f['ip']} logged in as '{f['user']}' at {f['time']}")
    out.append(f"\n[3] Username enumeration: {len(findings['user_enumeration'])}")
    for f in findings["user_enumeration"]:
        out.append(f"  [{f['severity']}] {f['ip']} tried invalid users: {', '.join(f['invalid_usernames'])}")
    out.append("\nRecommendations:")
    out += [f"  - {r}" for r in RECOMMENDATIONS]
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(description="Detect SSH brute-force attempts in auth logs.")
    p.add_argument("logfile")
    p.add_argument("--threshold", type=int, default=5, help="failures in window to flag (default 5)")
    p.add_argument("--window", type=int, default=300, help="window in seconds (default 300)")
    p.add_argument("--year", type=int, help="log year (syslog omits it; default current)")
    p.add_argument("--json", metavar="FILE", help="also write findings as JSON")
    a = p.parse_args(argv)

    try:
        with open(a.logfile, errors="replace") as fh:
            findings = analyze(parse_log(fh, a.year), a.threshold, a.window)
    except OSError as e:
        sys.exit(f"Error: {e}")

    print(render(findings))
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(findings, fh, indent=2)
        print(f"\nJSON report written to {a.json}")


if __name__ == "__main__":
    main()
