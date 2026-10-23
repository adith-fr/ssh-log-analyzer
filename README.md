# SSH Log Analyzer

A defensive cybersecurity tool that reads Linux SSH authentication logs and detects brute-force attacks, username enumeration, and possible account compromise.

**Project for:** IBM SkillsBuild Cybersecurity Bootcamp 2026 (BharatCares)
**Author:** Adith.O

## Project Description

Internet-facing SSH servers are attacked constantly by bots guessing passwords. This tool automatically analyzes the server's auth log and answers three questions: who is attacking, did any attack succeed, and what should be done about it.

| Detection | Logic | Severity |
|---|---|---|
| Brute force | At least N failed logins from one IP inside a time window (sliding window) | MEDIUM / HIGH |
| Possible compromise | Successful login from an IP that was already flagged for brute force | CRITICAL |
| Username enumeration | One IP probes 3 or more invalid usernames | MEDIUM |

## Dataset

- **Included sample dataset:** [`sample_auth.log`](sample_auth.log) - a small fictional OpenSSH log using reserved documentation IP ranges (no real systems or people). It contains an attacker who gets in, a normal user with typos, and a slow scan.
- **Real data:** the tool also works on any real `/var/log/auth.log` from a Linux server.

> Repository link: https://github.com/adith-fr/ssh-log-analyzer

## Technologies Used

- Python 3.8+ (standard library only: `re`, `argparse`, `json`, `collections`, `datetime`, `unittest`)
- Git / GitHub

## Setup and Run Instructions

No installation needed beyond Python 3.8+ (see `requirements.txt`).

```bash
# 1. Get the project
git clone https://github.com/adith-fr/ssh-log-analyzer.git
cd ssh-log-analyzer

# 2. Run on the sample log
python3 Adith.O_SSHLogAnalyzer.py sample_auth.log --year 2026

# 3. Run on a real log with custom settings and JSON export
python3 Adith.O_SSHLogAnalyzer.py /var/log/auth.log --threshold 5 --window 300 --json report.json

# 4. Run the tests
python3 -m unittest -v
```

Options: `--threshold` (failures to flag, default 5), `--window` (seconds, default 300), `--year` (syslog has no year; default current year), `--json FILE`.

## Key Information

**How it works:** parse log lines with regex, group failures per IP, slide a time window over the timestamps to find the densest burst, then cross-check successful logins against flagged IPs.

**Sample output:**

```
[1] Brute-force sources: 1
  [HIGH] 203.0.113.5: 15 failures (15 in one window), users: admin, oracle, root, test
[2] Possible compromises: 1
  [CRITICAL] 203.0.113.5 logged in as 'root' at 2026-10-22T03:14:37
[3] Username enumeration: 1
  [MEDIUM] 203.0.113.5 tried invalid users: admin, oracle, test
```

**Recommended mitigations:** block attacker IPs / use fail2ban, use SSH keys (`PasswordAuthentication no`), disable root login (`PermitRootLogin no`), enable MFA.

**Limitations / future work:** slow "low and slow" attacks are missed (add a daily-total rule); only OpenSSH syslog format is supported; could add GeoIP, real-time monitoring and alerts.

## Files

| File | Description |
|---|---|
| `Adith.O_SSHLogAnalyzer.py` | Main program |
| `requirements.txt` | Dependencies (none beyond the standard library) |
| `sample_auth.log` | Sample dataset |
| `test_analyzer.py` | Unit tests (7, all passing) |
| `Adith.O_ProjectReport.docx` | Full project report |
