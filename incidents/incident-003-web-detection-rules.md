# Incident 003 – Regex-Based Web Detection Rules (NGINX access.log)

## Summary
As part of a SOC detection engineering exercise, I created and validated a set of **regex-based web detections** against **NGINX access logs** to identify suspicious behaviors commonly associated with **reconnaissance, enumeration, and automated scanning**. The detections were converted into **pseudo-SIEM alert outputs** and improved through **noise reduction** techniques (allowlisting and rate-based aggregation).

## Environment
- Host: Raspberry Pi 5
- OS: Kali Linux (ARM)
- Web server: NGINX
- Log source: `/var/log/nginx/access.log`
- Detection artifacts:
  - Ruleset: `rules/nginx_web_detections.regex`
  - Alert script: `detections/nginx_alerts.sh`
  - Evidence output: `outputs/nginx_alerts_<date_time>.txt`

## Detection Objective
Turn raw web access logs into repeatable detections that produce alert-style outputs with:
- Timestamp
- Source IP
- Method
- URI
- Status code
- Rule name and severity (HIGH / MEDIUM / INFO)

## Detection Rules Created

### Rule 1 — Sensitive Path Probing (HIGH)
**Intent:** Identify requests for common admin panels and sensitive files.
**Regex logic:**
- `/admin`, `/login`, `/wp-admin`, `/phpmyadmin`, `/.env`, `/.git`

**Why it’s high severity:**
- These URIs are rarely accessed by normal users
- Indicates targeted discovery of privileged entry points or secrets
- Low false-positive rate

**Example detection query:**
egrep -i '(/admin|/login|/wp-admin|/phpmyadmin|/\.env|/\.git)' /var/log/nginx/access.log

### Rule 2 — Scanner Tool User-Agent Detection (MEDIUM)

Intent:
Detect automated scanning activity based on identifiable user-agent strings used by common security tools.

Regex Logic:
- ffuf
- gobuster
- dirb
- dirbuster
- nikto
- wpscan
- sqlmap
- curl

Why This Rule Exists:
- Automated tools often self-identify in the User-Agent
- Indicates non-human traffic
- Severity increases when correlated with other rules

Example Detection Query:
egrep -i '(ffuf|gobuster|dirb|dirbuster|nikto|wpscan|sqlmap|curl)' /var/log/nginx/access.log

### Rule 3 — Injection Attempt Indicators (HIGH)

Intent:
Detect potential exploit attempts by identifying common SQL injection and command injection strings.

Regex Logic:
SQL Injection:
- union select
- or 1=1
- %27
- %22

Command Injection:
- ;whoami
- ;id
- ;uname
- %3b

Why This Rule Exists:
- Indicates exploit intent, even if unsuccessful
- High-signal indicators of malicious behavior
- A single hit may justify escalation

Example Detection Query:
egrep -i 'union\s+select|or\s+1=1|%27|%22|;whoami|;id|;uname|%3b' /var/log/nginx/access.log

### Rule 4 — Rate-Based Scanning / Enumeration (INFO → MEDIUM)

Intent:
Identify reconnaissance activity based on request volume and enumeration of multiple unique paths from a single source.

Detection Logic (Aggregation-Based):
- High number of requests in a short time window
- High number of unique URIs requested by the same IP

Why This Rule Exists:
- Enumeration tools generate many requests rapidly
- Helps distinguish scanning from normal browsing
- Severity depends on volume and correlation with other rules

Example Detection Queries:

Requests per source IP:
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head

Unique paths per source IP:
awk '{print $1, $7}' /var/log/nginx/access.log | sort | uniq | awk '{print $1}' | sort | uniq -c | sort -nr | head


## Alerts Fired (Pseudo-SIEM Output)

Detections were operationalized via `detections/nginx_alerts.sh`, generating the following alert categories:

### ALERT: Sensitive Path Probing (HIGH)
- Triggered by requests to sensitive or administrative paths (e.g., `/admin`, `/.env`, `/.git`)
- Evidence includes repeated probe attempts often resulting in `404 Not Found` responses

### ALERT: Scanner User-Agent Detected (MEDIUM)
- Triggered by user-agent strings consistent with automated scanning tools
- Evidence includes tool-based user agents combined with repetitive request patterns

### ALERT: Top Talkers (INFO)
- Provides context to identify source IPs generating high request volumes
- Used to support escalation when correlated with other detection rules

Evidence saved to:
- `outputs/nginx_alerts_<date_time>.txt`


## Noise Reduction / False Positive Control

Noise reduction techniques were applied to improve alert quality and reduce false positives.


### Allowlisting

Known benign IP addresses (e.g., lab host and analyst workstation) were excluded from alerting to prevent self-triggering and routine testing noise.

Example allowlisted IPs:
- `192.168.1.37`
- `192.168.1.88`

Implementation approach:
- Applied `egrep -v "$ALLOWLIST"` to alert streams


### Thresholding

Rate-based logic was applied to prevent alerts caused by:
- Single `404` errors
- Casual browsing mistakes
- Low-frequency benign testing activity

Escalation criteria examples:
- **MEDIUM severity:** High request volume within a short timeframe
- **HIGH severity:** High request volume combined with sensitive path probing and scanner user-agent detection


## Analyst Assessment

The detection set reliably identifies:
- Web reconnaissance and enumeration behavior
- Automated scanning attempts using identifiable tools
- High-signal probing of sensitive files and administrative panels

The addition of allowlisting and aggregation significantly reduced false positives and improved alert quality, reflecting real-world SOC detection tuning practices.


## Recommendations

- Implement NGINX rate limiting to reduce scan effectiveness
- Integrate `fail2ban` for repeated web probing and abusive clients
- Forward logs into a SIEM platform (next step: Filebeat → Wazuh / ELK)
- Correlate multiple rule hits (sensitive paths, tool user-agents, rate-based indicators) into higher-confidence alerts


## Appendix

- Ruleset: `rules/nginx_web_detections.regex`
- Alert Generator: `detections/nginx_alerts.sh`
- Output Evidence: `outputs/nginx_alerts_<date_time>.txt`
