# Incident 006 – SSH Honeypot Interaction and Threat Intelligence Analysis (Cowrie)

## Summary
An SSH honeypot (Cowrie) was deployed on a Raspberry Pi 5 running Kali Linux (ARM64) to observe unauthorized access attempts. During monitoring, an attacker successfully authenticated using weak credentials and executed post-login reconnaissance commands. The interaction was fully captured via Cowrie logs and analyzed to extract indicators of compromise (IOCs), reconstruct the timeline, and assess attacker intent.

---

## Environment
- **Host:** Raspberry Pi 5  
- **Operating System:** Kali Linux (ARM64 / aarch64)  
- **Honeypot:** Cowrie SSH Honeypot  
- **Installation Method:** Python virtual environment (pip, non-root)  
- **Listening Port:** 2222  
- **Log Source:** `/home/kali/cowrie/var/log/cowrie/cowrie.json`

---

## Detection Source
The incident was detected through **honeypot telemetry**. Cowrie recorded all SSH connection attempts, authentication events, and command execution in structured JSON logs.

Relevant Cowrie event types observed:
- `cowrie.session.connect`
- `cowrie.login.failed`
- `cowrie.login.success`
- `cowrie.command.input`
- `cowrie.session.closed`

---

## Timeline of Events
Using the Cowrie `session` field, attacker activity was reconstructed chronologically.

| Time (UTC) | Event |
|-----------|------|
| 2026-02-06 15:30:45 | SSH connection initiated |
| 2026-02-06 15:30:58 | Failed login attempt |
| 2026-02-06 15:30:58 | Successful login |
| 2026-02-06 15:31:09 – 15:31:29 | Post-login commands executed |
| 2026-02-06 15:31:46 | Session closed |

This sequence is consistent with **credential-based access followed by system reconnaissance**.

---

## Source and Target Information
- **Source IP:** `192.168.1.36`
- **Destination Port:** `2222`
- **Protocol:** SSH
- **Sensor Hostname:** `kali-raspberrypi`

---

## Authentication Activity

### Failed Login Attempts
Observed failed authentication attempts using weak credentials:

192.168.1.36 | root:root


### Successful Login Attempts
The attacker successfully authenticated using the following credentials:

192.168.1.36 | root:admin


The successful authentication indicates the attacker believed they had compromised a legitimate system.

---

## Post-Authentication Activity

After successful login, the attacker executed the following commands:

192.168.1.36 | pwd
192.168.1.36 | whoami
192.168.1.36 | ls
192.168.1.36 | exit


### Command Frequency

2 exit
1 whoami
1 pwd
1 ls



This behavior is indicative of **initial reconnaissance**, commonly performed to:
- Identify current directory
- Confirm user context
- Enumerate filesystem contents

---

## Indicators of Compromise (IOCs)

### Network IOCs
- **Source IP:** `192.168.1.36`

### Credential IOCs
- **Usernames:** `root`
- **Passwords:** `root`, `admin`

### Behavioral IOCs
- SSH access on non-standard port (2222)
- Immediate execution of reconnaissance commands
- Short-lived session with no lateral movement

---

## Evidence (Log Excerpts)

### Successful Authentication Event
``json
{
  "eventid": "cowrie.login.success",
  "src_ip": "192.168.1.36",
  "username": "root",
  "password": "admin"
}


###Command Execution Event

{
  "eventid": "cowrie.command.input",
  "src_ip": "192.168.1.36",
  "input": "whoami"
}

All events were correlated using the Cowrie session identifier to ensure accuracy.

###Analyst Assessment

The observed activity aligns with opportunistic SSH brute-force behavior, commonly associated with automated or low-sophistication attacks. The attacker leveraged weak credentials and performed minimal reconnaissance before terminating the session.

There is no evidence of:

-Privilege escalation
-Malware deployment
-Data exfiltration
-Persistence mechanisms


###Recommendations:

-Disable password-based SSH authentication
-Enforce key-based authentication
-Monitor SSH access attempts on non-standard ports
-Integrate honeypot telemetry into a SIEM
-Enrich source IPs with threat intelligence feeds
-Use observed indicators to build detection rules


###Conclusion

This incident demonstrates the effectiveness of SSH honeypots for capturing real-world attacker behavior.
 Through Cowrie telemetry, attacker actions were fully observed, correlated, and analyzed.
 The extracted indicators and reconstructed timeline provide actionable intelligence suitable for SOC operations and detection engineering.
