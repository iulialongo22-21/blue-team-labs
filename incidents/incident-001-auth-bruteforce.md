#Incident 001 - SSH Authentication Brute-Force (Lab)
Incident ID: SOC-LAB-001
Incident Type: SSH Authentication Brute-Force / Username Enumeration
Severity: Medium (Attempted intrusion, no compromise)
Status: Contained
Date Identified: 2026-01-27
Reported By: SOC Analyst (Lab)

#Executive Summary
On 2026-01-27, multiple failed SSH authentication attempts were detected on a Kali Linux system running on Raspberry Pi 5.
The activity originated from a single internal IP address and showed clear signs of automated brute-force and username enumeration targeting the SSH service.

No successful authentication attempts were observed from the attacker IP.
The incident was contained by blocking the source IP at the firewall level (UFW) and reviewing SSH hardening configurations.

#Environment
Host: kali-raspberrypi
Hardware: Raspberry Pi 5
Operating System: Kali Linux (ARM)
Service Targeted: OpenSSH (sshd)
SSH Port: 22/tcp
Log Source: /var/log/auth.log
Firewall: UFW (Uncomplicated Firewall) 

#Detection & Identification
1.0 Initial Detection 
Suspicious activity was identified through manual log review using:
--sudo grep "Failed password" /var/log/auth.log
This revealed multiple failed authentication attempts in a short time window.

1.1 Service Verification
The SSH service was confirmed to be active and listening:
--sudo systemctl status ssh
*Findings:
SSH service active and running
Listening on 0.0.0.0:22 and :::22
Service exposed to the network

#Timeline of Events (Local Time)
Time	                Event
2026-01-27 21:53:17	First failed SSH login attempt observed
2026-01-27 21:53–21:59	Multiple repeated failures from same IP
2026-01-28 13:59:48	Last failed authentication attempt
2026-01-28 14:00+	Firewall containment applied

#Evidence and Observation 
2.0 Source IP Analysis 
command used:
--sudo awk '/Failed password/ {print $(NF-3)}' /var/log/auth.log | sort | uniq -c | sort -nr 
result:
192.168.1.135
*All failed attempts originated from 192.168.1.135
*Repetition confirms brute-force behavior
2.1 Username Enumeration
Observed log entries:
--Invalid user fakeuser from 192.168.1.135
--Failed password for invalid user fakeuser from 192.168.1.135
Findings:
*Targeted username does not exist
*Indicates username enumeration, not targeted account compromise

#Authentication Outcome Verification 
Command used:
--sudo grep -E "Failed password|Accepted" /var/log/auth.log | grep "192.168.1.135"
Result:
 No Accepted password entries
 Only failed authentication attempts recorded
Conclusion: 
No successful login occurred.

#Analysis
*Attack Characteristics*
Attack Type: SSH brute-force / username guessing
Technique: Automated authentication attempts
Pattern: Repeated failures, same IP, multiple ports
Target: SSH service (port 22)
*Indicators of Malicious Activity*
Repeated Invalid user messages
Multiple failed attempts in short timeframe
Single source IP
No legitimate user behavior observed

#Impact Assessment 
| Category             | Assessment |
| -------------------- | ---------- |
| System Compromise    | No         |
| Account Compromise   | No         |
| Privilege Escalation | No         |
| Data Exposure        | No         |
| Service Disruption   | No         |

The attack was unsuccessful and limited to authentication attempts only.

#8 Cantainment & Response 
8.1 Firewall Mitigation

The attacking IP was blocked using UFW:
--sudo ufw deny from 192.168.1.135 to any port 22

Verification:
--sudo ufw status verbose

Result:
SSH remains accessible
Attacker IP successfully denied

8.2 SSH Hardening Review

The following security controls were reviewed/applied:
-PermitRootLogin no
-PasswordAuthentication no (key-based auth recommended)
-MaxAuthTries 3
-AllowUsers <authorized_user>
These measures reduce brute-force effectiveness and attack surface.

#Lesson Learned 
-SSH authentication logs provide high-signal indicators of attack activity
-Repetition and timing are critical for distinguishing noise from attacks
-Blocking at the firewall level is effective for immediate containment
-Preventive SSH hardening significantly reduces risk

#Recommendation
-Enforce SSH key-based authentication only
-Disable password authentication permanently
-Deploy Fail2Ban for automated response
-Restrict SSH access to trusted IPs or VPN
-Centralize logs for correlation (future improvement: SIEM/Wazuh)

#Appendix-Sample Log Evidence
2026-01-27T21:53:17.369110+00:00 kali-raspberrypi sshd-session[34889]: Failed password for invalid user fakeuser from 192.168.1.135 port 56310 ssh2
2026-01-27T21:53:25.326826+00:00 kali-raspberrypi sshd-session[34889]: Failed password for invalid user fakeuser from 192.168.1.135 port 56310 ssh2
2026-01-27T21:53:29.751953+00:00 kali-raspberrypi sshd-session[34889]: Failed password for invalid user fakeuser from 192.168.1.135 port 56310 ssh2
2026-01-28T13:59:38.485628+00:00 kali-raspberrypi sshd-session[8789]: Failed password for invalid user fakeuser from 192.168.1.135 port 52339 ssh2
2026-01-28T13:59:44.724491+00:00 kali-raspberrypi sshd-session[8789]: Failed password for invalid user fakeuser from 192.168.1.135 port 52339 ssh2
2026-01-28T13:59:48.646979+00:00 kali-raspberrypi sshd-session[8789]: Failed password for invalid user fakeuser from 192.168.1.135 port 52339 ssh2
 
#Final Assessment 
Final Assessment

This incident demonstrates a successful detection, analysis, and containment of an SSH brute-force attempt.
The investigation followed proper SOC methodology: identify → analyze → contain → document.
- No compromise occurred
- Appropriate response applied
- Incident fully documented
