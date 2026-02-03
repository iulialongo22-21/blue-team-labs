# Incident 005 – Network Intrusion Detection with Suricata

## Summary
A Network Intrusion Detection System (NIDS) was deployed using **Suricata** on a **Raspberry Pi 5 running Kali Linux (ARM64)** to monitor live network traffic. During controlled testing, Suricata successfully generated alerts related to **network scanning activity** and **suspicious HTTP responses**, demonstrating effective **signature-based detection** at the network layer.

---

## Environment
- **Device:** Raspberry Pi 5  
- **Operating System:** Kali Linux (ARM64 / aarch64)  
- **Network Interface:** `wlan1`  
- **IDS Tool:** Suricata 8.0.3  
- **Log Source:** `/var/log/suricata/eve.json`  

---

## IDS Tool Overview
Suricata is an open-source **Network Intrusion Detection System (NIDS)** that inspects network traffic and generates alerts based on predefined signatures and protocol analysis.

In this lab, Suricata was configured in **IDS mode** and executed as a system service on the Raspberry Pi. The default community ruleset was used to detect suspicious and malicious traffic patterns.

---

## Detection Method
Detection was performed using **signature-based rules** provided by the Suricata community ruleset. These rules inspect packet payloads, protocol behavior, and traffic patterns.

Rules were updated using:
suricata-update
Traffic was captured from the active wireless interface (wlan1) and analyzed in real time.

---

##Alert Generation (Controlled Testing)##

Alerts were intentionally triggered using safe and controlled techniques, including:

-TCP port scanning using nmap
-HTTP requests to IDS testing endpoints (testmyids.org)
-Normal network activity for baseline comparison

Suricata generated alerts in JSON format within eve.json.

---

##Alert Details##
 ==Alert 1 — Network Scanning Activity

-Detection Type: Port scan / reconnaissance
-Signature: Nmap scan detection (ET rules)
-Source IP: Localhost / external test host
-Destination IP: Local system or test target
-Severity: Medium
-Description: Traffic patterns consistent with TCP SYN scanning behavior

 ==Alert 2 — Suspicious HTTP Response

-Detection Type: Application-layer anomaly
-Signature: GPL ATTACK_RESPONSE id check returned root
-Source IP: 52.222.132.84
-Destination IP: 192.168.1.37
-Severity: 2
-Description: HTTP response indicating execution context commonly used for IDS testing

---

##Evidence (eve.json Excerpt)##

{
  "timestamp": "2026-02-03T14:01:53.857699+0000",
  "src_ip": "52.222.132.84",
  "dest_ip": "192.168.1.37",
  "signature": "GPL ATTACK_RESPONSE id check returned root",
  "severity": 2
}

Alerts were extracted using:

jq 'select(.event_type=="alert")' /var/log/suricata/eve.json


---

##Analyst Assessment##

The alerts observed during this investigation are consistent with expected behavior during IDS validation testing. 
Suricata correctly identified network reconnaissance activity and suspicious HTTP responses, confirming that packet inspection and rule matching were functioning as intended.

No evidence of unauthorized exploitation, persistence, or data exfiltration was identified. 
All alerts were associated with controlled testing activity.


---

##Response Actions##

-Alerts were reviewed and validated as expected test events
-No containment or blocking actions were required
-Suricata service status was verified and confirmed operational

---

##Recommendations##

-Tune Suricata rules to reduce alert noise in production environments
-Apply thresholds to minimize false positives
-Forward Suricata eve.json logs into a SIEM for correlation
-Correlate network alerts with host-based logs (authentication and web logs)

---

##Conclusion##

This project demonstrates the successful deployment and operation of a Network Intrusion Detection System on ARM-based hardware.
 It validates the ability to generate, analyze, and document IDS alerts, reflecting practical SOC-level network monitoring and incident analysis skills.
