#  Network Service Discovery – RTSP / AirPlay Enumeration

## Objective
The goal of this lab was to identify active hosts on a local network, enumerate open ports and services, analyze an unknown service discovered via Nmap, and assess its security impact from both attacker and SOC perspectives.

This lab focuses on **service discovery and analysis**, not exploitation.

---

## Environment

| Component | Details |
|---------|--------|
| Attacker Machine | Kali Linux |
| Network | Local lab / home network |
| Target | Internal network host |
| Tools | Nmap, arp, curl |
| Authorization | Authorized lab environment |

---

## Host Discovery

sudo nmap -sn 192.168.1.0/24

--Purpose:
Identify live hosts without scanning ports.

##Port & Service Enumeration

sudo nmap -sS -sV -p7000 <target-ip>

#Result:

7000/tcp open  rtsp
Service Info: Apple AirTunes rtspd 770.8.1

##Service Analysis

-Protocol: RTSP (Real Time Streaming Protocol)
-Application: Apple AirTunes / AirPlay
-Function: Receives audio streams from devices on the same network

Common devices exposing this service:

-Apple TV
-Smart speakers
-Smart TVs
-Macs with AirPlay enabled
-Linux AirPlay receivers

##Interaction Feasibility

Can the service be directly manipulated with only IP + port?
 No.

Reason:

-RTSP is a stateful protocol
-AirPlay requires a compliant client
-Audio streaming involves session negotiation, codecs, and timing control

Only legitimate AirPlay clients can interact with this service.

##Security Assessment

Risk Level: Low

Observations:

-Intended for local network use
-No remote exposure observed
-No authentication bypass detected

Potential Risks:

-Unauthorized audio playback by users on the same Wi-Fi
-Privacy concerns on shared networks

Mitigations

-Enable AirPlay authentication / PIN
-Restrict AirPlay to trusted devices
-Isolate media devices in a separate VLAN
-Ensure no router port forwarding exists for port 7000

SOC Perspective

From a SOC standpoint, this activity represents:

-Normal internal service discovery
-Expected AirPlay traffic
-No indicators of compromise
-No malicious behavior observed

Understanding these services helps reduce false positives during monitoring.

##Conclusion

This lab demonstrated that:

-Open ports are not inherently vulnerabilities
-Accurate service fingerprinting is critical
-Protocol knowledge is required before attempting interaction
-Discovery and exploitation are separate phases
