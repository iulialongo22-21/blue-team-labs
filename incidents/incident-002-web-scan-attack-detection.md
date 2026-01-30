##Incident 002 – Web Application Scan & Enumeration Attempt
*Summary*

On 30 January 2026, suspicious web activity was detected on a Raspberry Pi web server running NGINX. The activity originated from a single internal source IP and consisted of repeated requests to common administrative paths, high request volume in a short time window, and scanning behavior consistent with web enumeration and directory brute-force attempts.
No successful exploitation or compromise was identified.


*Environment*

Host: Raspberry Pi 5
Operating System: Kali Linux (ARM)
Web Server: NGINX
Log Source: /var/log/nginx/access.log
Service Port: TCP/80
Server IP: 192.168.1.37
Attacker IP: 192.168.1.135


*Detection*

The activity was detected through manual log analysis of NGINX access logs.
Primary detection command:

-sudo awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head

This revealed an unusually high number of HTTP requests from a single IP address.


*Timeline*

First suspicious request:
30/Jan/2026:15:19:26 +0000
Last suspicious request:
30/Jan/2026:15:26:54 +0000
Total activity window: ~7 minutes

During this period, repeated requests were made to non-existent and sensitive paths.


*Evidence*

Top Source IPs (Request Volume)
18 192.168.1.88
7  192.168.1.135
6  192.168.1.37
1  127.0.0.1


The IP 192.168.1.135 was responsible for repeated probing behavior.


*Suspicious Paths Accessed*

Detected using:
-sudo egrep -i "/admin|/login|\.env|\.git|wp-admin|phpmyadmin" /var/log/nginx/access.log


Sample log entries:
192.168.1.135 - [30/Jan/2026:15:22:13 +0000] "GET /admin HTTP/1.1" 404
192.168.1.135 - [30/Jan/2026:15:22:34 +0000] "HEAD / HTTP/1.1" 200
192.168.1.135 - [30/Jan/2026:15:26:54 +0000] "GET /admin HTTP/1.1" 404


*HTTP Status Code Distribution*

-sudo awk '{print $9}' /var/log/nginx/access.log | sort | uniq -c | sort -nr

Results:
17 200
15 404

A high number of 404 responses indicates directory or resource enumeration attempts.


*Analysis*

The observed behavior is consistent with web application reconnaissance and enumeration, characterized by:

>Repeated requests to common administrative paths (/admin)
>High number of requests from a single IP in a short timeframe
>Use of automated tools (evidenced by rapid requests and HEAD methods)
>Absence of normal browsing patterns

No indicators of successful exploitation were observed. The activity aligns with pre-exploitation scanning, commonly seen during early attack stages.


*Impact Assessment*

Service availability: Not affected
Data compromise: None identified
Authentication bypass: Not observed
System integrity: Intact

The attacker was able to enumerate available paths but did not gain access to restricted resources.


*Containment / Response Actions*

The attacking IP was blocked using UFW:

-sudo ufw deny from 192.168.1.135 to any port 80

Firewall status confirmed:

-sudo ufw status verbose


*Recommendations*

>Implement rate limiting on NGINX to reduce brute-force and scan effectiveness
>Deploy fail2ban for HTTP-based abuse
>Add WAF rules for common attack patterns
>Remove or customize default web server pages
>Centralize logs for correlation (future SIEM integration)
>Monitor repeated 404 spikes as early indicators of reconnaissance


*Appendix – Sample Log Entries*
192.168.1.135 - [30/Jan/2026:15:22:05 +0000] "GET /about HTTP/1.1" 404
192.168.1.135 - [30/Jan/2026:15:22:13 +0000] "GET /admin HTTP/1.1" 404
192.168.1.135 - [30/Jan/2026:15:26:27 +0000] "HEAD / HTTP/1.1" 200


