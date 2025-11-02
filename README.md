# 🛡 Security Alert Monitoring & Incident Response

![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![Tool](https://img.shields.io/badge/Tools-ELK%20%7C%20Splunk-blue)
![Focus](https://img.shields.io/badge/Focus-SOC%20%7C%20Incident%20Response-orange)
![Author](https://img.shields.io/badge/Author-Nandhitha%20V%20N-purple)

---

## 📘 Project Overview
This project demonstrates how *SIEM tools* (ELK & Splunk) can be used to *detect, analyze, and respond* to simulated cybersecurity incidents.  
It highlights real-world *Security Operations Center (SOC)* tasks — including log monitoring, threat detection, incident classification, and response planning.

---

## 🎯 Objectives
- Collect and analyze simulated security logs.  
- Identify potential threats or abnormal activities.  
- Classify incidents by severity level.  
- Document response actions and mitigation recommendations.  

---

## 🧰 Tools & Technologies
| Category | Tools Used |
|-----------|-------------|
| SIEM Platform | ELK Stack (Elasticsearch, Logstash, Kibana), Splunk |
| Log Simulation | Custom log files (Linux & Network logs) |
| Analysis | Kibana dashboards, Splunk queries |
| Reporting | Markdown / PDF Report |

---

## 🧠 Skills Gained
- Log correlation and threat analysis  
- Security alert triage and classification  
- SOC incident handling workflow  
- Writing structured incident reports
-  [2025-11-01 10:15:42] SRC=192.168.1.50 DST=10.0.0.15 SPT=55789 DPT=22 ACTION=DENY MSG="Multiple failed SSH login attempts" [2025-11-01 10:17:10] SRC=203.0.113.45 DST=10.0.0.20 SPT=443 DPT=80 ACTION=ALLOW MSG="HTTP request with suspicious payload detected" [2025-11-01 10:19:03] SRC=198.51.100.32 DST=10.0.0.30 SPT=50223 DPT=3389 ACTION=DENY MSG="RDP brute-force attempt detected"
-  ---

## 🔍 Sample Incident Analysis

### *Incident 1: SSH Brute Force Attempt*
- *Description:* Multiple failed SSH logins detected from IP 192.168.1.50.  
- *Severity:* High  
- *Impact:* Potential unauthorized access attempt.  
- *Recommendation:* Implement account lockout policy and restrict SSH access to trusted IPs.  

### *Incident 2: Suspicious HTTP Payload*
- *Description:* HTTP request from 203.0.113.45 containing a script injection pattern.  
- *Severity:* Medium  
- *Impact:* Possible XSS or injection attempt.  
- *Recommendation:* Enable web application firewall (WAF) and sanitize user inputs.
- ---

## 🚨 Incident Response Summary

| Incident | Severity | Description | Action Taken |
|-----------|-----------|--------------|---------------|
| SSH Brute-Force | 🔴 High | Multiple failed SSH logins | IP blocked & account lockout enforced |
| Suspicious HTTP Payload | 🟠 Medium | XSS pattern detected in HTTP logs | WAF rules applied, IP blocked |
| RDP Attack | 🔴 High | Repeated failed RDP attempts | Disabled external RDP, enabled MFA |

---

## 🧩 Key Findings
- Frequent brute-force attempts on SSH and RDP ports.  
- Suspicious HTTP payloads indicating injection attacks.  
- Insider-like privilege escalation detected in internal systems.  

---

## 🛠 Implementation Steps
1. Set up ELK and Splunk for log collection and analysis.  
2. Imported and visualized simulated log data.  
3. Created dashboards to track failed logins and network anomalies.  
4. Classified and documented incidents in a structured report.
5. ---

## 🧾 Full Incident Report
A detailed incident response report including all alerts, severity, and actions is available here:  
👉 [View Report (PDF)](incident_response_report.pdf)

---

## 📊 Future Enhancements
- Automate alert correlation using Python scripts.  
- Integrate email notifications for high-severity incidents.  
- Deploy on cloud-based SIEM like Azure Sentinel or QRadar.

---

## ❤ Acknowledgements
Thanks to *OWASP, **Elastic Security Labs, and **Splunk Security Essentials* for providing real-world learning material and use cases.

---

## 👩‍💻 Author
*Nandhitha V N*  
🔗 [LinkedIn Profile](https://www.linkedin.com) https://www.linkedin.com/in/nandhitha-v-n-41173136b?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=android_app  


---
- 

---

## 🧾 Sample Log Entries
