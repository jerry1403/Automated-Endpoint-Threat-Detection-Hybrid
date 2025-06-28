# Automated-Endpoint-Threat-Detection-Hybrid
This hybrid architecture enables real-time collection, analysis, and automated remediation of endpoint threats across distributed assets. 

Overview:
In today’s complex IT environments, organizations increasingly rely on hybrid infrastructures combining cloud-hosted endpoints with on-premises systems. This project delivers a robust, scalable, and automated endpoint threat detection framework that seamlessly integrates cloud and on-premises environments to provide comprehensive security monitoring and rapid incident response. 

Leveraging Wazuh agents deployed on Google Cloud Platform (GCP) virtual machines and integrating with on-premises SOAR tools such as Shuffle and TheHive, the solution establishes a secure, encrypted communication channel using WireGuard VPN.

Custom detection engineering—including tailored YARA rules—enhances malware and anomaly detection beyond signature-based methods, while Shuffle’s orchestrated workflows automate incident triage and response. The system reduces alert fatigue, accelerates mean time to respond (MTTR), and strengthens organizational security posture by unifying visibility and control across hybrid endpoint environments. 

![aytomatedendpointthreatdetection](https://github.com/user-attachments/assets/4770d898-0a19-40a4-88c3-0d1658595e29)


Technical Summary:
Hybrid Architecture and Deployment:-
Cloud Endpoint Monitoring:

Wazuh agents are installed on GCP virtual machines, continuously monitoring system logs, file integrity, process execution, and network activity. 
Agents collect telemetry data including syslogs, event logs, and security-related events, forwarding them securely to the Wazuh manager for analysis. 

On-Premises SOAR Integration: 

Shuffle orchestrates automated incident response workflows triggered by alerts from Wazuh and other integrated tools. 
TheHive serves as the centralized incident management platform, enabling SOC analysts to investigate, track, and document security incidents. 

Secure Communication: 

A WireGuard VPN tunnel connects cloud endpoints and on-premises infrastructure, ensuring encrypted, low-latency, and reliable data transmission. 

![FIM_Enrichment](https://github.com/user-attachments/assets/10872e5e-9e15-435e-8fd5-1e4d2b139b65)
![WireguardVPN_Tunnel](https://github.com/user-attachments/assets/c059a923-29a2-4e25-8ee5-0033dfc45ebf)


Custom Detection Engineering:-
YARA Rule Development:

Created and deployed custom YARA rules within Wazuh agents to detect sophisticated malware behaviors and suspicious file patterns not covered by default signatures. 
Rules target specific attack vectors such as PowerShell-based attacks, lateral movement techniques, and fileless malware indicators. 
Created Scripts to execute rules file on to the directories and parse JSON results to be viewed in Wazuh.

![CustomYARA](https://github.com/user-attachments/assets/88e5f778-bc82-4bfc-b316-da2ddac052e6)


Alert Tuning and False Positive Reduction: 

Conducted iterative tuning of detection thresholds and rule logic to reduce false positives by approximately 25%, improving alert quality and SOC efficiency. 
Context-aware filtering excludes benign activities (e.g., scheduled tasks, known admin scripts) while maintaining sensitivity to genuine threats

![Github_rules_YARA](https://github.com/user-attachments/assets/f9646bf4-ea78-4d57-86c3-974aae1fdb7c)
![AnalysisScript](https://github.com/user-attachments/assets/420c8f5d-2e14-43a9-b6e1-a8933b5338a1)



Automated Incident Response Workflows:-
Workflow Design in Shuffle: 

Developed over 10 automated workflows tailored to common endpoint incident types, including: 
Malware detection: Isolating affected endpoints, collecting forensic data, and initiating malware scans. 
Brute-force attacks: Blocking offending IP addresses and notifying SOC teams. 
Suspicious process execution: Terminating unauthorized processes and gathering artifacts. 
Data exfiltration attempts: Quarantining endpoints and blocking suspicious network connections. 
![TotalWF](https://github.com/user-attachments/assets/a59d2291-fb76-40ef-b148-519f66e31661)


Multi-step Orchestration: 

Workflows combine conditional logic, API calls to security tools, and human-in-the-loop approvals to balance automation with analyst oversight. 
Integration with TheHive allows automated case creation and enrichment, streamlining incident management. 
![hive](https://github.com/user-attachments/assets/6eff49c1-05cb-46fb-a847-3b27239690e3)


Data Aggregation and Visualization:-
Wazuh Dashboard:

All logs and alerts are visualized within the Wazuh dashboard, providing a unified interface for monitoring endpoint health, security events, and threat trends.
The dashboard supports the creation of custom visualizations (e.g., time series charts, pie charts, tables) to analyze security data and identify patterns.

![Bar](https://github.com/user-attachments/assets/d15e2b31-f300-4a8f-b393-7fc0be00251c)
![Pie](https://github.com/user-attachments/assets/6c7e68f2-2464-4444-b35b-5a766f878eb4)
![events](https://github.com/user-attachments/assets/410dd47a-1821-4676-9a6c-17e01999831e)


Threat Intelligence Enrichment: 

Integrated external threat intelligence feeds to contextualize alerts and prioritize response efforts based on attacker reputation and known IOCs. 


Security and Compliance Controls:-
Access Control: 

Enforced least privilege access using GCP IAM roles. 
WireGuard VPN keys are rotated regularly, and endpoint agents are configured with secure authentication mechanisms. 

Data Protection: 

Data retention policies comply with organizational and regulatory requirements, balancing operational needs with privacy concerns.


Visual Data highlights:-
IP Enrichment:

![cowrie-shuffle](https://github.com/user-attachments/assets/cfbe5f0a-4114-4e42-985b-d2bfc9dd8632) ![virustotalscanresult IP](https://github.com/user-attachments/assets/6ee9fe41-5e78-4d98-8541-3dd09258d8d8) ![cowrie-alerts](https://github.com/user-attachments/assets/0a5363b8-357b-46ab-b0b8-0b2ff07598f2)


Conditional Flow:

![Suricata-shuffle](https://github.com/user-attachments/assets/3d30d6d1-a15a-42b7-a721-664d9ca1d1ba) ![suricataflow-ingress](https://github.com/user-attachments/assets/36eaa9ac-be4f-410d-92b2-cfec39d0b8a2) ![suricataflow-egress](https://github.com/user-attachments/assets/61a11ec8-b36a-4e83-8227-99c6faf36a15)


File Intergrity Monitoring:(Persistence attempt)

![executable_drop](https://github.com/user-attachments/assets/5fde97a1-da51-44d0-86a8-df52f8a3e8dc) ![script-drop](https://github.com/user-attachments/assets/a362025e-4e0c-4010-82fe-734a329a70e2) ![FIM_Enrichment](https://github.com/user-attachments/assets/bc5fd65b-6916-4d65-84d2-7d2ee7277111)


Mitre specific Workflows:

![Account_Discovery](https://github.com/user-attachments/assets/680b3007-a772-4360-83fb-330aa3f1865c) ![Account_Enumeration](https://github.com/user-attachments/assets/20b3276d-6833-482c-8574-1bb67cd71568) ![BruteForce](https://github.com/user-attachments/assets/5c09ef4c-6055-4f4d-923b-f47481dccea2) ![CommandandControl](https://github.com/user-attachments/assets/064f022f-be8d-4f17-879f-f2ab0f70400d)


Conclusion:
This project exemplifies a modern, hybrid approach to endpoint threat detection and response, combining cloud-native monitoring with powerful on-premises automation. By leveraging custom detection engineering, secure communications, and orchestrated workflows, it delivers faster detection, reduced false positives, and streamlined incident handling. The solution enhances SOC capabilities, enabling security teams to proactively defend distributed environments against evolving cyber threats. 
