# SIEM Internship – Phase 2:  Suspicious Activity Detection & Threat Actor Behavior Simulation

##  Overview
  This repository presents the second phase of the SIEM internship, focusing on detecting post-exploitation attacker behavior using **Elastic Stack (ELK)**. The setup emulates real-world adversarial techniques and analyzes them through log data collected from **Windows systems** using **Elastic Agents**. This environment enables effective threat detection, investigation, and response through centralized logging and analysis.

## Tools Used

- Windows Virtual Machine (VM) in AWS(EC2)
- **Sysmon** – System Monitor for Sysinternals
- Elastic Stack (Elasticsearch + Kibana + Logstash)
- Elastic Agent 

## Use Cases

1. [Privilege Escalation Attempt](<writeups/Use Case 1 Privilege Escalation Attempt/detection.md >)

2. [Lateral Movement via PsExec](<writeups/Use Case 2 Lateral Movement via PsExec/detection.md >)

3. [Suspicious File Download & Execution](<writeups/Use Case 3 Suspicious File Download & Execution/detection.md >)

4. [Abnormal User Behavior](<Siem-Internship-Phase-2/writeups/Use Case 4 Abnormal User Behavior/detection.md>)

5. [Command & Control (c2) - Beaconing Detection](<Siem-Internship-Phase-2/writeups/Use Case 5 Command & Control (c2) - Beaconing Detection/detection.md>)

## Learning Outcomes

-  Correlate events across multiple system
-  Detection and investigate attacker behavior post-login
-  Build and document detection logic using real data
-  Improve SIEM rule tuning and false positive analysis.