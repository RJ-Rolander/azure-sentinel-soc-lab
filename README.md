# Azure Sentinel SOC Home Lab
 
A hybrid, on-premises-to-cloud SOC lab built to practice detection engineering and incident response with Microsoft Sentinel. A locally virtualized Windows Server 2025 domain controller is connected to Azure via Azure Arc, with security event data flowing into a Log Analytics workspace and Microsoft Sentinel for analysis and alerting.
 
---
 
## Why Hybrid, Not a Native Azure VM
 
Most beginner Sentinel labs spin up a Windows VM directly inside Azure. This lab instead runs the domain controller locally in VirtualBox and connects it to Azure through Azure Arc, which is closer to how many real organizations onboard on-premises or non-Azure infrastructure into a cloud SIEM. It also demonstrates the Arc registration, authentication, and agent troubleshooting layer that a pure Azure-VM lab skips entirely.
 
---
 
## Architecture
 
```
[ Kali Linux VM ] --(attacks/simulation)--> [ Windows Server 2025 DC ]
                                                       |
                                                 Azure Arc Agent
                                                       |
                                            Azure Monitor Agent (AMA)
                                                       |
                                            Data Collection Rule (DCR)
                                                       |
                                           Log Analytics Workspace
                                                       |
                                            Microsoft Sentinel (SIEM)
```
 
### Components
 
| Component | Role |
|---|---|
| Windows Server 2025 (VirtualBox) | Domain controller for `soclab.local`, primary log source |
| Kali Linux (VirtualBox) | Attacker/simulation host |
| VirtualBox NAT Network | Shared network allowing both VMs to communicate and reach the internet independently |
| Azure Arc | Registers the on-premises DC as a manageable Azure resource |
| Azure Monitor Agent (AMA) | Installed via Arc extension; reads Windows Event Logs and forwards them |
| Data Collection Rule (DCR) | Defines exactly which events AMA collects and forwards |
| Log Analytics Workspace | Central store for all collected log data |
| Microsoft Sentinel | SIEM layer for querying, detection rules, and incident management |
 
---
 
## Data Sources Collected
 
Two Windows Event Log subscriptions are configured on the DCR, each targeting a specific log with a custom XPath filter rather than collecting entire log categories wholesale.
 
**Security log:**
```
Security!*[System[(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4720 or EventID=4732 or EventID=4698)]]
```
 
**PowerShell Operational log:**
```
Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4104)]]
```
 
### Event ID Reference
 
| Event ID | Log | Meaning |
|---|---|---|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon attempt |
| 4688 | Security | Process creation (with command-line auditing enabled) |
| 4720 | Security | User account created |
| 4732 | Security | Member added to a security-enabled local group |
| 4698 | Security | Scheduled task created |
| 4104 | PowerShell Operational | Script block logging (captures deobfuscated PowerShell content) |
 
These event types cover the core arc of a typical intrusion: initial access attempts (4624/4625), attacker execution once inside (4688, 4104), and common persistence or privilege escalation actions (4698, 4720, 4732). Collecting only these IDs keeps ingestion lean and avoids the noise and cost of collecting the entire Security log.
 
---
 
## Prerequisites Configured on the Domain Controller
 
A fresh Windows Server install does not audit everything needed for the above event IDs to fire. The following were configured explicitly:
 
```powershell
# Required for 4688 to generate
auditpol /set /subcategory:"Process Creation" /success:enable
 
# Required for 4698
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```
 
**Local Group Policy:**
- `Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events` — **Enabled** (without this, 4688 fires but the CommandLine field is blank)
- `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging` — **Enabled** (source of event 4104)
Logon/logoff and account management auditing were already enabled by default on a fresh domain controller promotion.
 
---
 
## KQL Detection Queries
 
### Pipeline Health Check
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize count() by EventID
| order by count_ desc
```
 
### Successful Logons (4624)
```kql
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, LogonType, IpAddress, WorkstationName
| order by TimeGenerated desc
```
 
### Failed Logon Attempts (4625)
```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, SubjectUserName, IpAddress, WorkstationName
| order by TimeGenerated desc
```
 
### Process Creation with Command Line (4688)
```kql
SecurityEvent
| where EventID == 4688
| project TimeGenerated, Account, NewProcessName, CommandLine
| order by TimeGenerated desc
```
 
### New User Account Created (4720)
```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Account, SubjectUserName
| order by TimeGenerated desc
```
 
### Member Added to Privileged Group (4732)
```kql
SecurityEvent
| where EventID == 4732
| project TimeGenerated, Account, SubjectUserName, MemberName, TargetUserName
| order by TimeGenerated desc
```
 
### Scheduled Task Created (4698)
```kql
SecurityEvent
| where EventID == 4698
| project TimeGenerated, Account, SubjectUserName, Activity
| order by TimeGenerated desc
```
 
### PowerShell Script Block Logging (4104)
```kql
SecurityEvent
| where EventID == 4104
| project TimeGenerated, Account, Activity
| order by TimeGenerated desc
```
 
---
 
## Attack Simulation
 
The Kali Linux VM is configured on the same VirtualBox NAT Network as the Windows Server DC, giving it direct network access to the domain controller while maintaining independent internet connectivity.
 
Tools used for simulation:
 
- **netexec (nxc)** — SMB credential brute force to generate 4625 failed logon events
- **impacket-psexec** — Remote execution over SMB to generate 4688 process creation events (blocked by Defender, but generated noise logged by Sentinel)
- **evil-winrm** — WinRM-based remote PowerShell shell for interactive command execution
- **Local PowerShell (fallback)** — Direct execution on the DC to confirm event ID generation when remote execution was blocked
### Simulated Event Generation Commands
 
```powershell
# 4625 - failed logon
nxc smb <target_ip> -u Administrator -p wrongpassword
 
# 4720 - new user created
net user LabAttacker P@ssw0rd123! /add
 
# 4732 - added to Administrators group
net localgroup Administrators LabAttacker /add
 
# 4698 - scheduled task created
schtasks /create /tn "LabTest" /tr "calc.exe" /sc once /st 00:00 /f
 
# 4104 - PowerShell script block
Invoke-Expression 'Get-Process'
```
 
---
 
## Current Status
 
All seven event IDs confirmed ingested and queryable in Sentinel:
 
| Event ID | Count (sample run) | Status |
|---|---|---|
| 4688 | 209 | Confirmed |
| 4104 | 208 | Confirmed |
| 4624 | 187 | Confirmed |
| 4625 | 23 | Confirmed |
| 4720 | 1 | Confirmed |
| 4732 | 1 | Confirmed |
| 4698 | 1 | Confirmed |
 
---
 
## Roadmap
 
- [ ] Formalize 3-5 attack simulation scenarios: RDP brute force, PowerShell encoded command execution, new local admin account creation, scheduled task persistence
- [ ] Write custom KQL detection logic for each scenario and convert into Sentinel scheduled analytics rules
- [ ] Trigger each scenario and practice the full incident lifecycle in Sentinel: triage, investigation, closure with documented findings
- [ ] **Phase 2:** AI-augmented incident triage — export Sentinel incidents via the REST API and feed them to an LLM to generate plain-English incident summaries, MITRE ATT&CK technique mapping, remediation recommendations, and executive-level reports
---
 
## Troubleshooting
 
Building this lab surfaced several non-obvious issues. A full writeup covering each problem, root cause, and fix is in [docs/troubleshooting-journal.md](docs/troubleshooting-journal.md).
 
Issues documented:
1. AD DS role installed silently incomplete via GUI wizard
2. Azure Arc onboarding stuck on biometric prompt inside VM
3. Invalid change token error due to domain controller clock drift
4. HTTP 401 during Arc resource creation due to wrong tenant resolution
5. DCR silently rejecting its own XPath query with no portal-side error
6. Path assumptions in official documentation not matching actual Arc agent folder names
