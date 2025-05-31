# Lateral Movement Via SMB or PSExec

##  Scenario Description
  an attacker who has already compromised a system within a Windows network attempts to **move laterally** to other hosts using **SMB (Server Message Block)** protocol or **PsExec**, a legitimate administrative tool from the Sysinternals suite.
## Objective
  To **detect and alert on lateral movement attempts** in a Windows environment using **SMB-based techniques**, particularly **PsExec** and similar tools. The goal is to identify unauthorized or suspicious remote command execution and service creation activities across systems, which may indicate an attacker moving laterally within the network using valid credentials and administrative protocols.


## Detection Logic / Query

```powershell
destination.port: 445 and 
(
  process.name: ("psexec.exe" or "psexesvc.exe" or "cmd.exe" or "powershell.exe" or "wmic.exe" or "sc.exe") or
  process.command_line: ("\\\\*\\ADMIN$" or "\\\\*\\C$" or "\\\\*\\IPC$")
)
```

## Sample Alert Screenshot

## Logs or Sample Event

```powershell
event_id,image,destination_ip,destination_port,command_line
3,C:\Windows\System32\psexec.exe,172.31.32.205,80,"psexec.exe \\54.83.141.170 -u Administrator -p cmd.exe
```
## Detection Status
