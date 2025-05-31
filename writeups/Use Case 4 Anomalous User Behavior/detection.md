# Abnormal User Behavior / Account Compromise
##  Scenario Description
 An attacker with valid credentials gains access to the network during off-business hours (e.g., midnight–6 AM), accesses file shares, and **copies over 100 files rapidly**. This behavior is anomalous for most users and strongly indicates account compromise or malicious insider activity.
## Objective
  Detect a compromised account that:

1. Logs in during **off-hours**
2. Accesses file shares (SMB)
3. Copies/downloads a large number of files in a short time frame (e.g., 100+ in 5 minutes)
## Windows Event IDs

| Event ID | Description                                                                                                                                                                        |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 5145     | [A network share object was checked to see whether client can be granted desired access](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5145) |


## Detection Logic / Query

```sh
event.code:"4624" and winlog.event_data.LogonType:("3" or "10") and user.name:* and not user.name:("SYSTEM" or "Administrator")
```

## Sample Alert Screenshot

## Logs or Sample Event

## Detection Status