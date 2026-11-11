# Help Desk Ticket #4451 – Capture the Flag (CTF) Investigation

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

A help desk ticket was received from an employee in the Finance department reporting that unexpected prompts kept appearing on his computer while he was working. The employee stated that he ignored the prompts because he assumed everything was fine but requested that IT investigate the issue. Upon reviewing the screenshot provided, the IT team noticed a Remote Desktop Connection notification indicating that another user, m.smith, was attempting to connect to his computer. The employee confirmed that he did not initiate or expect any remote connection. The goal is to investigate the suspicious Remote Desktop activity, determine who attempted to access the employee's workstation, establish whether unauthorized access was successful, and identify any related suspicious login attempts, process executions, file access, or network connections. If unauthorized access is confirmed, determine the extent of the compromise, take appropriate containment measures, and notify management.

![Geo Map](https://i.imgur.com/dbKVWgP.png)

## Incident Details
- **Received:** 22 April 2026, 09:14 UTC
- **Employee:** Mark Smith, Finance
- **Affected machine:** NPT-WS01
- **Focus window:** 22 April 2026, 04:30 to 06:00 UTC.
- **Target host:** npt-ws01


### KQL Query to define the investigation scope.
This was ran at the beginning of every query
```Kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
```

## Steps Taken

### 1. The Logon(Authentication events; recognising the suspicious logon.)
**objective:** To find the account the attacker actually succeeded with(not Mark's account).

**KQL Query Used to locate event:**
```kql
DeviceLogonEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion  

```
<img src="https://i.imgur.com/7SG2a2Q.png" alt="Geo Map Result" width="80%">

**Result:** : The "HelpDesk" account was used.

### 2. The Source(Linking a logon to the external source address.)
**objective:** To find the external IP address the attacker authenticated from

**KQL Query used to locate event:**
```kql
DeviceLogonEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, ActionType, AccountName, RemoteIP
```
<img src="https://i.imgur.com/khXRd7i.png" alt="Geo Map Result" width="80%">

**Result:** `20.110.92.50` is the external IP address used by the attacker


### 3. The Process(Knowing the Process execution and command-line analysis)
**objective:** To find the command line that launched the implant

**Query used to locate events:**
```kql
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where AccountName =="helpdesk"
| project TimeGenerated, DeviceName, ActionType, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```
<img src="https://i.imgur.com/Bxb4RyR.png" alt="Geo Map Result" width="80%">

**Result:** cmd.exe /Q /c start "" "C:\Windows\Temp\WindowsUpdate.exe" is the command line used to launch the implant

### 4. The Tree(Parent-child process relationships; reconstructing the chain)
**objective:** To Identify the immediate parent process that spawned that cmd.exe. This is what confirms remote WMI execution rather than a local user.

**Query used to locate events:**
```kql
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where AccountName =="helpdesk"
| project TimeGenerated, DeviceName, ActionType, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
```
<img src="https://i.imgur.com/iivW2rL.png" alt="Geo Map Result" width="80%">
<img src="https://i.imgur.com/iV8Nf5g.png" alt="Geo Map Result" width="80%">

**Result:** The process that spawned the cmd.exe file is "wmiprvse.exe".

### 5. File Download - The Connection(Looking for the domain Mark's computer is talking to)
**objective:** To find the command-and-control(server out on the internet that issues command to compromise computers out on the internet) domain the host beaconed to. (This folds the old Connection and DNS stages into one — the network event and the DNS lookup resolve to the same artifact.)
```Kql
DeviceNetworkEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where InitiatingProcessAccountName == "helpdesk"
| project TimeGenerated, DeviceName, ActionType, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessFileName
```
<img src="https://i.imgur.com/hkaDvY6.png" alt="Geo Map Result" width="80%">

**Result:** The connection is "updates.abordasync.website

### 6. The File- File drops in staging locations; network-delivered file attribution.(the compromised host becaconed out to hackers, the hacker responds back to have a file downloaded by the compromised host, thereby downloading a malware
**objective:** To find the SHA256 (hash) of the dropped implant. 
**Query used to locate events:**
```kql
DeviceFileEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where FolderPath has "WindowsUpdate.exe"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256
```
<img src="https://i.imgur.com/fT4NtEA.png" alt="Geo Map Result" width="80%">

**Result:** The "SHA256" file is 20cef6a013953890f9d38605d25d60dd63b42b09946bbb18ddb4a456da306e77

### 7. The Key (Registry Run-key persistence)
**objective:** To find the name of the Run-key value the attacker created for autostart persistence
```Kql
DeviceRegistryEvents
| where Timestamp  between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where RegistryKey contains "run"
| where isnotempty(RegistryValueName)
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData
```
<img src="https://i.imgur.com/ZyP8XqR.png" alt="Geo Map Result" width="80%">

**Result:** The "WindowsHealthCheck" is the name of the Run-Key value the attacker created

### 8. The Task (Scheduled-task persistence)-making a task in windows to make some execution at given intervals when the computer is turned on
**objective:** To  Find the name of the scheduled task created for persistence
```Kql
DeviceProcessEvents
| where Timestamp  between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ProcessCommandLine contains "tn"
| project TimeGenerated, DeviceName, ActionType, FileName, ProcessCommandLine
```
<img src="https://i.imgur.com/lR4H0lZ.png" alt="Geo Map Result" width="80%">

**Result:** The "goggleupdatertask" in schtasks  "/create /tn GoogleUpdaterTask /tr C:\Windows\Temp\WindowsUpdate.exe" is the scheduled task created

### 9. The Service-Service-based persistence.(using a service running already in the computer to persist access.so if a service was deleted, it gets to be re-created
**Objective:** To Find the name of the Windows service the attacker installed to run the implant.
```Kql
DeviceProcessEvents
| where Timestamp  between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ProcessCommandLine contains "sc.exe create"
| project Timestamp, ActionType, FileName, ProcessCommandLine
```
<img src="https://i.imgur.com/rBVw9vP.png" alt="Geo Map Result" width="80%">

**Result:** The "windowsHealthSvc" is the name of the Window service attacker installed

### 10. The Account (Local account creation and privilege escalation)- The hacker got into the system and created another account and had it elevated to admin priviledges.
**Objective:** To find the backdoor local user account the attacker created and then promoted to Administrators.
```Kql
DeviceProcessEvents
| where Timestamp  between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ProcessCommandLine contains "net user"
| project Timestamp, ActionType, FileName, ProcessCommandLine
```
<img src="https://i.imgur.com/VbOQqwA.png" alt="Geo Map Result" width="80%">

**Result:** The "nexus_admin" admin privileges was the backdoor local account created.

### 11. The Endpoint(Scoping an investigation across multiple hosts)
**Objective:** The attacker did not stay on a box, To Find the second host the attacker moved toward, so containment can be extended to it. First query is to list all npt and second query is to know which npt- raised alerts which will lead to the second host attacked by the attacker.
```Kql
DeviceInfo
| where DeviceName starts with "npt-"
| distinct DeviceName
| sort by DeviceName asc
```

<img src="https://i.imgur.com/P2B5kCB.png" alt="Geo Map Result" width="80%">

**Result:** It listed all npt in the windows

```Kql2
AlertInfo
| join AlertEvidence on AlertId
| where DeviceName starts with "npt-"
| Project DeviceName, Title, AlertId
| sort by DeviceName asc
```

<img src="https://i.imgur.com/Supf5K5.png" alt="Geo Map Result" width="80%">

**Result:** This showed the npt- hosts that raised an alert




### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
