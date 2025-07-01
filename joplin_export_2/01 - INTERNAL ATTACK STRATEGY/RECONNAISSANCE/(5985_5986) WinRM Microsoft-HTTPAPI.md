---
title: '(5985/5986) WinRM Microsoft-HTTPAPI '
updated: 2025-05-12 01:18:45Z
created: 2023-11-29 02:29:49Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

## WinRM - Microsoft-HTTPAPI

1.  Once you have crerdentials, run **evil-winrm**  
    `evil-winrm -i <target> -u <user> -p <password>`

2. `powershell.exe -ExecutionPolicy Bypass`
3. `Import-Module .\powerview-dev.ps1`

4. 
```
Get-NetGPO
Get-NetDomain
Get-NetUser
Get-NetGroup
```