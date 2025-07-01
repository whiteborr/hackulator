---
title: WINDOWS ENUMERATION
updated: 2023-11-29 02:35:34Z
created: 2023-10-03 22:55:24Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# WINDOWS ENUMERATION

## Automated Tools

### Executables:
- winPEAS.exe
- Seatbelt.exe (compile)
- Watson.exe (compile)
- SharpUp.exe (compile)

### PowerShell:
- Sherlock.ps1
- PowerUp.ps1
- PowerView.ps1
- jaws-enum.ps1
- WinPEAS.ps1
- PowerSploit-Master

### Other:
- windows-exploit-suggester.py (local)
- Exploit Suggester (Metasploit)

* * *

### Meterpreter
meterpreter > run post/multi/recon/local\_exploit\_suggestor

### Windows-exploit-suggester.py

1.  Copy systeminfo of target to file **systeminfo\_target.txt** & Download [windows-exploit-suggester.py](https://github.com/Pwnistry/Windows-Exploit-Suggester-python3/blob/master/windows-exploit-suggester.py) file locally
    
2.  `sudo pip install xlrd --upgrade`
    
3.  `python2 get-pip.py`
    
4.  `python -m pip install --user xlrd==1.1.0`
    
5.  `python3 ./windows-exploit-suggester.py --update`
    
6.  Take note of database name
    
7.  `python3 ./windows-exploit-suggester.py --database <database_name> --systeminfo systeminfo_target.txt`
    

**NTUSER.DAT**: This is the main registry hive for the users residing in the user account profile folder and contains the most valuable forensics data.

**UsrClass.dat**: Just Like NTUSER.DAT, the UsrClass is another registry hive to obtained user-related information.

***
## PowerUp.ps1
`. .\PowerUp.ps1`
`Invoke-AllChecks`

## PowerView.ps1
#### Abusing Active Directory ACLs/ACEs

`Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}`  