---
title: LINUX ENUMERATION
updated: 2023-11-29 02:33:39Z
created: 2023-10-15 07:05:09Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

# LINUX ENUMERATION
## Automated Tools
* linPEAS.sh
* LinENUM.sh
* linux-exploit-suggester.sh
* linuxprivchecker.py

***
## Enumerate OS
Find OS and architecture, core count
1. `uname -a`
2. `cat /proc/version`
3. `cat /etc/issue`

## Enumerate USER
1. `history`
2. `sudo su -`
3. `whoami`
`id` 
4. Look for SUDO exploits
`sudo -l`
5. `cat /etc/passwd`
6. `cat /etc/shadow` 
7. `cat /etc/group`

## Enumerate NETWORK
Check network settings, route settings, multi-homing
1. `ifconfig`
`ip a`
1. `ip route`
`netstat -r`
3. `arp -a`
Check open port and who machine is communicating with
5. `netatat -ano`

## Password Hunting
1. `grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2>/dev/null`
`grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2>/dev/null`

2. `locate password | more`
`locate passw | more`
`locate pwd | more`

Look for SSH keys:
1. `find / -name authorized_keys 2>/dev/null` 
`find / -name id_rsa 2>/dev/null`


