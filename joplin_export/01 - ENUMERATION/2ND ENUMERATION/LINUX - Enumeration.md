---
title: LINUX - Enumeration
updated: 2025-05-06 13:25:08Z
created: 2025-05-06 12:52:06Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

Get bash history:
`history`

Get Privileges:
`id`

Other commands
`cat /etc/passwd`
`hostname`
`cat /etc/issue`
`cat /etc/os-release`
`uname -a` - how kernel version and architecture

Show variables:
`enum`
*** 
### List system processes:
`ps aux` (look for processes running as root)
`watch -n 1 "ps aux | grep <keyword>`


***
### Check for interfaces, routes and open ports:
`ifconfig` OR `ip a`
`route` OR `routel`
`cat /etc/resolv.conf`

`ss -anp` 
-a : List all connections
-n : Disable hostname resolution
-p : List name of process

`netstat -ano`

### Firewall rules
`/etc/iptables`
`cat /etc/iptables/rules.v4`

`iptables-save`
`iptables-restore`

* * *
Look for scheduled or automated tasks that are run by processes. Look for weak permissions
`ls -lah /etc/cron*`
`crontal -l` OR `sudo crontab -l`

* * *
### unix-privesc-check
https://pentestmonkey.net/tools/audit/unix-privesc-check
`./unix-privesc-check standard > output.txt`


LinEnum
LinPEAS

