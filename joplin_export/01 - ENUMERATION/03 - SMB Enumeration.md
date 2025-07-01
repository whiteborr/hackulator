---
title: 03 - SMB Enumeration
updated: 2025-05-12 05:56:21Z
created: 2025-04-15 13:06:59Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

**NetBIOS** (TCP_139) - An independent session layer protocol and service used for LAN  
**SMB** (TCP_445) - Can work without NetBIOS, but NetBIOS over TCP (**NBT**) is required for backward compatibility 

Both are usually enabled together, so enumeration often goes hand in hand  
* * *
Note: **nmap** scripts can be found at `/usr/share/nmap/scripts/smb*`
1. Scan IP range for NetBIOS and SMB:
`nmap -v -p 139,445 -oG smb.txt x.x.x.1-254`
2. Scan for SMB OS discovery:
`nmap -v -p 139,445 --script smb-os-discovery <target>`

* * *
1. Scan with **nbtscan**
`nbtscan -r x.x.x.0/24/`

* * *
1. Scan using a Windows client
`net view \\servername /all`


