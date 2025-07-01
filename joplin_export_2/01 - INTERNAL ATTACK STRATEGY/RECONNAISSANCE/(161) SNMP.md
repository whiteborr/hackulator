---
title: (161) SNMP
updated: 2023-11-29 02:28:56Z
created: 2023-11-29 02:28:48Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

## SNMP

1.  Enumerate with **onesixtyone**  
    `onesixtyone <targetIP> public`  
    `onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp-onesixtyone.txt <targetIP>`
    
2.  Enumerate with **snmp-check**  
    `snmp-check -c public <targetIP>`
    
3.  Enumerate with **snmpwalk**  
    `snmpwalk -v2c -c public <targetIP>`