---
title: (1521) ORACLE
updated: 2023-11-29 02:28:28Z
created: 2023-11-29 02:28:03Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

## ORACLE

1.  Scan to look for database and services  
    `odat all -s <targetIP> -p 1521`
2.  `nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n <targetIP>`