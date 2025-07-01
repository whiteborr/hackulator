---
title: WEB-APPLICATION ENUMERATION
updated: 2023-11-30 11:32:07Z
created: 2023-09-29 05:28:21Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# WEB-APPLICATION ENUMERATION

1.  Install **Go**
2.  Install **Assetfinder**
3.  Install **Amass** (OWASP)
4.  use `httpprobe` to find alive domains
5.  Screenshot with **GoWitness**
6.  Automate the process

## FUZZ for subdomains

`wfuzz -c -f sub-fighter -w /usr/share/seclists/Fuzzing/subdomains-top1million-5000.txt -u 'http://<website>' -H "Host: FUZZ.<website>"`  
Note: you can use `--hc/hl/hw/hh` to hide responses with the specified code/lines/words/chars

`gobuster vhost -w /usr/share/seclists/Fuzzing/subdomains-top1million-5000.txt -u http://<website> -v --append-domain`

## Access webpage from different world locations
`shotsherpa`

***
### Try to register or create an account.
1. If possible to login or register a new account, once logged in check browser **cookies**
2. Check if **HttpOnly** 