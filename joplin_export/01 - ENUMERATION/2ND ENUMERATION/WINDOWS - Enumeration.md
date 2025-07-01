---
title: WINDOWS - Enumeration
updated: 2025-05-06 12:52:39Z
created: 2025-04-29 07:03:37Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

Check Powershell history
`Get-History`
`(Get-PSReadlineOption).HistorySavePath`

Gather the following information:
- Username and hostname
- Group memberships of the current user
- Existing users and groups

`whoami /groups`
`net user` OR `Get-LocalUser`
`net localgroup` OR `Get-LocalGroup`
`Get-LocalGroupMember <group_name>`

- Operating system, version and architecture

`systeminfo`

- Network information 

`ipconfig /all`
`route print`
`netstat -ano`

- Installed applications

`Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select DisplayName`
`Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName"`

- Running processes

`Get-Process`
`systeminfo`

- Privileges

`whoami /priv`