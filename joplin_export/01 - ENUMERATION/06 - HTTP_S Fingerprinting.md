---
title: 06 - HTTP/S Fingerprinting
updated: 2025-05-12 03:22:56Z
created: 2025-04-16 11:17:46Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

* * *
Scan web server using **nmap**
`nmap -p80 --script=http-enum <target>`

Identify supported SSL/TLS versions & cipher suites:
`nmap --script ssl-enum-ciphers -p 443 <target>`
* * *
## GoBuster
`gobuster dir -u <target> -w /usr/share/wordlists/dirb/common.txt -t 5`

`gobuster dir -u http://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t20 -x aspx`

vhost
`gobuster vhost -w <wordlist> -u http://<target>:<port> --exclude-length 334`

* * *

## Debug Page Content

1. Start with a URL address
2. File extensions (which can be part of a URL) can reveal the application it was written in
3. Some extension like PHP are straightforward, but other are more cryptic and vary based on the frameworks in use. ***File extensions on webpages are becoming less common***, however since many languages & frameworks now support the concept of *routes* which allow developers to map a URI to a section of code. Applications leveraging *routes* use logic to determine what content is returned to the user - making URI extensions largely irrelevant.
Most context clues can be found in the source of the web page.
4. The Firefox debugger tool displays the pages resources and content, which may display:
- Javascript & Javascript Frameworks
- Hidden Input Fields
- Comments
- Client-Side controls within HTML

* * * 
## BurpSuite
1. Inspect **HTTP response headers** and **Sitemaps**
**Sitemap** files are used by searchengine bot to crawl and index site, including a list of what not to crawl (such as sensite pages or admin consoles). The **robots.txt** file includes the URL to exclude
2. Inspect **Server responses** for additional information

* * *
## Dirbuster
`dirb http://<target> -r`

* * *
Hints:
1. Look for hidden directories and files using gobuster/dirb/etc
2. Check for login pages
3. Check pages (including source) for application versions