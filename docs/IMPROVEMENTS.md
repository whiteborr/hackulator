# 🛠️ RPC Enumeration Tool - IMPROVEMENTS.md

This document tracks enhancements made and planned for the RPC Enumeration module in the tool. It outlines feature improvements, security-oriented upgrades, and coverage expansion relevant to red teaming, threat emulation, and vulnerability analysis.

---

## ✅ Implemented Improvements

### 1. Structured Output for UI Integration
- Introduced a consistent JSON structure for scan results:
  ```json
  {
    "host": "192.168.1.10",
    "os": "Windows 11 Pro",
    "shares": ["C$", "inetpub"],
    "ports": [135, 139, 445],
    "rpc_interfaces": [
      "uuid: 1234-5678 svcctl",
      "uuid: 5678-90ab eventlog",
      ...
    ]
  }
  ```
- Enables seamless UI data binding for tables and visual graphs.
- Ensures output can be logged, exported, and reused in post-processing.

### 2. System Info Retrieval Improvements
- Primary method: Native Windows command `systeminfo` with optional credentials:
  ```bash
  systeminfo /s <target> /u <user> /p <password>
  ```
- Fallback: Registry-based OS info enumeration using:
  ```bash
  reg query \\<target>\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion /v ProductName
  ```
- Accounts for restricted UAC policies and disabled RemoteRegistry service.
- Annotates failures in the UI with actionable suggestions (e.g., enabling services, adjusting UAC).

### 3. Network Share Enumeration
- Executes the following logic:
  - Authenticated: `net use` to initiate IPC$ session
  - Listing: `net view \\target` to enumerate available shares
- Parses typical shares like `ADMIN$`, `C$`, and custom shares.
- Filters and formats output with annotations for accessibility or error states (e.g., access denied).

### 4. RPC Endpoint Mapping
- Added optional call to `rpcdump.py` to discover:
  - Active RPC endpoints
  - Interface UUIDs
  - Associated named pipes and bindings
- Top 10 most relevant interfaces shown in output (e.g., `svcctl`, `eventlog`, `spoolss`)
- Highlights potentially vulnerable interfaces
- Automatically detects and logs absence of `rpcdump.py` without crashing

### 5. Open RPC Port Scanner
- Performs direct TCP connectivity checks to commonly used RPC-related ports:
  - `135` – RPC Endpoint Mapper
  - `139` – NetBIOS Session Service
  - `445` – SMB
  - `1024–1026` – Dynamic RPC ports (legacy range)
- Results are recorded as a structured list and reported with appropriate visual cues

### 6. RPC Endpoint Mapping
- Added optional call to `rpcdump.py` to discover:
  - Active RPC endpoints
  - Interface UUIDs
  - Associated named pipes and bindings
- Top 10 most relevant interfaces shown in output (e.g., `svcctl`, `eventlog`, `spoolss`)
- Highlights potentially vulnerable interfaces
- Automatically detects and logs absence of `rpcdump.py` without crashing
- Integrated into structured output format with `rpc_interfaces` field

### 7. Authentication Modes
- Implemented NTLM hash-based authentication (pass-the-hash)
- Added NTLM hash field to UI controls
- Support for hash authentication in rpcdump and rpcclient calls
- Credential validation with feedback on success/failure
- UI toggle between password and hash authentication

### 8. Advanced Enumeration Modules - SAMR Interface
- `samr` interface enumeration via rpcclient:
  - Enumerate domain users (`enumdomusers`)
  - Enumerate domain groups (`enumdomgroups`)
  - Parse user/group names and RIDs
- Integrated into structured output with `domain_users` and `domain_groups` fields
- Limited results display (top 10 users, top 8 groups) for UI performance
- Requires authenticated access (username + password/hash)

### 9. Advanced Enumeration Modules - LSARPC Interface
- `lsarpc` interface enumeration via rpcclient:
  - Domain SID extraction (`lsaquery`)
  - Trust relationships enumeration (`lsaenumsid`)
  - Policy information retrieval
- Integrated into structured output with `lsa_info` field
- Displays domain SID and trust domain relationships
- Requires authenticated access for full functionality

### 10. Vulnerability Path Probing
- Interface exposure tests for known RPC-based exploits:
  - `spoolss` — PrintNightmare (CVE-2021-1675) detection
  - `efsr/lsarpc` — PetitPotam (CVE-2021-36942) NTLM relay path
  - `svcctl` — Service control interface abuse detection
- Severity classification (High/Medium/Low)
- Vulnerability descriptions and interface identification
- Integrated into structured output with `vulnerabilities` field

### 11. RID Cycling Logic
- Sequential RID enumeration for user discovery:
  - Tests common RIDs (500, 501, 502, 512, 513, etc.)
  - High-privileged RID identification (500, 512, 516, 518, 519)
  - Standard user RID enumeration (1000+)
- SID-to-name resolution via `lookupsids` command
- Privilege level classification (High/Standard)
- Integrated into structured output with `rid_users` field
- Limited to 15 results for performance

### 12. WKSSVC Interface Enumeration
- `wkssvc` interface enumeration via rpcclient:
  - Computer name and domain information
  - OS version and workstation details
  - Logged-in users enumeration
  - Network share count and accessibility
- Integrated into structured output with `workstation_info` field
- Fallback to share enumeration when direct WKSSVC fails

### 13. UI Enhancements
- Added scan type selection (Basic Info, Full Enumeration, Vulnerability Scan, Complete Assessment)
- Warning banners for Windows 11 compatibility issues:
  - RemoteRegistry service disabled notifications
  - UAC token filtering alerts
- Improved control layout with scan type categorization
- Enhanced visual feedback for different enumeration levels

### 14. Secrets / Hash Extraction (Privileged Only)
- Integrated with Impacket's `secretsdump.py` for credential extraction:
  - SAM database hash extraction
  - LSA secrets and DPAPI keys
  - Cached credentials retrieval
- Protected behind privilege confirmation prompt
- Secure handling - hashes not displayed in UI
- Integrated into structured output with `secrets` field
- Requires elevated access and explicit user consent

### 15. RPC Relay & MITM Mapping
- Detection of NTLM-authenticating RPC interfaces:
  - PrinterBug/SpoolSample relay potential (spoolss)
  - PetitPotam relay vectors (lsarpc/efsr)
  - Service control interface abuse (svcctl)
- SMB signing enforcement detection:
  - Identifies relay-vulnerable configurations
  - Warns when signing not enforced
- Risk assessment and relay potential scoring
- Integrated into structured output with `relay_info` field
- Comprehensive MITM attack surface analysis

---

## 🔜 Future Enhancements (Planned)

### 🔐 Kerberos Authentication
- Kerberos support via TGT/TGS or `.ccache` ticket usage (if environment supports)
- Ticket-based authentication for domain environments
- Golden/Silver ticket detection and analysis

### 📦 Advanced Secrets Extraction
- Integrate with Impacket’s `secretsdump.py` to pull sensitive data:
  - Cached credentials (LSA secrets)
  - SAM hashes
  - NTDS.dit on Domain Controllers
- Protect behind a privileged-use confirmation prompt
- Add logging and optional offline hash storage

### 🛡️ Vulnerability Path Probing
- Interface exposure tests for known RPC-based exploits:
  - `spoolss` — PrintNightmare (CVE-2021-1675)
  - `efsr` — PetitPotam NTLM relay path
  - `svcctl` — Abusable service creation
- Show warnings if vulnerable interfaces are bound on exposed ports
- Future: auto-detection of patches/hardening via registry or function call probing

### 📊 UI Enhancements
- Add expandable sections or tabs for:
  - RPC interfaces list
  - Per-share permission detail
  - Credential result states (e.g., Auth OK, Auth Denied)
- Show warning banners for typical Windows 11 issues:
  - RemoteRegistry disabled
  - UAC token filtering blocking remote systeminfo

### 🌐 RPC Relay & MITM Mapping
- Integrate detection of NTLM-authenticating RPC interfaces
- Output if services are susceptible to:
  - Responder relay
  - mitm6/NTLMv1 relay
- Future: simulate challenge flow to assess relayability


