# MITRE ATT&CK Mapping

This document provides a comprehensive mapping of detection rules to the MITRE ATT&CK framework.

---

## Coverage Summary

| Tactic | Techniques Covered | Rules | Detection Methods |
|--------|-------------------|-------|-------------------|
| TA0043 Reconnaissance | 3 | 3 | Sigma + ML |
| TA0001 Initial Access | 5 | 5 | Sigma + ML + YARA |
| TA0002 Execution | 5 | 5 | Sigma + ML |
| TA0003 Persistence | 6 | 6 | Sigma + ML |
| TA0004 Privilege Escalation | 4 | 4 | Sigma + ML |
| TA0005 Defense Evasion | 5 | 5 | Sigma + YARA |
| TA0006 Credential Access | 4 | 4 | Sigma + ML |
| TA0007 Discovery | 4 | 4 | Sigma + ML |
| TA0008 Lateral Movement | 4 | 4 | Sigma + ML |
| TA0009 Collection | 3 | 3 | Sigma + ML |
| TA0010 Exfiltration | 3 | 3 | Sigma + ML |
| TA0011 Command & Control | 3 | 3 | Sigma + ML + YARA |
| TA0040 Impact | 2 | 2 | Sigma + YARA |
| **Total** | **51** | **51** | |

---

## Detailed Rule Mapping

### TA0043 Reconnaissance

| Rule ID | Rule Name | Technique ID | Technique Name | Severity | Detection Method | False Positive Level |
|---------|-----------|--------------|----------------|----------|------------------|---------------------|
| SIGMA-001 | Active Port Scanning | T1595 | Active Scanning | High | Sigma + ML | Medium |
| SIGMA-002 | Host Enumeration | T1592 | Gather Victim Host Information | Medium | Sigma | Low |
| SIGMA-003 | Identity Harvesting | T1589 | Gather Victim Identity Information | Medium | Sigma | Low |

**Detection Logic:**
- **T1595 Active Scanning**: Detects high-rate connection attempts to multiple ports on single/multiple hosts within short time window
- **T1592 Host Enumeration**: Identifies enumeration of system information, installed software, or hardware
- **T1589 Identity Harvesting**: Detects LDAP queries, email harvesting, or credential collection attempts

---

### TA0001 Initial Access

| Rule ID | Rule Name | Technique ID | Technique Name | Severity | Detection Method | False Positive Level |
|---------|-----------|--------------|----------------|----------|------------------|---------------------|
| SIGMA-004 | Exploit Public-Facing App | T1190 | Exploit Public-Facing Application | Critical | Sigma + ML | Low |
| SIGMA-005 | External Remote Services | T1133 | External Remote Services | High | Sigma | Medium |
| SIGMA-006 | Phishing Attachment | T1566.001 | Phishing: Spearphishing Attachment | Critical | Sigma + YARA | Low |
| SIGMA-007 | Phishing Link | T1566.002 | Phishing: Spearphishing Link | High | Sigma | Medium |
| SIGMA-008 | Trusted Relationship | T1199 | Trusted Relationship | High | Sigma + ML | Medium |

**Detection Logic:**
- **T1190 Exploit Public-Facing App**: Monitors web server logs for injection attempts, abnormal request patterns, and exploitation indicators
- **T1133 External Remote Services**: Tracks VPN, SSH, and RDP authentication from external IPs
- **T1566.001 Phishing Attachment**: Scans email attachments with YARA rules for malicious content
- **T1566.002 Phishing Link**: Detects URL patterns associated with phishing campaigns
- **T1199 Trusted Relationship**: Monitors for abuse of trusted third-party access

---

### TA0002 Execution

| Rule ID | Rule Name | Technique ID | Technique Name | Severity | Detection Method | False Positive Level |
|---------|-----------|--------------|----------------|----------|------------------|---------------------|
| SIGMA-009 | Command Interpreter | T1059 | Command and Scripting Interpreter | High | Sigma + ML | Medium |
| SIGMA-010 | PowerShell Execution | T1059.001 | PowerShell | High | Sigma | Medium |
| SIGMA-011 | Bash Execution | T1059.004 | Unix Shell | Medium | Sigma | High |
| SIGMA-012 | Client Execution | T1203 | Exploitation for Client Execution | Critical | Sigma + ML | Low |
| SIGMA-013 | WMI Execution | T1047 | Windows Management Instrumentation | High | Sigma | Low |

**Detection Logic:**
- **T1059 Command Interpreter**: Detects suspicious command execution patterns, encoded commands, and unusual parent-child process relationships
- **T1059.001 PowerShell**: Monitors for encoded PowerShell, download cradles, and AMSI bypass attempts
- **T1059.004 Unix Shell**: Tracks unusual shell execution, reverse shells, and terminal spawning
- **T1203 Exploitation for Client Execution**: Identifies exploitation of client-side vulnerabilities
- **T1047 WMI**: Detects WMI-based execution for lateral movement and persistence

---

### TA0003 Persistence

| Rule ID | Rule Name | Technique ID | Technique Name | Severity | Detection Method | False Positive Level |
|---------|-----------|--------------|----------------|----------|------------------|---------------------|
| SIGMA-014 | Scheduled Task | T1053.005 | Scheduled Task | High | Sigma + ML | Medium |
| SIGMA-015 | System Process | T1543 | Create or Modify System Process | High | Sigma | Low |
| SIGMA-016 | Registry Run Keys | T1547.001 | Boot or Logon Autostart: Registry Run Keys | High | Sigma | Medium |
| SIGMA-017 | Create Account | T1136 | Create Account | High | Sigma + ML | Low |
| SIGMA-018 | Systemd Service | T1543.002 | Systemd Service | Medium | Sigma | Low |
| SIGMA-019 | Startup Folder | T1547.001 | Startup Folder Items | Medium | Sigma | Medium |

**Detection Logic:**
- **T1053.005 Scheduled Task**: Monitors creation and modification of scheduled tasks
- **T1543 System Process**: Detects creation of new system services
- **T1547.001 Registry Run Keys**: Tracks modifications to autostart registry locations
- **T1136 Create Account**: Identifies new user account creation
- **T1543.002 Systemd Service**: Detects new systemd service installation
- **T1547.001 Startup Folder**: Monitors startup folder modifications

---

### TA0004 Privilege Escalation

| Rule ID | Rule Name | Technique ID | Technique Name | Severity | Detection Method | False Positive Level |
|---------|-----------|--------------|----------------|----------|------------------|---------------------|
| SIGMA-020 | Abuse Elevation | T1548 | Abuse Elevation Control Mechanism | Critical | Sigma + ML | Low |
| SIGMA-021 | Exploitation | T1068 | Exploitation for Privilege Escalation | Critical | Sigma + ML | Low |
| SIGMA-022 | Token Manipulation | T1134 | Access Token Manipulation | High | Sigma | Low |
| SIGMA-023 | Sudo Abuse | T1548.003 | Sudo and Sudo Caching | High | Sigma | Medium |

**Detection Logic:**
- **T1548 Abuse Elevation**: Detects UAC bypass, sudo abuse, and elevation mechanism exploitation
- **T1068 Exploitation**: Identifies privilege escalation exploits in process context
- **T1134 Token Manipulation**: Monitors for token theft and impersonation
- **T1548.003 Sudo Abuse**: Detects unusual sudo usage patterns and sudo cache manipulation

---

### TA0005 Defense Evasion

| Rule ID | Rule Name | Technique ID | Technique Name | Severity | Detection Method | False Positive Level |
|---------|-----------|--------------|----------------|----------|------------------|---------------------|
| SIGMA-024 | Log Deletion | T1070.001 | Clear Windows Event Logs | Critical | Sigma + ML | Low |
| SIGMA-025 | Obfuscated Files | T1027 | Obfuscated Files or Information | High | Sigma + YARA | Low |
| SIGMA-026 | Masquerading | T1036 | Masquerading | High | Sigma | Medium |
| SIGMA-027 | Disable Security | T1562.001 | Impair Defenses: Disable or Modify Tools | Critical | Sigma + ML | Low |
| SIGMA-028 | Deobfuscation | T1140 | Deobfuscate/Decode Files | Medium | Sigma | Medium |

**Detection Logic:**
- **T1070.001 Log Deletion**: Detects clearing of Windows event logs
- **T1027 Obfuscated Files**: Identifies packed or obfuscated executables
- **T1036 Masquerading**: Detects process name and path manipulation
- **T1562.001 Disable Security**: Monitors for disabling of security tools
- **T1140 Deobfuscation**: Identifies runtime deobfuscation activities

---

### TA0006 Credential Access

| Rule ID | Rule Name | Technique ID | Technique Name | Severity | Detection Method | False Positive Level |
|---------|-----------|--------------|----------------|----------|------------------|---------------------|
| SIGMA-029 | Brute Force | T1110 | Brute Force | Critical | Sigma + ML | Low |
| SIGMA-030 | Credential Dumping | T1003 | OS Credential Dumping | Critical | Sigma + ML | Low |
| SIGMA-031 | Kerberoasting | T1558.003 | Steal or Forge Kerberos Tickets | High | Sigma | Low |
| SIGMA-032 | Credential Stores | T1555 | Credentials from Password Stores | High | Sigma | Medium |

**Detection Logic:**
- **T1110 Brute Force**: Detects high-rate failed authentication attempts
- **T1003 Credential Dumping**: Identifies LSASS access, SAM database extraction
- **T1558.003 Kerberoasting**: Detects unusual Kerberos service ticket requests
- **T1555 Credential Stores**: Monitors access to password stores and credential files

---

### TA0007 Discovery

| Rule ID | Rule Name | Technique ID | Technique Name | Severity | Detection Method | False Positive Level |
|---------|-----------|--------------|----------------|----------|------------------|---------------------|
| SIGMA-033 | Network Scanning | T1046 | Network Service Scanning | Medium | Sigma + ML | Medium |
| SIGMA-034 | Account Discovery | T1087 | Account Discovery | Medium | Sigma | Medium |
| SIGMA-035 | Remote System | T1018 | Remote System Discovery | Medium | Sigma | Low |
| SIGMA-036 | System Info | T1082 | System Information Discovery | Low | Sigma | High |

**Detection Logic:**
- **T1046 Network Scanning**: Detects network enumeration and port scanning
- **T1087 Account Discovery**: Identifies user and group enumeration
- **T1018 Remote System Discovery**: Monitors for host discovery activities
- **T1082 System Information Discovery**: Tracks system information gathering

---

### TA0008 Lateral Movement

| Rule ID | Rule Name | Technique ID | Technique Name | Severity | Detection Method | False Positive Level |
|---------|-----------|--------------|----------------|----------|------------------|---------------------|
| SIGMA-037 | Remote Services | T1021 | Remote Services | High | Sigma + ML | Medium |
| SIGMA-038 | Tool Transfer | T1570 | Lateral Tool Transfer | High | Sigma | Low |
| SIGMA-039 | Alternate Auth | T1550 | Use Alternate Authentication Material | High | Sigma + ML | Low |
| SIGMA-040 | SMB Lateral | T1021.002 | SMB/Windows Admin Shares | High | Sigma | Medium |

**Detection Logic:**
- **T1021 Remote Services**: Detects lateral movement via RDP, SSH, WinRM
- **T1570 Tool Transfer**: Identifies file transfer activities between systems
- **T1550 Alternate Auth**: Monitors for use of pass-the-hash, pass-the-ticket
- **T1021.002 SMB Lateral**: Tracks SMB-based lateral movement

---

### TA0009 Collection

| Rule ID | Rule Name | Technique ID | Technique Name | Severity | Detection Method | False Positive Level |
|---------|-----------|--------------|----------------|----------|------------------|---------------------|
| SIGMA-041 | Local Data | T1005 | Data from Local System | High | Sigma + ML | Medium |
| SIGMA-042 | Email Collection | T1114 | Email Collection | High | Sigma | Low |
| SIGMA-043 | Input Capture | T1056 | Input Capture | Critical | Sigma + ML | Low |

**Detection Logic:**
- **T1005 Local Data**: Detects mass file access or collection
- **T1114 Email Collection**: Monitors for email access and exfiltration
- **T1056 Input Capture**: Identifies keylogger and screenshot capture activities

---

### TA0010 Exfiltration

| Rule ID | Rule Name | Technique ID | Technique Name | Severity | Detection Method | False Positive Level |
|---------|-----------|--------------|----------------|----------|------------------|---------------------|
| SIGMA-044 | Alt Protocol | T1048 | Exfiltration Over Alternative Protocol | Critical | Sigma + ML | Low |
| SIGMA-045 | C2 Channel | T1041 | Exfiltration Over C2 Channel | High | Sigma | Low |
| SIGMA-046 | Web Service | T1567 | Exfiltration Over Web Service | High | Sigma | Medium |

**Detection Logic:**
- **T1048 Alt Protocol**: Detects data exfiltration over DNS, ICMP, or custom protocols
- **T1041 C2 Channel**: Identifies exfiltration within C2 traffic
- **T1567 Web Service**: Monitors for uploads to cloud storage and paste sites

---

### TA0011 Command & Control

| Rule ID | Rule Name | Technique ID | Technique Name | Severity | Detection Method | False Positive Level |
|---------|-----------|--------------|----------------|----------|------------------|---------------------|
| SIGMA-047 | App Layer Protocol | T1071 | Application Layer Protocol | High | Sigma + ML | Medium |
| SIGMA-048 | Tool Transfer | T1105 | Ingress Tool Transfer | High | Sigma + YARA | Low |
| SIGMA-049 | Protocol Tunnel | T1572 | Protocol Tunneling | High | Sigma | Low |

**YARA-001-005**: Trojan C2 beacon patterns
**YARA-006-009**: Backdoor C2 communication

**Detection Logic:**
- **T1071 App Layer Protocol**: Detects C2 over HTTP, HTTPS, DNS
- **T1105 Tool Transfer**: Identifies tool downloads and staging
- **T1572 Protocol Tunnel**: Monitors for tunneling and encapsulation

---

### TA0040 Impact

| Rule ID | Rule Name | Technique ID | Technique Name | Severity | Detection Method | False Positive Level |
|---------|-----------|--------------|----------------|----------|------------------|---------------------|
| SIGMA-050 | Data Encrypted | T1486 | Data Encrypted for Impact | Critical | Sigma + YARA | Low |
| SIGMA-051 | Endpoint DoS | T1499 | Endpoint Denial of Service | High | Sigma | Medium |

**YARA-010-014**: Ransomware detection rules

**Detection Logic:**
- **T1486 Data Encrypted**: Detects ransomware encryption patterns
- **T1499 Endpoint DoS**: Identifies resource exhaustion attacks

---

## YARA Rule Mapping

### Ransomware Detection

| Rule ID | Rule Name | MITRE Technique | Detection Method | Confidence |
|---------|-----------|-----------------|------------------|------------|
| YARA-010 | Ransomware Extensions | T1486 | File extension matching | High |
| YARA-011 | Ransomware Note | T1486 | Ransom note string matching | High |
| YARA-012 | Ransomware Encryption | T1486 | Encryption pattern detection | Medium |
| YARA-013 | Lockbit Patterns | T1486 | Lockbit-specific indicators | High |
| YARA-014 | Ryuk Patterns | T1486 | Ryuk-specific indicators | High |

### Trojan Detection

| Rule ID | Rule Name | MITRE Technique | Detection Method | Confidence |
|---------|-----------|-----------------|------------------|------------|
| YARA-001 | Trojan C2 Beacon | T1071 | Beacon pattern matching | High |
| YARA-002 | Trojan Persistence | T1547 | Persistence mechanism detection | High |
| YARA-003 | Trojan Lateral Move | T1021 | Lateral movement code | Medium |
| YARA-004 | Trojan Registry Mod | T1547 | Registry modification code | High |
| YARA-005 | Trojan Screenshot | T1056 | Screenshot capture code | Medium |

### Backdoor Detection

| Rule ID | Rule Name | MITRE Technique | Detection Method | Confidence |
|---------|-----------|-----------------|------------------|------------|
| YARA-006 | Reverse Shell | T1059 | Reverse shell code patterns | High |
| YARA-007 | SSH Backdoor | T1059 | SSH persistence code | High |
| YARA-008 | Cron Backdoor | T1053 | Cron job persistence | High |
| YARA-009 | Systemd Backdoor | T1543 | Systemd service persistence | High |

### Webshell Detection

| Rule ID | Rule Name | MITRE Technique | Detection Method | Confidence |
|---------|-----------|-----------------|------------------|------------|
| YARA-015 | PHP Webshell | T1505.003 | PHP shell code patterns | High |
| YARA-016 | ASP Webshell | T1505.003 | ASP shell code patterns | High |
| YARA-017 | JSP Webshell | T1505.003 | JSP shell code patterns | High |

### Cryptominer Detection

| Rule ID | Rule Name | MITRE Technique | Detection Method | Confidence |
|---------|-----------|-----------------|------------------|------------|
| YARA-018 | XMR Miner | T1496 | XMRig patterns | High |
| YARA-019 | Mining Pool | T1496 | Mining pool connection code | Medium |
| YARA-020 | High CPU Usage | T1496 | CPU-intensive patterns | Medium |

---

## Detection Coverage Matrix

```
                    ┌─────────────────────────────────────────────────────────────┐
                    │                    MITRE ATT&CK COVERAGE                   │
                    ├─────────────────────────────────────────────────────────────┤
                    │ Sigma │ YARA │ ML  │ Combined │ Coverage │
┌───────────────────┼───────┼──────┼─────┼──────────┼──────────┤
│ TA0043 Recon      │   3   │  0   │  2  │ Sigma+ML │   100%   │
│ TA0001 Initial    │   5   │  1   │  3  │ S+Y+M    │   100%   │
│ TA0002 Execution  │   5   │  0   │  3  │ Sigma+ML │   100%   │
│ TA0003 Persist    │   6   │  0   │  2  │ Sigma+ML │   100%   │
│ TA0004 Priv Esc   │   4   │  0   │  3  │ Sigma+ML │   100%   │
│ TA0005 Evasion    │   5   │  1   │  3  │ S+Y+M    │   100%   │
│ TA0006 Cred Access│   4   │  0   │  3  │ Sigma+ML │   100%   │
│ TA0007 Discovery  │   4   │  0   │  2  │ Sigma+ML │   100%   │
│ TA0008 Lateral    │   4   │  0   │  2  │ Sigma+ML │   100%   │
│ TA0009 Collection │   3   │  0   │  2  │ Sigma+ML │   100%   │
│ TA0010 Exfil      │   3   │  0   │  2  │ Sigma+ML │   100%   │
│ TA0011 C2         │   3   │  4   │  2  │ S+Y+M    │   100%   │
│ TA0040 Impact     │   2   │  5   │  0  │ Sigma+Y  │   100%   │
├───────────────────┼───────┼──────┼─────┼──────────┼──────────┤
│ TOTAL             │  51   │  11  │ 30  │          │   100%   │
└───────────────────┴───────┴──────┴─────┴──────────┴──────────┘
```

---

## Rule Severity Distribution

| Severity | Sigma Rules | YARA Rules | Total | Percentage |
|----------|-------------|------------|-------|------------|
| Critical | 12 | 9 | 21 | 30% |
| High | 31 | 7 | 38 | 53% |
| Medium | 7 | 3 | 10 | 14% |
| Low | 1 | 1 | 2 | 3% |
| **Total** | **51** | **20** | **71** | **100%** |

---

## Detection Method Distribution

| Detection Method | Rules | Percentage |
|------------------|-------|------------|
| Sigma Only | 25 | 35% |
| Sigma + ML | 20 | 28% |
| Sigma + YARA | 5 | 7% |
| Sigma + ML + YARA | 6 | 8% |
| YARA Only | 5 | 7% |
| ML Only | 0 | 0% |
| **Total** | **61** | **100%** |

---

## Coverage Gaps and Future Improvements

### Current Gaps

| Tactic | Gap | Impact | Mitigation |
|--------|-----|--------|------------|
| TA0002 | T1059.002 AppleScript | Low | Not applicable (Linux/Windows only) |
| TA0003 | T1543.003 Windows Service | Medium | Add Windows service detection |
| TA0005 | T1027.002 Software Packing | Medium | Add PE header analysis |
| TA0006 | T1003.003 NTDS | Low | Add AD-specific detection |
| TA0007 | T1083 File and Directory | Medium | Add file enumeration detection |
| TA0009 | T1057 Process Discovery | Medium | Add process enumeration detection |
| TA0011 | T1105 Ingress Tool Transfer | Low | Add download detection |

### Planned Improvements

1. **Add Sysmon Integration**: Enhanced Windows process and network monitoring
2. **Add Suricata IDS**: Network-based threat detection
3. **Add Zeek Network Monitor**: Network traffic analysis
4. **Enhanced ML Features**: Add network flow features
5. **Automated Rule Updates**: Sigma rule version management

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [YARA Documentation](https://virustotal.github.io/yara/)
- [ELK Stack Documentation](https://www.elastic.co/guide/)
- [XGBoost Documentation](https://xgboost.readthedocs.io/)
