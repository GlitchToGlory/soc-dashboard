// Static reference data for the Reference page.

export const WIN_EVENTS = [
  ["4624", "Security", "Successful logon (check Logon Type: 2 interactive, 3 network, 10 RDP)"],
  ["4625", "Security", "Failed logon – brute force / password spray indicator"],
  ["4634 / 4647", "Security", "Logoff / user-initiated logoff"],
  ["4648", "Security", "Logon with explicit credentials (runas, lateral movement)"],
  ["4672", "Security", "Special privileges assigned to new logon (admin-equivalent)"],
  ["4688", "Security", "New process created (needs command-line auditing for full value)"],
  ["4697 / 7045", "Security / System", "Service installed – common persistence / PsExec"],
  ["4698 / 4699 / 4702", "Security", "Scheduled task created / deleted / updated"],
  ["4720", "Security", "User account created"],
  ["4722 / 4725", "Security", "User account enabled / disabled"],
  ["4723 / 4724", "Security", "Password change attempt / reset by another account"],
  ["4728 / 4732 / 4756", "Security", "Member added to global / local / universal security group"],
  ["4740", "Security", "Account locked out"],
  ["4768 / 4769 / 4771", "Security", "Kerberos TGT request / service ticket request / pre-auth failed (Kerberoasting: 4769 with RC4)"],
  ["4776", "Security", "NTLM credential validation by a domain controller"],
  ["1102 / 104", "Security / System", "Audit log cleared – defence evasion"],
  ["4103 / 4104", "PowerShell/Operational", "PowerShell module / script block logging"],
  ["1 / 3 / 11", "Sysmon", "Process create / network connection / file create"],
  ["5140 / 5145", "Security", "Network share accessed / share object access check"],
  ["4663", "Security", "Object access attempt (file auditing)"],
];

export const LINK_GROUPS = [
  ["MITRE & frameworks", [
    ["MITRE ATT&CK", "https://attack.mitre.org/"], ["ATT&CK Navigator", "https://mitre-attack.github.io/attack-navigator/"],
    ["MITRE D3FEND (defensive techniques)", "https://d3fend.mitre.org/"], ["CVE.org (CVE records)", "https://www.cve.org/"],
    ["CWE (weakness types)", "https://cwe.mitre.org/"], ["NIST NVD", "https://nvd.nist.gov/"], ["FIRST – CVSS", "https://www.first.org/cvss/"],
  ]],
  ["Vulnerabilities & exploitation", [
    ["CISA KEV Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"], ["EPSS (FIRST)", "https://www.first.org/epss/"],
    ["Microsoft Security Update Guide", "https://msrc.microsoft.com/update-guide"], ["Exploit-DB", "https://www.exploit-db.com/"],
    ["CIRCL Vulnerability-Lookup", "https://vulnerability.circl.lu/"],
  ]],
  ["Reputation & threat intel", [
    ["VirusTotal", "https://www.virustotal.com/"], ["AbuseIPDB", "https://www.abuseipdb.com/"], ["AlienVault OTX", "https://otx.alienvault.com/"],
    ["Cisco Talos Intelligence", "https://talosintelligence.com/"], ["GreyNoise", "https://viz.greynoise.io/"], ["Shodan", "https://www.shodan.io/"],
    ["Censys", "https://search.censys.io/"], ["URLhaus (abuse.ch)", "https://urlhaus.abuse.ch/"], ["MalwareBazaar (abuse.ch)", "https://bazaar.abuse.ch/"],
    ["ThreatFox (abuse.ch)", "https://threatfox.abuse.ch/"], ["Have I Been Pwned", "https://haveibeenpwned.com/"],
  ]],
  ["Sandboxes & URL analysis", [
    ["urlscan.io", "https://urlscan.io/"], ["ANY.RUN", "https://any.run/"], ["Hybrid Analysis", "https://www.hybrid-analysis.com/"], ["Joe Sandbox", "https://www.joesandbox.com/"],
  ]],
  ["DNS, certificates & email", [
    ["MXToolbox (headers, DNS, blacklists)", "https://mxtoolbox.com/"], ["crt.sh (certificate transparency)", "https://crt.sh/"],
    ["DNSDumpster", "https://dnsdumpster.com/"], ["ICANN lookup (WHOIS / RDAP)", "https://lookup.icann.org/"],
  ]],
  ["Detection engineering & hunting", [
    ["Sigma rules", "https://github.com/SigmaHQ/sigma"], ["LOLBAS (Windows living-off-the-land)", "https://lolbas-project.github.io/"],
    ["GTFOBins (Linux)", "https://gtfobins.github.io/"], ["LOLDrivers", "https://www.loldrivers.io/"],
    ["Atomic Red Team", "https://github.com/redcanaryco/atomic-red-team"], ["CyberChef", "https://gchq.github.io/CyberChef/"],
    ["KQL language reference", "https://learn.microsoft.com/en-us/kusto/query/"],
  ]],
  ["Microsoft security portals", [
    ["Microsoft Defender portal", "https://security.microsoft.com/"], ["Microsoft Entra admin centre", "https://entra.microsoft.com/"],
    ["Azure portal (Sentinel)", "https://portal.azure.com/"], ["Microsoft Purview", "https://purview.microsoft.com/"],
    ["Microsoft Threat Intelligence blog", "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/"],
  ]],
  ["Security news (open in a new tab)", [
    ["BleepingComputer", "https://www.bleepingcomputer.com/"], ["The Hacker News", "https://thehackernews.com/"], ["Krebs on Security", "https://krebsonsecurity.com/"],
    ["SecurityWeek", "https://www.securityweek.com/"], ["Dark Reading", "https://www.darkreading.com/"], ["SANS ISC Diary", "https://isc.sans.edu/"],
    ["CISA advisories", "https://www.cisa.gov/news-events/cybersecurity-advisories"], ["NCSC UK – news", "https://www.ncsc.gov.uk/section/keep-up-to-date/ncsc-news"],
    ["Microsoft Security blog", "https://www.microsoft.com/en-us/security/blog/"],
  ]],
  ["UK & government guidance", [
    ["NCSC (UK)", "https://www.ncsc.gov.uk/"], ["CISA (US)", "https://www.cisa.gov/"],
    ["ICO – reporting a personal data breach (UK)", "https://ico.org.uk/for-organisations/report-a-breach/"], ["Action Fraud / report cyber crime (UK)", "https://www.actionfraud.police.uk/"],
  ]],
];

export const PORTS = [
  ["20/21", "TCP", "FTP", "Cleartext credentials; data exfil / staging"], ["22", "TCP", "SSH", "Brute force, lateral movement, tunnelling"],
  ["23", "TCP", "Telnet", "Cleartext – should not be exposed"], ["25", "TCP", "SMTP", "Mail relay; spam / phishing sources"],
  ["53", "TCP/UDP", "DNS", "DNS tunnelling / exfil, C2 over DNS"], ["67/68", "UDP", "DHCP", "Rogue DHCP servers"],
  ["69", "UDP", "TFTP", "Unauthenticated file transfer"], ["80 / 443", "TCP", "HTTP / HTTPS", "Most C2 and exfil hides here"],
  ["88", "TCP/UDP", "Kerberos", "Kerberoasting, AS-REP roasting, golden tickets"], ["110 / 143 / 993 / 995", "TCP", "POP3 / IMAP (+TLS)", "Mailbox access, brute force"],
  ["123", "UDP", "NTP", "Amplification / DDoS reflection"], ["135", "TCP", "MS-RPC", "Lateral movement (DCOM, WMI)"],
  ["137-139", "TCP/UDP", "NetBIOS", "Legacy name resolution; poisoning (LLMNR/NBT-NS)"], ["161/162", "UDP", "SNMP", "Default community strings"],
  ["389 / 636", "TCP", "LDAP / LDAPS", "AD enumeration, credential relay"], ["445", "TCP", "SMB", "Ransomware spread, lateral movement, EternalBlue-class bugs"],
  ["587 / 465", "TCP", "SMTP submission", "Authenticated mail sending – compromised accounts"], ["1433", "TCP", "Microsoft SQL Server", "Brute force, xp_cmdshell abuse"],
  ["3268 / 3269", "TCP", "AD Global Catalog", "AD enumeration"], ["3306", "TCP", "MySQL", "Should not be internet-facing"],
  ["3389", "TCP", "RDP", "Brute force, ransomware entry point"], ["4444", "TCP", "Metasploit default handler", "Common (default) reverse-shell port"],
  ["5432", "TCP", "PostgreSQL", "Should not be internet-facing"], ["5900", "TCP", "VNC", "Weak/no authentication"],
  ["5985 / 5986", "TCP", "WinRM (HTTP / HTTPS)", "Remote PowerShell lateral movement"], ["6379", "TCP", "Redis", "Often unauthenticated"],
  ["8080 / 8443", "TCP", "Alt HTTP / HTTPS", "Proxies, admin panels, C2"], ["9200", "TCP", "Elasticsearch", "Exposed indices / data leaks"],
  ["27017", "TCP", "MongoDB", "Exposed databases"],
];

export const COMMANDS = [
  ["Windows", "Network connections with owning process", "Get-NetTCPConnection -State Established | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,@{n='Process';e={(Get-Process -Id $_.OwningProcess).Name}}"],
  ["Windows", "Listening ports (classic)", "netstat -ano | findstr LISTENING"],
  ["Windows", "Running processes with command line", "Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine"],
  ["Windows", "Scheduled tasks (persistence)", "Get-ScheduledTask | Where State -ne 'Disabled' | Select TaskName,TaskPath,@{n='Action';e={$_.Actions.Execute}}"],
  ["Windows", "Auto-run registry keys", "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run & reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
  ["Windows", "Services set to auto-start", "Get-CimInstance Win32_Service | Where StartMode -eq 'Auto' | Select Name,State,PathName"],
  ["Windows", "Local administrators", "Get-LocalGroupMember -Group 'Administrators'"],
  ["Windows", "Recent failed logons (4625)", "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 50 | Select TimeCreated,Message"],
  ["Windows", "DNS cache", "Get-DnsClientCache | Select Entry,Data"],
  ["Windows", "File hash", "Get-FileHash -Algorithm SHA256 .\\file.exe"],
  ["Windows", "Check a file's signature", "Get-AuthenticodeSignature .\\file.exe | Select Status,SignerCertificate"],
  ["Linux", "Listening sockets with process", "ss -tulpn"], ["Linux", "Process tree", "ps auxf"],
  ["Linux", "Recent logins / failed logins", "last -a | head -30 ; sudo lastb | head -30"],
  ["Linux", "SSH auth failures (Debian/Ubuntu)", "grep 'Failed password' /var/log/auth.log | tail -50"],
  ["Linux", "Cron persistence", "crontab -l ; ls -la /etc/cron* /var/spool/cron 2>/dev/null"],
  ["Linux", "Recently modified files", "find / -xdev -type f -mtime -1 2>/dev/null | head -100"], ["Linux", "File hash", "sha256sum ./file"],
  ["Linux", "Systemd units changed recently", "systemctl list-unit-files --state=enabled ; find /etc/systemd /lib/systemd -mtime -7 -type f"],
];

export const FRAMEWORKS = {
  tlp: [
    ["TLP:RED", "Not for disclosure – restricted to named recipients only."],
    ["TLP:AMBER+STRICT", "Restricted to the recipient's organisation only."],
    ["TLP:AMBER", "Restricted to the recipient's organisation and its clients, on a need-to-know basis."],
    ["TLP:GREEN", "Can be shared within the community, but not publicly."],
    ["TLP:CLEAR", "No restriction – may be shared publicly (subject to copyright)."],
  ],
  killchain: [
    ["1. Reconnaissance", "Research and target selection"], ["2. Weaponisation", "Build the payload / exploit"], ["3. Delivery", "Email, web, USB, supply chain"],
    ["4. Exploitation", "Trigger the vulnerability or user action"], ["5. Installation", "Persistence / implant"], ["6. Command & control", "Remote control channel"],
    ["7. Actions on objectives", "Theft, destruction, ransom, lateral movement"],
  ],
  pyramid: [
    ["TTPs", "Tough!", "Hardest for the attacker to change – detect behaviour"], ["Tools", "Challenging", "Attacker must find or build new tooling"],
    ["Network / host artefacts", "Annoying", "User-agents, registry keys, mutexes, file paths"], ["Domain names", "Simple", "Cheap to register new ones"],
    ["IP addresses", "Easy", "Trivial to change"], ["Hash values", "Trivial", "Change one byte, new hash"],
  ],
  severity: [
    ["Critical (P1)", "Confirmed compromise, active attacker, ransomware, data theft, or exploitation of a critical internet-facing system", "Escalate to IR immediately, 24/7"],
    ["High (P2)", "Likely malicious activity or successful phishing / credential compromise; no evidence of spread yet", "Respond within the hour"],
    ["Medium (P3)", "Suspicious activity needing investigation; contained single host; blocked attack", "Same working day"],
    ["Low (P4)", "Informational, policy violation, noisy detection, blocked commodity spam", "Backlog / tuning"],
  ],
  cvss: [["None", "0.0"], ["Low", "0.1 – 3.9"], ["Medium", "4.0 – 6.9"], ["High", "7.0 – 8.9"], ["Critical", "9.0 – 10.0"]],
};
