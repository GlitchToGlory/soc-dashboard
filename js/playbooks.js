// Interactive checklists. Progress is saved in the browser. Adapt the steps to your own runbooks.

export const PLAYBOOKS = [
  { id: "phishing", title: "Phishing email", blurb: "Reported or detected phishing message.",
    phases: [
      ["Triage", ["Get the original message (.eml / headers) – not a forward", "Check SPF / DKIM / DMARC and From vs Return-Path vs Reply-To (Toolkit → Email header analyser)", "Extract and defang URLs, attachments and sender (Toolkit → IOC extractor)", "Detonate URLs / attachments in a sandbox – never on your own workstation", "Decide: malicious, suspicious, spam or legitimate"]],
      ["Scope", ["Search for the same sender, subject, URL and attachment hash across all mailboxes", "List recipients and who opened / clicked / replied", "Check sign-ins and inbox rules for anyone who clicked or entered credentials"]],
      ["Contain", ["Purge / quarantine the message from all mailboxes", "Block sender, domain and URLs (email gateway, proxy, DNS)", "Reset passwords and revoke sessions for affected users", "Isolate any device that ran an attachment"]],
      ["Close out", ["Add IOCs to blocklists / threat intel platform", "Tell the reporter the outcome", "Record verdict, scope and actions in the ticket", "Consider a user-awareness note or detection improvement"]],
    ] },
  { id: "account", title: "Compromised account", blurb: "Credential theft, MFA fatigue, session hijack, impossible travel.",
    phases: [
      ["Validate", ["Review sign-in logs: IPs, locations, devices, apps, MFA results", "Contact the user out-of-band – did they do this?", "Check for new MFA methods, devices, OAuth consents"]],
      ["Contain", ["Disable sign-in or force password reset", "Revoke all refresh tokens / sessions", "Remove attacker MFA methods and consents", "Delete malicious inbox rules and forwarding"]],
      ["Investigate", ["What did the attacker access (mail, files, apps)?", "Did they send mail from the account (internal phishing)?", "How was the credential obtained (phish, reuse, spray, malware)?", "Check other accounts hit from the same IPs"]],
      ["Recover & close", ["Restore access with a strong, unique password and re-registered MFA", "Block attacker IPs / add to watchlist", "Notify data owners / DPO if data was accessed", "Document timeline and lessons learned"]],
    ] },
  { id: "malware", title: "Malware / EDR detection", blurb: "Endpoint alert for malicious file, process or behaviour.",
    phases: [
      ["Triage", ["Read the alert: rule, severity, process tree and command line", "Is it a known tool / admin activity / test? Check change records", "Check file hash and signer reputation (VirusTotal, internal intel)"]],
      ["Contain", ["Isolate the host from the network (keep it powered on)", "Kill process / quarantine file via EDR", "Disable the user account if credentials may be exposed"]],
      ["Scope", ["Search for the same hash, file name, command line and C2 across the estate", "Find the initial access vector (email, download, USB, exploit)", "Check persistence: run keys, scheduled tasks, services, startup items, WMI"]],
      ["Eradicate & recover", ["Remove artefacts or reimage the host", "Reset credentials used on the host", "Block IOCs (hash, IP, domain) and monitor for re-infection", "Return host to service after validation"]],
    ] },
  { id: "ransomware", title: "Ransomware", blurb: "Encryption, ransom note or mass file changes. Escalate immediately.",
    phases: [
      ["Immediately", ["Declare a major incident and notify the incident lead / management", "Isolate affected hosts and segments – disconnect network, do NOT power off if avoidable (memory evidence)", "Disable compromised accounts; protect backups (offline / immutable) and domain controllers", "Preserve evidence: ransom note, sample extension, logs, EDR telemetry"]],
      ["Scope", ["Identify patient zero and initial access (phishing, exposed RDP/VPN, exploited vuln)", "Find lateral movement, credential theft and data staging / exfiltration", "List encrypted systems and business impact"]],
      ["Contain & eradicate", ["Block attacker infrastructure and tooling; reset credentials (incl. privileged and service accounts)", "Remove persistence and attacker access", "Patch the entry point"]],
      ["Recover & report", ["Restore from clean backups after validating they are unaffected", "Legal / regulatory / insurer / law-enforcement notifications as required", "Post-incident review and control improvements"]],
    ] },
  { id: "c2", title: "Suspicious outbound traffic / possible C2", blurb: "Beaconing, DNS tunnelling, connections to bad infrastructure.",
    phases: [
      ["Validate", ["Confirm source host, process, destination, port, volume and timing (regular intervals = beaconing)", "Check destination reputation, domain age, certificate, passive DNS", "Check whether it is legitimate software (updates, SaaS, backup)"]],
      ["Contain", ["Block destination at firewall / proxy / DNS", "Isolate the host if malicious activity is likely"]],
      ["Investigate", ["Identify the responsible process and its parent", "Collect memory / triage package if needed", "Search the estate for other hosts contacting the same destination"]],
      ["Close out", ["Record IOCs; add detections for the technique used", "Remediate or reimage the host"]],
    ] },
  { id: "kev", title: "Actively exploited vulnerability (KEV)", blurb: "A CVE you run appears in CISA KEV or is being exploited.",
    phases: [
      ["Assess", ["Do we run the affected product / version? (asset inventory, scanner, EDR software list)", "Is it internet-facing or reachable by untrusted users?", "Check vendor advisory for fixes, mitigations and indicators of compromise"]],
      ["Respond", ["Apply the patch or vendor mitigation – prioritise internet-facing systems", "If you can't patch: restrict access, disable the feature, add WAF / IPS rule", "Hunt for exploitation before the patch date (logs, new accounts, web shells, unusual processes)"]],
      ["Communicate", ["Brief IT / system owners with deadline (Templates → Vulnerability advisory brief)", "Track to completion; record exceptions with risk acceptance"]],
    ] },
];
