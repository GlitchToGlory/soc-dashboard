// Analyst templates. Use {{placeholder}} tokens - the Templates page turns each one into a form field.
// Add your own below (or in the browser: "New template" saves to localStorage on this device).

export const TEMPLATES = [
  {
    id: "alert-triage", title: "Alert triage note", group: "Triage",
    desc: "Quick, consistent record of what you looked at and why you closed or escalated.",
    body: `# Alert triage – {{alert_name}}

**Date/time (UTC):** {{date_utc}}
**Analyst:** {{analyst}}
**Alert ID / ticket:** {{ticket_id}}
**Source / detection:** {{detection_source}}

## What fired
{{alert_summary}}

## Affected assets
- Host(s): {{hosts}}
- User(s): {{users}}
- Source IP(s) / destination(s): {{ips}}

## Investigation
- Context checked (asset owner, criticality, recent changes): {{context}}
- Related alerts / prior activity: {{related_activity}}
- Threat intel lookups (IP/domain/hash): {{intel_results}}
- Evidence reviewed (logs, EDR, proxy, email): {{evidence}}

## Verdict
**Classification:** {{verdict}}  (True positive / Benign true positive / False positive / Needs more info)
**Reasoning:** {{reasoning}}

## Action taken
{{actions_taken}}

## Next step
{{next_step}}`,
  },
  {
    id: "phishing-triage", title: "Phishing email triage", group: "Triage",
    desc: "Report on a reported phishing email: headers, URLs, attachments, blast radius, response.",
    body: `# Phishing triage – {{subject}}

**Reported by:** {{reporter}}   **Reported (UTC):** {{date_utc}}
**Analyst:** {{analyst}}   **Ticket:** {{ticket_id}}

## Message details
- From (display / address): {{from_address}}
- Return-Path / Reply-To: {{return_path}}
- Sending IP / relay: {{sending_ip}}
- SPF / DKIM / DMARC result: {{auth_results}}
- Received (UTC): {{received_time}}

## Content analysis
- Lure / pretext: {{lure}}
- URLs (defanged): {{urls}}
- Attachments (name + SHA256): {{attachments}}
- Sandbox / URL scan result: {{sandbox_result}}

## Impact
- Recipients in tenant: {{recipient_count}}
- Users who clicked / opened / submitted credentials: {{interacted_users}}
- Any sign-ins or inbox rules from those users after delivery: {{post_delivery_activity}}

## Verdict
{{verdict}}  (Malicious / Suspicious / Spam / Legitimate)

## Response
- [ ] Message purged from all mailboxes
- [ ] Sender / domain / URL blocked
- [ ] Affected users' passwords reset and sessions revoked
- [ ] IOCs shared with the team
- [ ] Reporter thanked

**Notes:** {{notes}}`,
  },
  {
    id: "edr-malware", title: "Endpoint / malware detection investigation", group: "Triage",
    desc: "Structured notes for an EDR or AV detection on a host.",
    body: `# Endpoint detection – {{host}}

**Date/time (UTC):** {{date_utc}}   **Analyst:** {{analyst}}   **Ticket:** {{ticket_id}}

## Detection
- Product / rule: {{detection_name}}
- Severity: {{severity}}
- Process tree: {{process_tree}}
- Command line: {{command_line}}
- File path / SHA256: {{file_hash}}
- User context: {{user}}

## Scope
- Same hash/behaviour seen elsewhere: {{other_hosts}}
- Parent process / initial access vector: {{initial_access}}
- Network connections (IP/domain, ports): {{network_activity}}
- Persistence mechanisms checked (run keys, scheduled tasks, services): {{persistence}}

## Assessment
{{assessment}}

## Containment & remediation
- [ ] Host isolated
- [ ] Malicious files/processes removed or quarantined
- [ ] Credentials reset for affected user(s)
- [ ] IOCs added to blocklists
- [ ] Host reimaged / returned to service (date: {{return_date}})

**Follow-up:** {{follow_up}}`,
  },
  {
    id: "suspicious-signin", title: "Suspicious sign-in / account compromise", group: "Triage",
    desc: "For impossible travel, MFA fatigue, brute-force or password-spray alerts.",
    body: `# Suspicious sign-in – {{user}}

**Date/time (UTC):** {{date_utc}}   **Analyst:** {{analyst}}   **Ticket:** {{ticket_id}}

## Trigger
{{trigger}}  (e.g. impossible travel, password spray, MFA prompt storm, new device)

## Sign-in evidence
- Source IP(s) / ASN / geo: {{source_ips}}
- User agent / device / app: {{device_info}}
- Result (success / failure / MFA outcome): {{signin_result}}
- Time window reviewed: {{time_window}}
- User confirmed activity? {{user_confirmation}}

## Post-authentication activity
- Mailbox rules / forwarding created: {{mailbox_rules}}
- OAuth consents / new MFA methods: {{persistence_changes}}
- Files / data accessed: {{data_access}}

## Verdict
{{verdict}}

## Actions
- [ ] Password reset
- [ ] Sessions / refresh tokens revoked
- [ ] MFA methods reviewed and re-registered
- [ ] Malicious rules / consents removed
- [ ] Source IP(s) blocked or added to watchlist`,
  },
  {
    id: "vuln-advisory", title: "Vulnerability advisory brief", group: "Vulnerability",
    desc: "Turn a CVE from the dashboard into a short brief for IT / stakeholders. (Use the “Draft brief” button on a CVE.)",
    body: `# Vulnerability brief – {{cve_id}}

**Date (UTC):** {{date_utc}}   **Prepared by:** {{analyst}}

## Summary
{{description}}

## Risk indicators
- CVSS: {{cvss}}
- EPSS (30-day exploitation probability): {{epss}}
- In CISA KEV (known exploited): {{in_kev}}
- Public exploit / PoC: {{public_poc}}

## Are we exposed?
- Affected products/versions: {{affected_products}}
- Where we run them (asset inventory / scan results): {{our_exposure}}
- Internet-facing? {{internet_facing}}

## Recommended action
- Patch / upgrade to: {{fixed_version}}
- Mitigation if patching is delayed: {{mitigation}}
- Detection ideas (logs / signatures to watch): {{detections}}
- Target remediation date: {{target_date}}

## References
- NVD: https://nvd.nist.gov/vuln/detail/{{cve_id}}
- Vendor advisory: {{vendor_link}}`,
  },
  {
    id: "ioc-block-request", title: "IOC block request", group: "Response",
    desc: "Ask network / email / endpoint teams to block indicators, with justification and expiry.",
    body: `Subject: IOC block request – {{reference}}

Hi {{recipient_team}},

Please block the following indicators (defanged below) across {{control_points}}.

**Indicators**
{{indicators}}

**Reason:** {{reason}}
**Confidence:** {{confidence}}
**Related ticket / incident:** {{ticket_id}}
**Requested by:** {{analyst}} on {{date_utc}}
**Review / expiry date:** {{expiry}}

Please reply once implemented, and let me know of any business impact.

Thanks,
{{analyst}}`,
  },
  {
    id: "escalation", title: "Escalation to Incident Response", group: "Response",
    desc: "Everything IR needs in one message so they don't have to ask again.",
    body: `Subject: [{{severity}}] Escalation – {{incident_title}} ({{ticket_id}})

**Raised by:** {{analyst}}   **Time (UTC):** {{date_utc}}

**What happened (3 sentences max):**
{{what_happened}}

**Why I'm escalating:** {{reason_for_escalation}}

**Scope so far**
- Systems: {{systems}}
- Accounts: {{accounts}}
- Data at risk: {{data_at_risk}}

**Containment already done:** {{containment}}
**Evidence location (logs / EDR / PCAP / ticket links):** {{evidence_links}}
**Known unknowns:** {{unknowns}}
**Business owner / contact:** {{business_contact}}

**Needed from IR:** {{ask}}`,
  },
  {
    id: "incident-report", title: "Incident report", group: "Response",
    desc: "Initial or final incident report with timeline, impact and actions.",
    body: `# Incident report – {{incident_title}}

**Incident ID:** {{incident_id}}   **Severity:** {{severity}}   **Status:** {{status}}
**Incident lead:** {{incident_lead}}   **Report date (UTC):** {{date_utc}}   **Author:** {{analyst}}

## Executive summary
{{executive_summary}}

## Timeline (UTC)
| Time | Event | Source |
|---|---|---|
| {{t1}} | {{e1}} | {{s1}} |
| {{t2}} | {{e2}} | {{s2}} |
| {{t3}} | {{e3}} | {{s3}} |

## Root cause / initial access
{{root_cause}}

## Impact
- Systems / accounts: {{impacted_assets}}
- Data: {{impacted_data}}
- Business / customer impact: {{business_impact}}
- Regulatory / notification obligations considered: {{notifications}}

## Containment, eradication, recovery
{{response_actions}}

## Indicators of compromise
{{iocs}}

## Recommendations
{{recommendations}}`,
  },
  {
    id: "shift-handover", title: "Shift handover", group: "Operations",
    desc: "End-of-shift summary so the next analyst can pick up without a call.",
    body: `# SOC shift handover – {{date_utc}}

**Outgoing:** {{analyst}}   **Incoming:** {{incoming_analyst}}   **Shift:** {{shift}}

## Open incidents / investigations
{{open_incidents}}

## Alerts awaiting action
{{pending_alerts}}

## Notable events this shift
{{notable_events}}

## Tuning / false-positive notes
{{tuning_notes}}

## Threat intel / advisories to watch
{{intel_notes}}

## Scheduled changes / maintenance windows
{{changes}}

## Anything else
{{other}}`,
  },
  {
    id: "user-comms-compromise", title: "User message – compromised account", group: "Communication",
    desc: "Clear, calm message to a user whose account needs action.",
    body: `Subject: Action needed – we've secured your account

Hi {{user_first_name}},

Our security team noticed unusual activity on your account ({{account}}) on {{activity_date}}. You haven't done anything wrong, but we've taken precautions to keep you and the company safe.

**What we've done**
- {{actions_done}}

**What we need from you**
1. {{step_one}}
2. Review your recent activity and tell us if anything looks unfamiliar.
3. Do not reuse this password anywhere else.

If you clicked a link or entered your details in a page you didn't recognise, please tell us – it helps us protect everyone, and you won't be in trouble.

You can reach us on {{contact}}.

Thanks,
{{analyst}}
Security Operations`,
  },
  {
    id: "pir", title: "Post-incident review", group: "Operations",
    desc: "Blameless lessons-learned review.",
    body: `# Post-incident review – {{incident_title}} ({{incident_id}})

**Review date (UTC):** {{date_utc}}   **Facilitator:** {{analyst}}   **Attendees:** {{attendees}}

## What happened
{{summary}}

## What went well
{{went_well}}

## What didn't go well
{{went_badly}}

## Detection & response metrics
- Time to detect: {{ttd}}
- Time to triage: {{ttt}}
- Time to contain: {{ttc}}
- Time to recover: {{ttr}}

## Contributing factors (people, process, technology)
{{contributing_factors}}

## Action items
| Action | Owner | Due |
|---|---|---|
| {{a1}} | {{o1}} | {{d1}} |
| {{a2}} | {{o2}} | {{d2}} |

## Detection / playbook improvements
{{improvements}}`,
  },
];
