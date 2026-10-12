// Starter hunting queries for Microsoft Sentinel / Defender XDR (KQL).
// Table and column availability depends on your licences and connectors - test on a short time range first.
// `attack` lists related ATT&CK technique IDs (used to cross-link from the ATT&CK pages).

export const KQL = [
  { id: "spray", title: "Password spray – many users from one IP", area: "Identity (Entra ID)", attack: ["T1110.003"],
    note: "ResultType 50126 = invalid password, 50053 = locked out, 50057 = disabled account.",
    query: `SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in ("50126", "50053", "50057")
| summarize Attempts = count(), Users = dcount(UserPrincipalName), SampleUsers = make_set(UserPrincipalName, 15) by IPAddress
| where Users >= 10
| order by Users desc` },
  { id: "success-after-fail", title: "Successful sign-in after repeated failures", area: "Identity (Entra ID)", attack: ["T1110", "T1078"],
    note: "Same user and IP: 5+ bad passwords, then a success.",
    query: `let failures = SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == "50126"
    | summarize Fails = count() by UserPrincipalName, IPAddress
    | where Fails >= 5;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| join kind=inner failures on UserPrincipalName, IPAddress
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, Fails` },
  { id: "new-country", title: "Sign-in from a country not seen in the last 30 days", area: "Identity (Entra ID)", attack: ["T1078"],
    note: "Noisy for travellers and VPNs – use as a lead, not a verdict.",
    query: `let history = SigninLogs
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | where ResultType == "0"
    | summarize by UserPrincipalName, Country = tostring(LocationDetails.countryOrRegion);
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| join kind=leftanti history on UserPrincipalName, Country
| project TimeGenerated, UserPrincipalName, Country, IPAddress, AppDisplayName` },
  { id: "mfa-method", title: "New MFA / security-info registration", area: "Identity (Entra ID)", attack: ["T1098"],
    note: "Attackers often add their own MFA method after taking over an account.",
    query: `AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "security info" or OperationName has "authentication method"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), Target = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, Result, Actor, Target` },
  { id: "consent", title: "OAuth application consent granted", area: "Identity (Entra ID)", attack: ["T1528"],
    note: "Illicit consent grants give persistent access without a password.",
    query: `AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), App = tostring(TargetResources[0].displayName)
| project TimeGenerated, Actor, App, Result, AdditionalDetails` },
  { id: "inbox-rule", title: "Suspicious inbox rules (forward / delete)", area: "Email (Microsoft 365)", attack: ["T1564.008", "T1114.003"],
    note: "Needs the Office 365 connector (OfficeActivity table).",
    query: `OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where Parameters has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "DeleteMessage", "MoveToFolder")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters` },
  { id: "email-sender", title: "All mail from a sender (blast radius)", area: "Email (Defender XDR)", attack: ["T1566"],
    note: "Replace the sender address. Advanced hunting: EmailEvents.",
    query: `EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress =~ "sender@example.com"
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation
| order by Timestamp desc` },
  { id: "url-click", title: "Who clicked a URL / domain", area: "Email (Defender XDR)", attack: ["T1566.002"],
    note: "Replace the domain. Advanced hunting: UrlClickEvents.",
    query: `UrlClickEvents
| where Timestamp > ago(14d)
| where Url has "bad-domain.example"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, NetworkMessageId
| order by Timestamp desc` },
  { id: "enc-ps", title: "Encoded / obfuscated PowerShell", area: "Endpoint (Defender XDR)", attack: ["T1059.001", "T1027"],
    note: "Decode the Base64 in the Toolkit page.",
    query: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "FromBase64String")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc` },
  { id: "office-spawn", title: "Office app spawning a script interpreter", area: "Endpoint (Defender XDR)", attack: ["T1204.002", "T1059"],
    note: "Classic macro / malicious document execution chain.",
    query: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine` },
  { id: "schtask", title: "Scheduled task creation", area: "Endpoint (Defender XDR)", attack: ["T1053.005"],
    note: "Persistence / execution. Check the task's action and who created it.",
    query: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine` },
  { id: "lsass", title: "Possible LSASS credential dumping", area: "Endpoint (Defender XDR)", attack: ["T1003.001"],
    note: "Also review EDR alerts – this only catches the command-line patterns.",
    query: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName in~ ("procdump.exe", "procdump64.exe") and ProcessCommandLine has "lsass")
    or ProcessCommandLine has_all ("comsvcs.dll", "MiniDump")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine` },
  { id: "net-ioc", title: "Devices that connected to an IP / domain IOC", area: "Endpoint (Defender XDR)", attack: ["T1071"],
    note: "Put your indicators in the lists.",
    query: `let badIPs = dynamic(["203.0.113.45", "198.51.100.7"]);
let badDomains = dynamic(["bad-domain.example"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (badIPs) or RemoteUrl has_any (badDomains)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc` },
  { id: "hash", title: "Where has a file hash been seen", area: "Endpoint (Defender XDR)", attack: [],
    note: "Put your SHA-256 values in the list.",
    query: `let hashes = dynamic(["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in (hashes)
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessFileName
| order by Timestamp desc` },
  { id: "new-admin", title: "Account created / added to privileged groups", area: "Windows Security events", attack: ["T1136", "T1098"],
    note: "4720 user created, 4728/4732/4756 member added to a group. Needs Windows security events in Sentinel.",
    query: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4720, 4728, 4732, 4756)
| project TimeGenerated, Computer, EventID, Activity, SubjectAccount, TargetAccount, TargetUserName
| order by TimeGenerated desc` },
  { id: "log-clear", title: "Security log cleared", area: "Windows Security events", attack: ["T1070.001"],
    note: "Event 1102 – rarely legitimate.",
    query: `SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 1102
| project TimeGenerated, Computer, Account, Activity` },
  { id: "rdp-brute", title: "Failed network / RDP logons", area: "Windows Security events", attack: ["T1110", "T1021.001"],
    note: "LogonType 3 (network) and 10 (remote interactive).",
    query: `SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4625 and LogonType in (3, 10)
| summarize Failures = count(), Accounts = dcount(TargetUserName) by IpAddress, Computer
| where Failures >= 20
| order by Failures desc` },
];
