---
document type: cmdlet
external help file: KrbEtypeInsight-Help.xml
HelpUri: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
Locale: en-US
Module Name: KrbEtypeInsight
ms.date: 08 30 2026
PlatyPS schema version: 2024-05-01
title: Get-KrbEvent
---

# Get-KrbEvent

## SYNOPSIS

Collects and decodes Kerberos authentication audit events from domain controllers or archived logs

## SYNTAX

### LiveDomain (Default)

```
Get-KrbEvent [-ComputerName <string[]>] [-EventId <int[]>] [-StartTime <datetime>]
 [-EndTime <datetime>] [-MaxEvents <int>] [-Credential <pscredential>] [-IncludeFailureOnly]
```

### Path

```
Get-KrbEvent -Path <string[]> [-EventId <int[]>] [-StartTime <datetime>] [-EndTime <datetime>]
 [-MaxEvents <int>] [-IncludeFailureOnly]
```


## DESCRIPTION

Reads security audit events 4768 (TGT requested), 4769 (service ticket requested) and
4771 (pre-authentication failed), and returns them in the single normalised schema the
rest of the module consumes.
Every encryption type, result code and pre-authentication
type is decoded on the way out, so no caller has to know which of the two Kerberos
numbering systems a given field belongs to.

Collection sources:

- The current domain's controllers, discovered automatically.
This is the default and
  needs no parameters.
- Named computers, for a subset of controllers or a read-only DC.
- Archived .evtx files, which is both the way to assess a domain from a workstation
  and the way this module's own tests exercise the full decode path with no domain
  present.

On event volume, which is the real constraint.
A busy domain controller produces
4769 events at a rate that makes "collect everything and filter later" untenable -
tens of millions per week is ordinary.
Three things follow from that, and this
function is built around them:

1.
All filtering that CAN be pushed to the event log service IS.
Event ID and time
   window go into the FilterHashtable, where they are evaluated by the log service on
   the remote controller before anything crosses the network.
Filtering the same
   events with Where-Object after collection transfers every record and is slower by
   orders of magnitude.

2.
MaxEvents is applied per source, not per collection, and applies to the newest
   events.
A representative sample from each controller is nearly always a better
   basis for an assessment than an exhaustive read of one.

3.
Controllers are read sequentially and the decode happens locally.
For a large
   estate, the intended pattern is to archive the security log to .evtx on each
   controller - wevtutil exports in seconds because it never leaves the machine -
   and then run this function against the collected files.
The Troubleshooting notes
   carry a worked example.

Business value: this is the observational half of an encryption-type hardening
assessment.
Configuration alone cannot tell you what a service account has actually
been presenting for the last thirty days, and that is the fact that decides whether
hardening it is safe.

## EXAMPLES

### Example 1: Collects the most recent 5000 Kerberos events from every controller in the domain

```powershell
Get-KrbEvent -MaxEvents 5000
```

Output: KrbEtypeInsight.Event objects with all encryption types decoded.

Use case: A first look at what a domain is actually issuing.

Duration: Roughly 30 seconds per controller at this volume.

### Example 2: Finds every service that has been issued at least one RC4 service ticket in 45 days

```powershell
Get-KrbEvent -EventId 4769 -StartTime (Get-Date).AddDays(-45) |
    Group-Object ServiceName |
    Where-Object { $_.Group.TicketEtype -contains 23 } |
    Sort-Object Count -Descending
```

Output: Service names ordered by request volume.

Use case: Building the work list for an RC4 removal project.

Duration: 2 to 10 minutes depending on domain size.

### Example 3: Processes archived security logs collected from every controller

```powershell
Get-ChildItem \\fileserver\krbaudit\*.evtx | Get-KrbEvent -MaxEvents 0
```

Output: The full decoded event set with no domain connectivity required.

Use case: Assessing a domain from an administrative workstation, or re-running an assessment against a preserved snapshot after the estate has changed.

### Example 4: Post-change verification over the four hours since a hardening rollout

```powershell
Get-KrbEvent -IncludeFailureOnly -StartTime (Get-Date).AddHours(-4) |
    Group-Object StatusName | Sort-Object Count -Descending
```

Output: Failure counts by KDC result code.

Use case: Deciding within a maintenance window whether to proceed or roll back. KDC_ERR_ETYPE_NOTSUPP appearing here is the change breaking something.

## PARAMETERS

### -ComputerName

[System.String[]] (Optional, No Pipeline Support)

Domain controllers to read the security log from.
When omitted, every controller in
the current domain is discovered and read.
Ignored when -Path is used.

```yaml
Type: System.String[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: LiveDomain
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Credential

[System.Management.Automation.PSCredential] (Optional, No Pipeline Support)

Credentials for reading remote security logs.
Requires membership of Event Log
Readers or equivalent on each controller.
Ignored when -Path is used.

```yaml
Type: System.Management.Automation.PSCredential
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: LiveDomain
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -EndTime

[System.DateTime] (Optional, No Pipeline Support)

Latest event to collect.
Defaults to the present.

```yaml
Type: System.DateTime
DefaultValue: (Get-Date)
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -EventId

[System.Int32[]] (Optional, No Pipeline Support)

Which audit events to collect.
Defaults to 4768, 4769 and 4771.

Narrowing this is the cheapest available optimisation.
4769 alone answers "what have
services been presenting"; 4768 alone answers "what do clients advertise"; 4771 alone
answers "what is already failing".

```yaml
Type: System.Int32[]
DefaultValue: '@(4768, 4769, 4771)'
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -IncludeFailureOnly

[System.Management.Automation.SwitchParameter] (Optional, No Pipeline Support)

Return only events that represent a failure - every 4771, plus any 4768 or 4769
carrying a non-zero result code.

The intended use is after a hardening change: filtered to failures and grouped by
StatusName, a collection shows immediately whether KDC_ERR_ETYPE_NOTSUPP has appeared
where it was not before.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: False
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -MaxEvents

[System.Int32] (Optional, No Pipeline Support)

Maximum events to read from each source, newest first.
Defaults to 50000.

Set this to 0 for no limit only when reading an archived file.
Applying no limit to a
live controller's security log is a request to transfer the entire log.

```yaml
Type: System.Int32
DefaultValue: 50000
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Path

[System.String[]] (Mandatory in the Path set, Pipeline: ByPropertyName)

Archived .evtx files to read instead of a live log.
Accepts wildcards and pipes
directly from Get-ChildItem.
This is the offline assessment path and the one the unit
tests use.

```yaml
Type: System.String[]
DefaultValue: ''
SupportsWildcards: false
Aliases:
- FullName
ParameterSets:
- Name: Path
  Position: Named
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: true
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -StartTime

[System.DateTime] (Optional, No Pipeline Support)

Earliest event to collect.
Defaults to 30 days ago, which is chosen to be longer than
the 30-day default computer account password cycle so that at least one full
authentication cycle for every domain-joined machine falls inside the window.

Assessments run over a window shorter than a month routinely miss the monthly batch
job that is the thing hardening will break.

```yaml
Type: System.DateTime
DefaultValue: (Get-Date).AddDays(-30)
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String[]

One or more paths to archived `.evtx` files, bound to **-Path** by property name. Because the
binding is by property name, `Get-ChildItem *.evtx | Get-KrbEvent` pipes directly — the
`FullName` property of each `FileInfo` satisfies the parameter without a calculated property.

## OUTPUTS

### KrbEtypeInsight.Event

One object per decoded 4768, 4769 or 4771 record, normalised across the version 0, 1 and 2
audit schemas so a consumer never tests the schema version itself. Carries the identity of the
request (`ClientAccount`, `ClientRealm`, `ServiceName`, `IsTgtRequest`), the encryption types
actually negotiated (`TicketEtype`, `SessionKeyEtype`, `PreAuthEtype`), the configuration the
KDC saw (`AccountSupportedEtypes`, `ServiceSupportedEtypes`, `AccountAvailableKeys`), the
client's advertised capability where the schema records it (`ClientAdvertizedNames`,
`ClientAdvertizedSupportsAes`, `ClientAdvertizedLegacyOnly`), and the originating `IpAddress`.

`HasEtypeDetail` is the property to test before drawing a conclusion: version 0 and version 1
records do not carry the client's advertised list, so an event may be a valid observation of a
ticket while saying nothing about what the client could have used instead.

## NOTES

Author: Jeffrey Stuhr
Blog: https://www.techbyjeff.net
LinkedIn: https://www.linkedin.com/in/jeffrey-stuhr-034214aa/

Requires the Kerberos Authentication Service and Kerberos Service Ticket Operations
audit subcategories to be enabled on the controllers.
Without them the collection
returns nothing and the assessment silently describes an empty domain - so this
function warns rather than returning quietly when a source yields no events.

Permissions: membership of Event Log Readers on each controller is sufficient for THIS
function, and Domain Admin is not required.
It is NOT sufficient for the module as a
whole - Get-KrbDomainEtypeContext reads each controller's registry over PowerShell
remoting and needs local administrator there.
See the rights table in the README.

Rights are not the only gate.
Get-WinEvent -ComputerName uses the legacy Event Log RPC
protocol, and the Remote Event Log Management firewall rules that permit it are off by
default on a fresh Windows install.
A controller with perfect rights still returns
"The RPC server is unavailable" until they are enabled.

TROUBLESHOOTING:
- No events returned: .\Troubleshooting\Common\No-Events-Collected.md
- Event volume and archiving: .\Troubleshooting\Performance\Event-Volume.md
- Remote access denied: .\Troubleshooting\Security\Event-Log-Permissions.md


## RELATED LINKS

- [4768 - A Kerberos authentication ticket (TGT) was requested](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [4769 - A Kerberos service ticket was requested](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [4771 - Kerberos pre-authentication failed](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771)
- [KB5021131 - Managing the Kerberos protocol changes for CVE-2022-37966](https://support.microsoft.com/help/5021131)
- [Get-KrbEtypeRisk]()
- [about_KrbEtypeInsight]()
