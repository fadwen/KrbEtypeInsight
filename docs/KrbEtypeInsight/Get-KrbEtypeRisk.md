---
document type: cmdlet
external help file: KrbEtypeInsight-Help.xml
HelpUri: ''
Locale: en-US
Module Name: KrbEtypeInsight
ms.date: 08 30 2026
PlatyPS schema version: 2024-05-01
title: Get-KrbEtypeRisk
---

# Get-KrbEtypeRisk

## SYNOPSIS

Predicts which principals and clients a Kerberos encryption type hardening change will break

## SYNTAX

### __AllParameterSets

```
Get-KrbEtypeRisk [-KerberosEvent] <Object[]> [[-Principal] <Object[]>] [[-DomainContext] <Object>]
 [[-TargetEncryptionTypes] <int>] [-Offline] [-IncludeHealthy]
```


## DESCRIPTION

Correlates observed authentication behaviour with directory configuration and domain
baseline, and emits one risk object per affected principal describing what a proposed
encryption type change would do to it - with the evidence attached.

This is the question the configuration scripts cannot answer.
Setting an account's
msDS-SupportedEncryptionTypes to AES is a one-line change; knowing whether that
account has ever successfully used AES, whether it even holds an AES key, and which
clients will stop working when RC4 goes away, requires putting three independent
sources next to each other:

- What the KDC actually issued, from events 4768 and 4769.
- What the directory says each principal supports, from msDS-SupportedEncryptionTypes
  and userAccountControl.
- What the domain permits by default, from the controllers' own policy.

The correlations that produce the useful findings:

1.
Available keys against configured types.
Version 2 events report which key material
   a principal actually holds.
An account configured for AES that holds no AES key is
   the single most common cause of a hardening rollback: Kerberos keys are derived
   when the password is set, so an account whose password predates the change has
   nothing to encrypt with and the KDC returns KDC_ERR_NULL_KEY.
Configuration alone
   cannot see this.
It is finding KRB002 and it is why this module exists.

2.
Client advertisement against service dependency.
Every 4768 records the full list
   of encryption types the client offered.
Indexing that by client account, and then
   looking up each client of a given service, converts "this service only ever gets
   RC4 tickets" into "these twelve named clients advertise no AES at all and will
   fail the moment the KDC stops offering RC4".
That named list is what an
   application owner needs in order to act, and no amount of configuration auditing
   produces it.

3.
Existing failures against the proposed change.
Events already carrying
   KDC_ERR_ETYPE_NOTSUPP or KDC_ERR_NULL_KEY are not predictions - they are breakage
   that has already happened and is being absorbed by retries somewhere.

Confidence is reported, not assumed.
Where the controllers emit the older version 0
or version 1 event schema, the available-key and client-advertisement fields do not
exist, and the engine falls back to weaker inference from ticket encryption types
alone.
It says so on every affected object rather than presenting an inference as an
observation.

## EXAMPLES

### Example 1: A complete assessment of an RC4 removal against the last 30 days

```powershell
Get-KrbEvent -MaxEvents 50000 | Get-KrbEtypeRisk | Sort-Object RiskScore -Descending
```

Output: One risk object per affected principal, worst first.

Use case: The main entry point; everything else in the module supports this line.

Duration: 2 to 15 minutes depending on domain and event volume.

### Example 2: Produces the named list of clients each critical service would take down

```powershell
$risks = Get-KrbEvent -EventId 4768,4769 | Get-KrbEtypeRisk
PS> $risks | Where-Object RiskLevel -eq 'Critical' |
    Select-Object PrincipalName, RequestCount, ClientCount,
    @{ n = 'BreaksClients'; e = { $_.ClientsWithoutAesSupport -join ', ' } }
```

Output: Service, its request volume, and the specific clients that cannot do AES.

Use case: The table to send to each application owner - it names their machines, not yours.

### Example 3: Models the intermediate step of adding AES while keeping RC4

```powershell
Get-KrbEvent | Get-KrbEtypeRisk -TargetEncryptionTypes 0x1C |
    Where-Object RiskLevel -in 'Critical', 'High'
```

Output: Anything that would break even from that supposedly safe change.

Use case: Validating the first phase of a staged rollout before scheduling it.

### Example 4: Assesses archived logs with no domain connectivity

```powershell
Get-KrbEvent -Path .\dc01.evtx, .\dc02.evtx -MaxEvents 0 | Get-KrbEtypeRisk -Offline
```

Output: Risk objects built entirely from version 2 event content.

Use case: Analysing a customer's collected logs on your own machine.

## PARAMETERS

### -DomainContext

[System.Object] (Optional, No Pipeline Support)

Domain baseline from Get-KrbDomainEtypeContext.
When omitted and -Offline is not set,
it is collected automatically.
Supplies the true domain default against which
accounts with an unset attribute are judged, and contributes trust and krbtgt
findings of its own.

```yaml
Type: System.Object
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 2
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -IncludeHealthy

[System.Management.Automation.SwitchParameter] (Optional, No Pipeline Support)

Also emit principals that the change would not affect.
Off by default so that the
output is a work list rather than an inventory.

Turn it on when producing evidence that a change is safe, where the principals with
nothing wrong are the point.

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

### -KerberosEvent

[System.Object[]] (Mandatory, Pipeline: ByValue)

Decoded events from Get-KrbEvent.
The assessment is only as good as this window; see
the StartTime guidance on Get-KrbEvent for why thirty days is the practical minimum.

Aliased to -Event, which reads better at the console.
The parameter itself cannot be
named Event: $Event is a PowerShell automatic variable, populated inside the action
block of an event registration, and a parameter of that name shadows it.
Nothing in
this function would notice, but a caller who pipes into it from inside such a block
would, and the failure would be baffling.

```yaml
Type: System.Object[]
DefaultValue: ''
SupportsWildcards: false
Aliases:
- Event
ParameterSets:
- Name: (All)
  Position: 0
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Offline

[System.Management.Automation.SwitchParameter] (Optional, No Pipeline Support)

Assess purely from the event data, making no directory or registry calls.

This is the mode for analysing archived logs on a machine with no domain
connectivity.
Version 2 events carry enough of each principal's configuration inline
that the assessment remains substantially complete; against older event schemas it
degrades considerably, and the ConfidenceNotes on each object record what was lost.

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

### -Principal

[System.Object[]] (Optional, No Pipeline Support)

Directory configuration from Get-KrbPrincipalEtype.
When omitted and -Offline is not
set, the domain is enumerated once and indexed in memory.

Supplying this explicitly is worthwhile when assessing repeatedly against the same
directory snapshot, and required when the analysis machine cannot reach the domain.

```yaml
Type: System.Object[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 1
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -TargetEncryptionTypes

[System.Int32] (Optional, No Pipeline Support)

The msDS-SupportedEncryptionTypes bitmask the change would move to.
Defaults to 0x18
(24) - AES128 and AES256, with RC4 and DES removed - which is what an RC4 removal
project is aiming at.

Set it to 0x1C (28) to model the intermediate step of adding AES while leaving RC4
in place, which should produce no Critical findings at all; if it does, that step is
not as safe as it is usually assumed to be.

```yaml
Type: System.Int32
DefaultValue: 24
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 3
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

### KrbEtypeInsight.Event

Decoded events from `Get-KrbEvent`, accepted from the pipeline by value. Events are buffered in
memory until the pipeline completes, because a per-principal view cannot be built from a stream
— the last event for a principal may change the conclusion drawn from the first.

## OUTPUTS

### KrbEtypeInsight.Risk

One object per principal observed in the collection. `RiskLevel` and `RiskScore` rank the
result, `Findings` and `FindingCodes` say which rules fired and why, and
`WillBreakOnHardening` is the single boolean a change decision turns on.

`Clients` and `ClientsWithoutAesSupport` are the deliverable. They name the specific machines
that depend on the principal and, of those, the ones that advertised no AES encryption type at
all — the list an application owner has to act on. `RequestCount`, `FirstSeen` and `LastSeen`
establish how current the observation is, and `ResolvedInDirectory` distinguishes a principal
seen in events but absent from the directory from one that was confirmed.

`WillBreakOnHardening` means "predicted to break given observed use", not "cannot work". A
principal with no traffic in the collection window is reported as `KRB012` rather than as
breaking: absence of traffic is not evidence of safety.

## NOTES

Author: Jeffrey Stuhr
Blog: https://www.techbyjeff.net
LinkedIn: https://www.linkedin.com/in/jeffrey-stuhr-034214aa/

Read-only.
This function predicts the effect of a change; it never makes one.

Events are buffered in memory before correlation, because a per-principal view cannot
be built from a stream.
Peak memory is roughly 2 KB per event.
For collections beyond
a few hundred thousand events, assess one controller's archive at a time and merge
the resulting risk objects.

TROUBLESHOOTING:
- Finding code reference: .\Troubleshooting\Common\Finding-Codes.md
- Risk scoring: .\Troubleshooting\Common\Risk-Scoring.md
- Low confidence results: .\Troubleshooting\Common\Event-Schema-Versions.md
- Memory use on large collections: .\Troubleshooting\Performance\Event-Volume.md


## RELATED LINKS

- [KB5021131 - Managing the Kerberos protocol changes for CVE-2022-37966](https://support.microsoft.com/help/5021131)
- [RFC 4120 - The Kerberos Network Authentication Service (V5)](https://www.rfc-editor.org/rfc/rfc4120)
- [Get-KrbEvent](https://github.com/fadwen/KrbEtypeInsight/blob/main/docs/KrbEtypeInsight/Get-KrbEvent.md)
- [Get-KrbDomainEtypeContext](https://github.com/fadwen/KrbEtypeInsight/blob/main/docs/KrbEtypeInsight/Get-KrbDomainEtypeContext.md)
- [Export-KrbEtypeReport](https://github.com/fadwen/KrbEtypeInsight/blob/main/docs/KrbEtypeInsight/Export-KrbEtypeReport.md)
