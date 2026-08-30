---
document type: cmdlet
external help file: KrbEtypeInsight-Help.xml
HelpUri: ''
Locale: en-US
Module Name: KrbEtypeInsight
ms.date: 08 30 2026
PlatyPS schema version: 2024-05-01
title: Get-KrbDomainEtypeContext
---

# Get-KrbDomainEtypeContext

## SYNOPSIS

Collects the domain-wide settings that govern Kerberos encryption type selection

## SYNTAX

### __AllParameterSets

```
Get-KrbDomainEtypeContext [[-Server] <string>] [[-ComputerName] <string[]>]
 [[-Credential] <pscredential>] [-SkipRegistry]
```


## DESCRIPTION

Gathers the context an individual account's configuration has to be read against.
Per-account encryption types do not act alone: what the KDC actually issues is the
intersection of the account's types, the domain default, the controller's own policy
and, for cross-realm requests, the trust's types.

What is collected and why each item changes a conclusion:

- Domain and forest functional level.
AES key derivation requires a domain functional
  level of Windows Server 2008 or higher.
Below that, no account in the domain has an
  AES key regardless of its attributes, and an AES-only hardening change breaks
  everything.

- DefaultDomainSupportedEncTypes, read from every reachable controller.
This is the
  value the KDC falls back to when msDS-SupportedEncryptionTypes is unset or zero,
  which in a typical domain is the great majority of accounts.
Two things about it
  matter more than its value.
First, it is a per-controller registry setting, not a
  replicated directory attribute, so controllers can and do disagree - and a domain
  where they disagree authenticates differently depending on which controller a
  client reaches, which produces intermittent failures that survive every attempt to
  reproduce them.
Second, its unwritten default of 0x27 includes the AES256
  session-key bit, so accounts inheriting it are not the RC4-only accounts a naive
  reading suggests.

- The controller-side Kerberos policy value from
  Policies\System\Kerberos\Parameters\SupportedEncryptionTypes, which is what the
  "Network security: Configure encryption types allowed for Kerberos" group policy
  setting writes.
Applied to a controller, it constrains the KDC itself.

- krbtgt's own encryption types and password age.
Every TGT in the domain is
  encrypted with a krbtgt key, so krbtgt is the one account whose encryption types
  are a domain-wide property.
Its password age also bounds which key material exists.

- Trust encryption types.
A trust whose msDS-SupportedEncryptionTypes omits AES
  forces RC4 on every cross-realm ticket regardless of what either side's accounts
  support, and is the most common reason a domain that has "finished" removing RC4
  keeps issuing it.

- Controller operating systems, because the RFC 8009 SHA-2 encryption types and the
  version 2 audit event schema are only available on newer builds.

Business value: this function answers "what baseline am I assessing against", which
is the question that determines whether every other finding in the report is correct
or merely plausible.

## EXAMPLES

### Example 1: Collects the full domain encryption type baseline

```powershell
Get-KrbDomainEtypeContext
```

Output: A KrbEtypeInsight.DomainContext object covering functional level, per-controller policy, krbtgt and trusts.

Use case: The first command to run in an assessment; its DomainDefaultEncryptionTypes value feeds every subsequent per-account decode.

Duration: A few seconds per domain controller.

### Example 2: Finds controllers whose local Kerberos policy differs from the rest

```powershell
$context = Get-KrbDomainEtypeContext
PS> $context.DomainControllers | Where-Object { -not $_.AgreesWithDomainDefault }
```

Output: The controllers responsible for intermittent, unreproducible authentication failures.

Use case: Explaining why one site's clients fail and another's do not.

### Example 3: Reads every account against the domain's real default rather than an assumed one

```powershell
$context = Get-KrbDomainEtypeContext
PS> Get-KrbPrincipalEtype -All -DomainDefaultEncryptionTypes $context.DomainDefaultEncryptionTypes
```

Output: Correct effective encryption types for accounts with an unset attribute.

Use case: The supported way to run a per-account assessment.

## PARAMETERS

### -ComputerName

[System.String[]] (Optional, No Pipeline Support)

Restrict registry collection to specific controllers.
When omitted, every controller
in the domain is contacted.

```yaml
Type: System.String[]
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

### -Credential

[System.Management.Automation.PSCredential] (Optional, No Pipeline Support)

Credentials for the directory query and for remote registry access.

```yaml
Type: System.Management.Automation.PSCredential
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

### -Server

[System.String] (Optional, No Pipeline Support)

Domain controller to read directory data from.
Defaults to whichever the
ActiveDirectory module selects.
Registry data is still gathered from every controller
regardless of this setting, because disagreement between controllers is one of the
findings.

```yaml
Type: System.String
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 0
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -SkipRegistry

[System.Management.Automation.SwitchParameter] (Optional, No Pipeline Support)

Skip the per-controller registry collection and report the documented Windows default
of 0x27 as the domain default.

Use this when remote management to the controllers is unavailable, and read the
resulting assessment knowing that its baseline is assumed rather than measured.
The
output records which of the two happened in DomainDefaultSource.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

This cmdlet does not accept pipeline input. The domain to assess is named with **-Server** or
discovered from the current context.

## OUTPUTS

### KrbEtypeInsight.DomainContext

A single object describing the baseline every per-principal judgement is made against: the
domain and forest functional levels, the `krbtgt` account's own encryption types and key
material, the encryption types configured on each outbound and inbound trust, and one entry per
domain controller carrying that controller's `DefaultDomainSupportedEncTypes` registry value.

The per-controller breakdown is the point of the object rather than a detail of it. Controllers
are permitted to disagree, the effective default for an account with an unset attribute depends
on which controller answers, and a domain where they disagree cannot be assessed as though it
had one baseline. Where remote registry collection is refused the entry records the documented
default and says the value was assumed, so a partial baseline is distinguishable from a
confirmed one.

## NOTES

Author: Jeffrey Stuhr
Blog: https://www.techbyjeff.net
LinkedIn: https://www.linkedin.com/in/jeffrey-stuhr-034214aa/

Remote registry collection uses PowerShell remoting.
Where that is unavailable the
function degrades to the documented default and says so rather than failing, because
a partial baseline reported honestly is more useful than no assessment at all.

Read-only throughout.

TROUBLESHOOTING:
- Remote registry access: .\Troubleshooting\Integration\Remote-Registry-Access.md
- Inconsistent controllers: .\Troubleshooting\Common\Controller-Policy-Drift.md
- Trust encryption types: .\Troubleshooting\Common\Trust-Encryption-Types.md


## RELATED LINKS

- [KB5021131 - Managing the Kerberos protocol changes for CVE-2022-37966](https://support.microsoft.com/help/5021131)
- [MS-KILE 2.2.7 - Supported Encryption Types Bit Flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919)
- [Get-KrbPrincipalEtype]()
- [Get-KrbEtypeRisk]()
- [about_KrbEtypeInsight]()
