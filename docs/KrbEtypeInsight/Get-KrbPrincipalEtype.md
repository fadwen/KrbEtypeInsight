---
document type: cmdlet
external help file: KrbEtypeInsight-Help.xml
HelpUri: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
Locale: en-US
Module Name: KrbEtypeInsight
ms.date: 08 30 2026
PlatyPS schema version: 2024-05-01
title: Get-KrbPrincipalEtype
---

# Get-KrbPrincipalEtype

## SYNOPSIS

Reads the configured Kerberos encryption type posture of Active Directory principals

## SYNTAX

### All (Default)

```
Get-KrbPrincipalEtype -All [-ServiceAccountOnly] [-IncludeDisabled]
 [-DomainDefaultEncryptionTypes <int>] [-Server <string>] [-Credential <pscredential>]
```

### Identity

```
Get-KrbPrincipalEtype -Identity <string[]> [-DomainDefaultEncryptionTypes <int>] [-Server <string>]
 [-Credential <pscredential>]
```

### ServicePrincipalName

```
Get-KrbPrincipalEtype -ServicePrincipalName <string[]> [-DomainDefaultEncryptionTypes <int>]
 [-Server <string>] [-Credential <pscredential>]
```


## DESCRIPTION

Returns, for each account, everything in the directory that determines which
encryption types the KDC will use for it - decoded, and with the interactions between
attributes made explicit.

Four attributes decide the answer, and reading any one of them alone gives a wrong
result:

- msDS-SupportedEncryptionTypes is the primary control.
Unset and zero both mean
  "use the domain default", which is not the same as "supports nothing" and not the
  same as "supports RC4 only".

- userAccountControl carries USE_DES_KEY_ONLY, which overrides the encryption-type
  attribute entirely, and the delegation bits, which determine how far a failure
  propagates.

- pwdLastSet decides which key material actually exists.
Kerberos keys are derived
  when the password is set, so an account whose password has not changed since the
  domain supported AES has no AES key regardless of what its attributes claim.
  Setting such an account to AES-only does not harden it, it breaks it - the KDC has
  nothing to encrypt with and returns KDC_ERR_NULL_KEY.

- servicePrincipalName decides whether the account is a service at all, and therefore
  whether it appears in 4769 events as a target rather than only as a requester.

Business value: this is the configuration half of the assessment.
Combined with the
observational half from Get-KrbEvent, it produces the statement that matters - not
"this account is configured for RC4" but "this account is configured for RC4, has
never presented anything else, holds no AES key, and twelve clients depend on it".

## EXAMPLES

### Example 1: Reads one service account's complete encryption type posture

```powershell
Get-KrbPrincipalEtype -Identity 'svc-legacyapp'
```

Output: Decoded supported types, account control flags, password age, and SPNs.

Use case: Investigating a single account before changing it.

### Example 2: Finds every service account that can only use RC4

```powershell
Get-KrbPrincipalEtype -All -ServiceAccountOnly |
    Where-Object { $_.EncryptionTypes.SupportsRc4 -and -not $_.EncryptionTypes.SupportsAes }
```

Output: The accounts an RC4 removal will definitely affect.

Use case: Scoping a hardening project.

Duration: Under a minute in a domain of a few thousand accounts.

### Example 3: Finds accounts pinned to single DES by userAccountControl

```powershell
Get-KrbPrincipalEtype -All | Where-Object { $_.AccountControl.UseDesKeyOnly }
```

Output: Accounts whose encryption-type attribute the KDC is ignoring.

Use case: Catching the accounts an attribute-only assessment reports as healthy.

### Example 4: Resolves the services actually observed in the log back to their accounts

```powershell
Get-KrbEvent -EventId 4769 -MaxEvents 20000 |
    Select-Object -ExpandProperty ServiceName -Unique |
    Get-KrbPrincipalEtype -ServicePrincipalName -ErrorAction SilentlyContinue
```

Output: Configuration for exactly the accounts that are in use.

Use case: Assessing what is live rather than what merely exists in the directory.

## PARAMETERS

### -All

[System.Management.Automation.SwitchParameter] (Mandatory in the All set, No Pipeline Support)

Enumerate every user and computer account in the domain.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: False
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: All
  Position: Named
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Credential

[System.Management.Automation.PSCredential] (Optional, No Pipeline Support)

Credentials for the directory query.
Read access to the listed attributes is
sufficient; no write permission is required or requested.

```yaml
Type: System.Management.Automation.PSCredential
DefaultValue: ''
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

### -DomainDefaultEncryptionTypes

[System.Int32] (Optional, No Pipeline Support)

The bitmask applied when msDS-SupportedEncryptionTypes is unset or zero.
Defaults to
the Windows default of 0x27.
Pass the real value from Get-KrbDomainEtypeContext when
the domain controllers have DefaultDomainSupportedEncTypes configured, otherwise
every account inheriting the default is described against the wrong baseline.

```yaml
Type: System.Int32
DefaultValue: 39
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

### -Identity

[System.String[]] (Mandatory in the Identity set, Pipeline: ByValue and ByPropertyName)

Accounts to read, by sAMAccountName, distinguished name, SID or GUID.

```yaml
Type: System.String[]
DefaultValue: ''
SupportsWildcards: false
Aliases:
- SamAccountName
- DistinguishedName
ParameterSets:
- Name: Identity
  Position: Named
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: true
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -IncludeDisabled

[System.Management.Automation.SwitchParameter] (Optional, No Pipeline Support)

Include disabled accounts in an -All enumeration.
Excluded by default: a disabled
account cannot authenticate, so counting it as a risk inflates the report without
adding a single action.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: False
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: All
  Position: Named
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

Domain controller to query.
Defaults to whichever the ActiveDirectory module selects.

```yaml
Type: System.String
DefaultValue: ''
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

### -ServiceAccountOnly

[System.Management.Automation.SwitchParameter] (Optional, No Pipeline Support)

Restrict an -All enumeration to accounts that have at least one service principal
name.
These are the accounts whose encryption types appear in service ticket requests
and therefore the ones a hardening change can break for other people.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: False
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: All
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -ServicePrincipalName

[System.String[]] (Mandatory in the ServicePrincipalName set, Pipeline: ByValue and ByPropertyName)

Service principal names to resolve back to their owning accounts.
This is how a
service name taken from a 4769 event becomes an account whose configuration can be
read.

For bulk work, prefer -All and index the results locally.
Resolving several thousand
SPNs one directory query at a time is the slowest thing this module can be asked to
do; one enumeration and an in-memory index is what Get-KrbEtypeRisk does instead.

```yaml
Type: System.String[]
DefaultValue: ''
SupportsWildcards: false
Aliases:
- ServiceName
- Spn
ParameterSets:
- Name: ServicePrincipalName
  Position: Named
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: true
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

One or more account identities or service principal names, accepted from the pipeline by value.
An identity may be a `sAMAccountName`, a distinguished name, a GUID or a SID; an SPN is
recognised by its `service/host` shape and resolved to the account that holds it.

## OUTPUTS

### KrbEtypeInsight.Principal

One object per resolved account, describing what the directory says it supports.
`ConfiguredEncryptionTypes` is the raw `msDS-SupportedEncryptionTypes` value and
`EffectiveEncryptionTypes` is what the account actually resolves to once an unset attribute has
been read against the domain default and any `userAccountControl` override has been applied —
the two differ far more often than the attribute alone suggests, which is why both are
returned. `AvailableKeys` reports the key material that exists rather than the configuration
that claims it, so an account configured for AES but holding no AES key is visible before a
change makes it a `KDC_ERR_NULL_KEY`.

## NOTES

Author: Jeffrey Stuhr
Blog: https://www.techbyjeff.net
LinkedIn: https://www.linkedin.com/in/jeffrey-stuhr-034214aa/

Requires the ActiveDirectory module.
Read-only throughout - this function never
modifies a directory object.

Group managed service accounts are returned like any other account.
Their passwords
are rotated by the KDC every 30 days by default, so they are among the few account
types whose key material can be assumed current.

TROUBLESHOOTING:
- SPN resolution failures: .\Troubleshooting\Common\SPN-Resolution.md
- Accounts with no AES key: .\Troubleshooting\Common\Missing-AES-Keys.md
- Query performance: .\Troubleshooting\Performance\Directory-Queries.md


## RELATED LINKS

- [MS-KILE 2.2.7 - Supported Encryption Types Bit Flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919)
- [Group Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [Get-KrbDomainEtypeContext]()
- [Get-KrbEtypeRisk]()
- [about_KrbEtypeInsight]()
