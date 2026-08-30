---
document type: cmdlet
external help file: KrbEtypeInsight-Help.xml
HelpUri: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
Locale: en-US
Module Name: KrbEtypeInsight
ms.date: 08 30 2026
PlatyPS schema version: 2024-05-01
title: ConvertFrom-KrbEtype
---

# ConvertFrom-KrbEtype

## SYNOPSIS

Decodes Kerberos encryption type values from any of the three forms Windows emits them in

## SYNTAX

### TicketEtype (Default)

```
ConvertFrom-KrbEtype -TicketEtype <Object>
```

### SupportedEncryptionTypes

```
ConvertFrom-KrbEtype -SupportedEncryptionTypes <Object> [-DomainDefaultEncryptionTypes <int>]
```

### AdvertizedEtype

```
ConvertFrom-KrbEtype -AdvertizedEtype <string[]>
```


## DESCRIPTION

Turns a raw Kerberos encryption-type value into a described object.
Which decoding is
applied depends on which parameter is used, because the three forms are three
different data types that happen to be written as small integers:

- -TicketEtype decodes an RFC 3961 encryption type NUMBER, the form found in the
  TicketEncryptionType, SessionKeyEncryptionType and PreAuthEncryptionType fields of
  events 4768 and 4769.
In this system RC4-HMAC is 23 (0x17) and
  AES256-CTS-HMAC-SHA1-96 is 18 (0x12).

- -SupportedEncryptionTypes decodes an MS-KILE 2.2.7 BITMASK, the form found in the
  msDS-SupportedEncryptionTypes attribute, in the DefaultDomainSupportedEncTypes
  registry value, on trustedDomain objects, and in the *SupportedEncryptionTypes
  fields of version 2 events.
In this system RC4-HMAC is bit 0x4 and
  AES256-CTS-HMAC-SHA1-96 is bit 0x10.

- -AdvertizedEtype decodes the newline-separated list of Windows etype NAMES found in
  the ClientAdvertizedEncryptionTypes field of a version 2 event - the list of
  algorithms the client actually offered on the wire.

The two numeric systems are not interconvertible by arithmetic and this function
never treats them as if they were.
Passing a ticket etype to
-SupportedEncryptionTypes decodes 23 as DES-CBC-CRC + DES-CBC-MD5 + RC4-HMAC +
AES128, which is meaningless; the parameter sets exist to make that mistake require
deliberate effort.

Business value: this is the decode layer the rest of the module and the risk report
are built on.
It has no dependency on Active Directory or on the event log, so it can
be exercised in full against captured fixtures with no domain present.

## EXAMPLES

### Example 1: Decodes a ticket encryption type taken straight from a 4769 event

```powershell
ConvertFrom-KrbEtype -TicketEtype '0x17'
```

Output: An object naming RC4-HMAC, family RC4, strength Weak, RemovedByHardening true.

Use case: Establishing that a service ticket was issued under RC4.

### Example 2: Decodes an AES-only msDS-SupportedEncryptionTypes value

```powershell
ConvertFrom-KrbEtype -SupportedEncryptionTypes 24
```

Output: AES128 and AES256 flags set, SupportsRc4 false, SupportsAes true.

Use case: Confirming an account has already been hardened.

### Example 3: Describes an account whose attribute has never been set

```powershell
ConvertFrom-KrbEtype -SupportedEncryptionTypes $null -DomainDefaultEncryptionTypes 0x27
```

Output: UsesDomainDefault true, and the effective flags the KDC will actually apply.

Use case: Assessing the several hundred accounts in a typical domain that inherit the default.

### Example 4: Decodes what a client offered on the wire

```powershell
ConvertFrom-KrbEtype -AdvertizedEtype "AES256-CTS-HMAC-SHA1-96`n`tRC4-HMAC-NT"
```

Output: Both etypes resolved, SupportsAes true - this client survives hardening.

Use case: Distinguishing a client that merely received RC4 from one that can only do RC4.

### Example 5: Profiles which ciphers a domain is actually issuing tickets under

```powershell
Get-KrbEvent -MaxEvents 500 | ForEach-Object { ConvertFrom-KrbEtype -TicketEtype $_.TicketEtype } |
    Group-Object DisplayName | Sort-Object Count -Descending
```

Output: A count per encryption type across the sampled events.

Use case: The first question to answer before any hardening change is scheduled.

## PARAMETERS

### -AdvertizedEtype

[System.String[]] (Mandatory in the AdvertizedEtype set, Pipeline: ByValue)

The etype names a client advertised.
Accepts either the raw multi-line, tab-indented
block exactly as it appears in ClientAdvertizedEncryptionTypes, or an array of
individual name strings.

```yaml
Type: System.String[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: AdvertizedEtype
  Position: Named
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -DomainDefaultEncryptionTypes

[System.Int32] (Optional, No Pipeline Support)

The bitmask the KDC falls back to when msDS-SupportedEncryptionTypes is unset or
zero - that is, the DefaultDomainSupportedEncTypes registry value on the domain
controllers.
Defaults to 0x27, which is the Windows default when the value has never
been written.

Supply the real value from Get-KrbDomainEtypeContext when assessing a live domain.
Getting this wrong is how an assessment concludes that several hundred accounts with
an unset attribute support nothing at all, or that they support RC4 only - neither is
true, because 0x27 also carries the AES256 session-key bit.

```yaml
Type: System.Int32
DefaultValue: 39
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: SupportedEncryptionTypes
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -SupportedEncryptionTypes

[System.Object] (Mandatory in the SupportedEncryptionTypes set, Pipeline: ByValue)

An MS-KILE supported-encryption-types bitmask.
Accepts an integer, a hex string, or
the full rendering a version 2 event uses, such as
'0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)'.
Pass $null to describe an attribute
that is not set at all, which is a different state from a value of 0 in every respect
except its effect.

```yaml
Type: System.Object
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: SupportedEncryptionTypes
  Position: Named
  IsRequired: true
  ValueFromPipeline: true
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -TicketEtype

[System.Object] (Mandatory in the TicketEtype set, Pipeline: ByValue)

An RFC 3961 encryption type number.
Accepts an integer, a hex string such as '0x12',
or a decimal string.
The KDC's no-ticket-issued sentinel - 0xffffffff, written on
every failure event - decodes to a NotApplicable result rather than to a cipher.

```yaml
Type: System.Object
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: TicketEtype
  Position: Named
  IsRequired: true
  ValueFromPipeline: true
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

### System.Object

An encryption type value, accepted from the pipeline by value and bound to **-TicketEtype**.
Piping bare numbers therefore decodes them as RFC 3961 ticket encryption types without naming a
parameter. Accepts an integer, a decimal string, or a `0x`-prefixed hexadecimal string.

### System.String[]

A list of Windows encryption type names, bound to **-AdvertizedEtype**. Accepts the
`ClientAdvertizedEncryptionTypes` field of a version 2 event verbatim — a single string whose
entries are separated by newlines and tabs — or an already-split array of names.

## OUTPUTS

### KrbEtypeInsight.TicketEtype

Returned by the **TicketEtype** parameter set. Describes one RFC 3961 encryption type number:
`Value` and `Hex`, the `DisplayName` and `Family`, a `Strength` of `Weak` or `Strong`, the `Rfc`
that defines it, `RemovedByHardening` for the types an RC4 removal takes away, and
`IsRecognized`, which is `$false` for a number outside the catalog rather than an error.

### KrbEtypeInsight.EtypeFlags

Returned by the **SupportedEncryptionTypes** parameter set. Decomposes an MS-KILE 2.2.7 bitmask
into `Flags` and `FlagNames`, the `TicketEtypes` and `SessionKeyEtypes` the bitmask permits, and
the `SupportsDes`, `SupportsRc4`, `SupportsAes` and `SupportsFast` booleans a decision is
usually made on. When the attribute is unset, `IsUnset` is `$true` and `EffectiveValue` carries
what the account actually resolves to — the domain default supplied by
**-DomainDefaultEncryptionTypes**, or the documented fallback when it is omitted. `UnknownBits`
reports bits outside the published specification instead of discarding them.

### KrbEtypeInsight.AdvertizedEtypeSet

Returned by the **AdvertizedEtype** parameter set. Summarises what a client offered: the
original `Names`, the `Etypes` and `Families` they map to, `SupportsAes`, `SupportsRc4` and
`SupportsDes`, and `LegacyOnly` — the property that identifies a client an RC4 removal will
break. `UnrecognizedNames` lists any name absent from the catalog, so an unfamiliar client
stack is visible rather than silently dropped.

## NOTES

Author: Jeffrey Stuhr
Blog: https://www.techbyjeff.net
LinkedIn: https://www.linkedin.com/in/jeffrey-stuhr-034214aa/

TROUBLESHOOTING:
- Unknown or unexpected etype values: .\Troubleshooting\Common\Unknown-Encryption-Types.md
- Bitmask versus ticket etype confusion: .\Troubleshooting\Common\Etype-Numbering-Systems.md


## RELATED LINKS

- [MS-KILE 2.2.7 - Supported Encryption Types Bit Flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919)
- [RFC 3961 - Encryption and Checksum Specifications for Kerberos 5](https://www.rfc-editor.org/rfc/rfc3961)
- [Get-KrbEvent](https://github.com/fadwen/KrbEtypeInsight/blob/main/docs/KrbEtypeInsight/Get-KrbEvent.md)
- [Get-KrbPrincipalEtype](https://github.com/fadwen/KrbEtypeInsight/blob/main/docs/KrbEtypeInsight/Get-KrbPrincipalEtype.md)
