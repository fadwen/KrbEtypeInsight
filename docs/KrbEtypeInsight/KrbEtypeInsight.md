---
document type: module
Help Version: 1.0.0.0
HelpInfoUri: 
Locale: en-US
Module Guid: ba1a8c68-0d77-4a64-b01b-e68d1bbdc810
Module Name: KrbEtypeInsight
ms.date: 08 30 2026
PlatyPS schema version: 2024-05-01
title: KrbEtypeInsight Module
---

# KrbEtypeInsight Module

## Description

Predicts which accounts, services and clients a Kerberos encryption type hardening change
will break, before the change is made. Collects events 4768, 4769 and 4771 from domain
controllers or archived logs, decodes ticket encryption types and msDS-SupportedEncryptionTypes
bitmasks, correlates observed behaviour against directory configuration and domain baseline,
and emits a per-principal risk assessment naming the specific clients that will stop working.

## KrbEtypeInsight

### [ConvertFrom-KrbEtype](ConvertFrom-KrbEtype.md)

Decodes Kerberos encryption type values from any of the three forms Windows emits them in

### [Export-KrbEtypeReport](Export-KrbEtypeReport.md)

Writes a Kerberos encryption type risk assessment to HTML, CSV or JSON

### [Get-KrbDomainEtypeContext](Get-KrbDomainEtypeContext.md)

Collects the domain-wide settings that govern Kerberos encryption type selection

### [Get-KrbEtypeRisk](Get-KrbEtypeRisk.md)

Predicts which principals and clients a Kerberos encryption type hardening change will break

### [Get-KrbEvent](Get-KrbEvent.md)

Collects and decodes Kerberos authentication audit events from domain controllers or archived logs

### [Get-KrbPrincipalEtype](Get-KrbPrincipalEtype.md)

Reads the configured Kerberos encryption type posture of Active Directory principals

