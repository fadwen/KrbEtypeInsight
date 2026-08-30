---
document type: cmdlet
external help file: KrbEtypeInsight-Help.xml
HelpUri: ''
Locale: en-US
Module Name: KrbEtypeInsight
ms.date: 08 30 2026
PlatyPS schema version: 2024-05-01
title: Export-KrbEtypeReport
---

# Export-KrbEtypeReport

## SYNOPSIS

Writes a Kerberos encryption type risk assessment to HTML, CSV or JSON

## SYNTAX

### __AllParameterSets

```
Export-KrbEtypeReport [-Risk] <Object[]> [-Path] <string> [[-Format] <string>] [[-Title] <string>]
 [[-DomainContext] <Object>] [-PassThru] [-WhatIf] [-Confirm]
```


## DESCRIPTION

Renders the output of Get-KrbEtypeRisk into a form that can be circulated, attached
to a change record, or diffed against a previous run.

Three formats, for three different readers:

- Html produces a single self-contained file with a summary, a prioritised table and
  the evidence behind every finding.
No external stylesheet, script or font is
  referenced, so it survives being emailed, dropped on a file share, or opened on a
  machine with no internet access - which is the machine most people open a security
  report on.
It is the format to send to an application owner.

- Csv produces one row per finding rather than one row per principal, because a
  principal with four findings needs four rows to be filtered and pivoted usefully in
  a spreadsheet.
Evidence is flattened to text.

- Json preserves the object graph including all evidence, and is the format to keep
  for comparison against the next run.
This is what makes "KRB002 is down from 40
  accounts to 3" answerable.

Content is HTML-encoded on the way in.
Every principal name, service name and client
address in this report originated in the event log, written there by whoever made the
request - a service principal name is chosen by the client and can contain markup.
An
assessment report that renders its input verbatim is a stored cross-site scripting
vector aimed at the person reading it, which is a poor way to end a security review.

## EXAMPLES

### Example 1: Produces the standard assessment report

```powershell
Get-KrbEvent | Get-KrbEtypeRisk | Export-KrbEtypeReport -Path .\krb-risk.html
```

Output: A self-contained HTML file.

Use case: The artefact to attach to a change request.

### Example 2: A report that states the baseline it was judged against

```powershell
$context = Get-KrbDomainEtypeContext
PS> Get-KrbEvent | Get-KrbEtypeRisk -DomainContext $context |
    Export-KrbEtypeReport -Path .\krb-risk.html -DomainContext $context `
    -Title 'RC4 removal readiness - Phase 1'
```

Output: HTML including the domain functional level and per-controller policy.

Use case: A report that will be read by someone who was not in the room.

### Example 3: Preserves the full object graph for comparison

```powershell
Get-KrbEvent | Get-KrbEtypeRisk | Export-KrbEtypeReport -Path .\krb-risk.json -Format Json
```

Output: JSON with all evidence retained.

Use case: Establishing the baseline for a quarterly trend.

## PARAMETERS

### -Confirm

Prompts you for confirmation before running the cmdlet.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: ''
SupportsWildcards: false
Aliases:
- cf
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

### -DomainContext

[System.Object] (Optional, No Pipeline Support)

Domain baseline from Get-KrbDomainEtypeContext.
When supplied, the HTML report opens
with the functional level, domain default and controller agreement that the findings
were judged against - without which a reader cannot tell whether the baseline was
measured or assumed.

```yaml
Type: System.Object
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 4
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Format

[System.String] (Optional, No Pipeline Support)

Html, Csv or Json.
Defaults to Html.

```yaml
Type: System.String
DefaultValue: Html
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

### -PassThru

[System.Management.Automation.SwitchParameter] (Optional, No Pipeline Support)

Return the written file as a FileInfo object.

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

### -Path

[System.String] (Mandatory, No Pipeline Support)

Destination file.
The parent directory must exist.

```yaml
Type: System.String
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 1
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Risk

[System.Object[]] (Mandatory, Pipeline: ByValue)

Risk objects from Get-KrbEtypeRisk.

```yaml
Type: System.Object[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
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

### -Title

[System.String] (Optional, No Pipeline Support)

Report heading.
Defaults to a generic title with the current date.

```yaml
Type: System.String
DefaultValue: ''
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

### -WhatIf

Runs the command in a mode that only reports what would happen without performing the actions.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: ''
SupportsWildcards: false
Aliases:
- wi
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

### KrbEtypeInsight.Risk

Risk objects from `Get-KrbEtypeRisk`, accepted from the pipeline by value. The whole collection
is buffered before rendering, because the report's summary counts and its ordering are
properties of the set rather than of any one object.

## OUTPUTS

### None

By default this cmdlet writes a file and returns nothing, so it can end a pipeline without
producing console output.

### System.IO.FileInfo

When **-PassThru** is specified, the written file is returned — for a subsequent `Send-MailMessage`,
an upload, or an attachment step in a pipeline.

## NOTES

Author: Jeffrey Stuhr
Blog: https://www.techbyjeff.net
LinkedIn: https://www.linkedin.com/in/jeffrey-stuhr-034214aa/

The report names accounts, service principal names and client addresses.
Handle it as
an internal document.

TROUBLESHOOTING:
- Report rendering: .\Troubleshooting\Common\Report-Output.md


## RELATED LINKS

- [KB5021131 - Managing the Kerberos protocol changes for CVE-2022-37966](https://support.microsoft.com/help/5021131)
- [Get-KrbEtypeRisk]()
- [Get-KrbEvent]()
- [about_KrbEtypeInsight]()
