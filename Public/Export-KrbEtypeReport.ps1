#Requires -Version 7.6

function Export-KrbEtypeReport {
    <#
    .EXTERNALHELP KrbEtypeInsight-Help.xml
    .SYNOPSIS
        Writes a Kerberos encryption type risk assessment to HTML, CSV or JSON
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [object[]]$Risk,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [ValidateSet('Html', 'Csv', 'Json')]
        [string]$Format = 'Html',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter()]
        [object]$DomainContext,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        $correlationId = [System.Guid]::NewGuid()
        Write-Verbose "Starting $($MyInvocation.MyCommand.Name) - CorrelationId: $correlationId"

        if (-not $Title) {
            $Title = "Kerberos Encryption Type Risk Assessment - $(Get-Date -Format 'yyyy-MM-dd')"
        }

        # Resolve-Path fails on a path that does not exist yet, which is every output file, so
        # the parent is resolved instead and the leaf appended. This also normalises a
        # relative path against the caller's location rather than the process working
        # directory, which are not the same thing in PowerShell.
        $parent = Split-Path -Path $Path -Parent
        if (-not $parent) { $parent = '.' }

        $resolvedParent = Resolve-Path -Path $parent -ErrorAction SilentlyContinue
        if (-not $resolvedParent) {
            Write-Error "Output directory does not exist: $parent" -ErrorAction Stop
            return
        }

        $outputPath = Join-Path -Path $resolvedParent.Path -ChildPath (Split-Path -Path $Path -Leaf)

        $collected = [System.Collections.Generic.List[object]]::new()
    }

    process {
        foreach ($item in $Risk) {
            if ($item) { $collected.Add($item) }
        }
    }

    end {
        if ($collected.Count -eq 0) {
            Write-Warning ('No risk objects were supplied, so no report was written. An empty ' +
                'assessment means nothing was measured, not that nothing is at risk.')
            return
        }

        if (-not $PSCmdlet.ShouldProcess($outputPath, "Write $Format assessment report")) {
            return
        }

        Write-Verbose "Writing $($collected.Count) risk object(s) as $Format to $outputPath"

        try {
            switch ($Format) {

                'Json' {
                    # Depth 8 reaches through Risk to Findings to Evidence and into the
                    # nested arrays inside Evidence. The default of 2 truncates at Findings
                    # and produces a file whose evidence is the string
                    # 'System.Collections.Hashtable'.
                    $collected | ConvertTo-Json -Depth 8 |
                        Set-Content -Path $outputPath -Encoding utf8 -ErrorAction Stop
                }

                'Csv' {
                    # One row per finding. A principal with four findings is four rows, which
                    # is what makes the file pivotable; one row per principal forces the
                    # findings into a single joined cell and defeats the purpose of using a
                    # spreadsheet.
                    $rows = foreach ($item in $collected) {
                        foreach ($finding in @($item.Findings)) {
                            [PSCustomObject]@{
                                PrincipalName    = $item.PrincipalName
                                Roles            = @($item.Roles) -join ';'
                                RiskLevel        = $item.RiskLevel
                                RiskScore        = $item.RiskScore
                                WillBreak        = $item.WillBreakOnHardening
                                FindingCode      = $finding.Code
                                Severity         = $finding.Severity
                                FindingTitle     = $finding.Title
                                FindingDetail    = $finding.Detail
                                RecommendedAction = $finding.RecommendedAction
                                RequestCount     = $item.RequestCount
                                FailureCount     = $item.FailureCount
                                ClientCount      = $item.ClientCount
                                ClientsWithoutAes = @($item.ClientsWithoutAesSupport) -join ';'
                                ObservedEtypes   = @($item.ObservedTicketEtypeNames) -join ';'
                                AvailableKeys    = @($item.AvailableKeys) -join ';'
                                ConfiguredEtypes = if ($item.ConfiguredEncryptionTypes) {
                                    $item.ConfiguredEncryptionTypes.EffectiveHex
                                } else { $null }
                                FirstSeen        = $item.FirstSeen
                                LastSeen         = $item.LastSeen
                                SchemaVersion2   = $item.EventSchemaVersion2
                            }
                        }
                    }

                    $rows | Export-Csv -Path $outputPath -NoTypeInformation -Encoding utf8 -ErrorAction Stop
                }

                'Html' {
                    $html = New-KrbHtmlReport -Risk $collected.ToArray() -Title $Title `
                        -DomainContext $DomainContext -CorrelationId $correlationId
                    $html | Set-Content -Path $outputPath -Encoding utf8 -ErrorAction Stop
                }
            }
        }
        catch {
            $errorDetails = @{
                CorrelationId = $correlationId
                Function      = $MyInvocation.MyCommand.Name
                OutputPath    = $outputPath
                Format        = $Format
                ErrorMessage  = $_.Exception.Message
                Line          = $_.InvocationInfo.ScriptLineNumber
            }
            Write-Verbose ('Report write failure detail: ' + ($errorDetails | ConvertTo-Json -Compress))
            Write-Error "Failed to write report to '$outputPath': $($_.Exception.Message)" -ErrorAction Stop
            return
        }

        Write-Verbose "Completed $($MyInvocation.MyCommand.Name) - CorrelationId: $correlationId"

        if ($PassThru) { Get-Item -Path $outputPath }
    }
}
