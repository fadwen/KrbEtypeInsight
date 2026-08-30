#Requires -Version 7.6

function Get-KrbEvent {
    <#
    .EXTERNALHELP KrbEtypeInsight-Help.xml
    .SYNOPSIS
        Collects and decodes Kerberos authentication audit events from domain controllers or archived logs
    #>
    [CmdletBinding(DefaultParameterSetName = 'LiveDomain')]
    [OutputType('KrbEtypeInsight.Event')]
    param(
        [Parameter(ParameterSetName = 'LiveDomain')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Path')]
        [ValidateNotNullOrEmpty()]
        [Alias('FullName')]
        [string[]]$Path,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        # Get-KrbEtypeRisk models only these three events. Accepting adjacent Kerberos
        # audit IDs here made Get-KrbEvent appear to support them even though the risk
        # engine silently omitted them from its assessment.
        [ValidateSet(4768, 4769, 4771)]
        [int[]]$EventId = @(4768, 4769, 4771),

        [Parameter()]
        [datetime]$StartTime = (Get-Date).AddDays(-30),

        [Parameter()]
        [datetime]$EndTime = (Get-Date),

        [Parameter()]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$MaxEvents = 50000,

        [Parameter(ParameterSetName = 'LiveDomain')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter()]
        [switch]$IncludeFailureOnly
    )

    begin {
        $correlationId = [System.Guid]::NewGuid()
        Write-Verbose "Starting $($MyInvocation.MyCommand.Name) - CorrelationId: $correlationId"

        if ($StartTime -ge $EndTime) {
            Write-Error "StartTime ($StartTime) must be earlier than EndTime ($EndTime)" -ErrorAction Stop
            return
        }

        $totalEmitted = 0
        $totalRead = 0
        $failuresSeen = 0
        $sourcesRead = 0
        $sourcesEmpty = [System.Collections.Generic.List[string]]::new()

        # Resolved once so the two collection paths share exactly one filter construction.
        # Time bounds are included here rather than applied afterwards because the log
        # service evaluates them before a single record crosses the network.
        $baseFilter = @{
            Id        = $EventId
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        # Get-WinEvent treats -MaxEvents 0 as an error rather than as "unlimited", so the
        # unlimited case is expressed by omitting the parameter entirely.
        $readerArgs = @{ ErrorAction = 'Stop' }
        if ($MaxEvents -gt 0) { $readerArgs['MaxEvents'] = $MaxEvents }
    }

    process {
        # Build the source list for this invocation. In the Path set this runs once per
        # pipeline item, which is what makes Get-ChildItem | Get-KrbEvent stream.
        $sources = switch ($PSCmdlet.ParameterSetName) {

            'Path' {
                foreach ($item in $Path) {
                    $resolved = Resolve-Path -Path $item -ErrorAction SilentlyContinue
                    if (-not $resolved) {
                        Write-Error "Archived log not found: $item"
                        continue
                    }
                    foreach ($file in $resolved) {
                        [PSCustomObject]@{
                            Name   = Split-Path -Path $file.Path -Leaf
                            Filter = $baseFilter + @{ Path = $file.Path }
                            Remote = @{}
                        }
                    }
                }
            }

            'LiveDomain' {
                $targets = $ComputerName
                if (-not $targets) {
                    try {
                        $targets = @(Get-ADDomainController -Filter * -ErrorAction Stop |
                            Select-Object -ExpandProperty HostName)
                        Write-Verbose "Discovered $($targets.Count) domain controller(s)"
                    }
                    catch {
                        Write-Error ("Could not enumerate domain controllers. Supply -ComputerName " +
                            "explicitly, or use -Path against archived logs. Error: $($_.Exception.Message)") `
                            -ErrorAction Stop
                        return
                    }
                }

                foreach ($target in $targets) {
                    $remote = @{ ComputerName = $target }
                    if ($Credential) { $remote['Credential'] = $Credential }

                    [PSCustomObject]@{
                        Name   = $target
                        Filter = $baseFilter + @{ LogName = 'Security' }
                        Remote = $remote
                    }
                }
            }
        }

        foreach ($source in $sources) {
            $sourcesRead++
            Write-Verbose "Reading $($source.Name) - CorrelationId: $correlationId"
            Write-Progress -Activity 'Collecting Kerberos events' -Status $source.Name `
                -CurrentOperation "$totalEmitted events decoded so far"

            $emittedFromSource = 0

            # Splatting needs a variable, not a property expression - @($source.Remote) is an
            # array subexpression and would pass the hashtable as a single positional
            # argument rather than binding ComputerName and Credential.
            $remoteArgs = $source.Remote

            try {
                # -ErrorAction Stop turns "no events matched" into a catchable terminating
                # error, which is the only way to distinguish it from a genuine empty result
                # and report it as the audit-policy problem it usually is.
                $records = Get-WinEvent -FilterHashtable $source.Filter @readerArgs @remoteArgs
            }
            catch [System.Exception] {
                # Get-WinEvent raises the same exception type for "no matching events" as for
                # real faults, so the message is the only discriminator available.
                if ($_.Exception.Message -match 'No events were found') {
                    $sourcesEmpty.Add($source.Name)
                    Write-Verbose "No matching events on $($source.Name) in the requested window"
                    continue
                }

                $errorDetails = @{
                    Source        = $source.Name
                    CorrelationId = $correlationId
                    Function      = $MyInvocation.MyCommand.Name
                    ErrorMessage  = $_.Exception.Message
                    Line          = $_.InvocationInfo.ScriptLineNumber
                }
                Write-Verbose ("Collection failure detail: " + ($errorDetails | ConvertTo-Json -Compress))

                # One unreachable controller must not abandon the others. The assessment is
                # still valid over the controllers that answered, provided the report says
                # which ones did not - which is why this is a non-terminating error.
                #
                # "The RPC server is unavailable" gets named, because on a domain controller
                # it almost never means the machine is down. Get-WinEvent -ComputerName uses
                # the legacy Event Log RPC protocol, which needs the dynamic RPC range as well
                # as port 135, and the firewall rules that open it - the Remote Event Log
                # Management group - are DISABLED by default on a fresh Windows install.
                #
                # Measured: a healthy, replicating Server 2025 domain controller, reachable on
                # 135, 445, 5985, 389 and 88, answering WinRM perfectly, returned this error
                # for every single event log call. Its Security log held 6,703 records the
                # whole time. Without naming the cause this reads as "that DC is broken", and
                # an assessment run with -ErrorAction SilentlyContinue simply omits the
                # controller and reports a confident result over a fraction of the estate.
                $message = "Failed to read Kerberos events from $($source.Name): $($_.Exception.Message)"

                if ($_.Exception.Message -match 'RPC server is unavailable') {
                    $message += (' The host is usually reachable and this is usually the ' +
                        'firewall: Get-WinEvent uses Event Log RPC, whose rules are off by ' +
                        'default. Enable them on that controller with ' +
                        "Enable-NetFirewallRule -DisplayGroup 'Remote Event Log Management', " +
                        'or collect from an archived .evtx instead.')
                }

                Write-Error $message
                continue
            }

            # Read and emitted are counted separately. Conflating them made a source that
            # returned plenty of events but no FAILURES - which under -IncludeFailureOnly is
            # simply a healthy controller - report as empty, and the end block then advised
            # the operator to go and check whether Kerberos auditing was enabled. That advice
            # fired hardest during post-change verification, the one moment the module's
            # empty-collection warning most needs to mean what it says.
            $readFromSource = 0

            foreach ($record in $records) {
                $decoded = ConvertFrom-KrbEventRecord -Record $record -SourceName $source.Name
                if (-not $decoded) { continue }

                $readFromSource++
                if ($decoded.IsFailure) { $failuresSeen++ }

                if ($IncludeFailureOnly -and -not $decoded.IsFailure) { continue }

                $emittedFromSource++
                $totalEmitted++
                $decoded
            }

            $totalRead += $readFromSource

            # Only a source that produced no events AT ALL is evidence of an auditing or
            # retention problem.
            if ($readFromSource -eq 0) { $sourcesEmpty.Add($source.Name) }
            elseif ($emittedFromSource -eq 0) {
                Write-Verbose ("$($source.Name) returned $readFromSource event(s), none matching " +
                    'the requested filter')
            }
        }
    }

    end {
        Write-Progress -Activity 'Collecting Kerberos events' -Completed

        # An empty collection is the failure mode that most often goes unnoticed, because it
        # looks exactly like a clean domain. Saying so explicitly is the difference between
        # an assessment that found nothing and an assessment that measured nothing.
        if ($sourcesEmpty.Count -gt 0) {
            $names = $sourcesEmpty -join ', '
            Write-Warning ("No Kerberos events matched on: $names. Check that the " +
                "'Kerberos Authentication Service' and 'Kerberos Service Ticket Operations' " +
                "audit subcategories are enabled, and that the requested window " +
                "($StartTime to $EndTime) is inside the log's retention.")
        }

        # Gated on events READ, not on events emitted. A collection that read plenty and
        # emitted none because -IncludeFailureOnly filtered them all is a healthy domain, and
        # telling its operator that the assessment "will describe an empty domain rather than
        # a clean one" is precisely backwards - it IS a clean one, and that is the answer
        # they were looking for.
        if ($sourcesRead -gt 0 -and $totalRead -eq 0) {
            Write-Warning ("Read $sourcesRead source(s) and decoded no events. Any assessment " +
                'built on this collection will describe an empty domain rather than a clean one.')
        }

        if ($IncludeFailureOnly -and $totalRead -gt 0 -and $totalEmitted -eq 0) {
            # Worth stating positively. Silence here reads as a failed collection, when it is
            # the result a post-change verification hopes for.
            Write-Verbose ("Read $totalRead event(s) across $sourcesRead source(s) and none were " +
                'failures.')
        }

        # Success-only audit policy is the module's remaining blind spot, and it was found by
        # running this against a domain that had it. The two Kerberos subcategories can be set
        # to Success without Failure, which is not the default but is common - and in that
        # state the KDC logs no 4771 at all and no failed 4769. A post-change verification
        # then returns nothing and reads as "the change broke nothing", when in truth nothing
        # capable of recording breakage was ever switched on.
        #
        # Inferred from the collection rather than by reading audit policy, which would need
        # local administrator on every controller for a module that otherwise needs only
        # Event Log Reader. Asking for 4771 and receiving none while thousands of successes
        # came back is not proof, but it is the shape the misconfiguration makes.
        if ($EventId -contains 4771 -and $totalRead -gt 100 -and $failuresSeen -eq 0) {
            Write-Warning ("Collected $totalRead event(s) and not one failure, including zero " +
                '4771s. That is what a domain with the Kerberos audit subcategories set to ' +
                'Success without Failure looks like. Confirm with: auditpol /get /subcategory:' +
                '"Kerberos Authentication Service" - if Failure is not enabled, this collection ' +
                'cannot show breakage and must not be read as showing none.')
        }

        Write-Verbose ("Completed $($MyInvocation.MyCommand.Name) - $totalEmitted of $totalRead " +
            "event(s) from $sourcesRead source(s) - CorrelationId: $correlationId")
    }
}
