#Requires -Version 7.4

function Get-KrbDomainEtypeContext {
    <#
    .EXTERNALHELP KrbEtypeInsight-Help.xml
    .SYNOPSIS
        Collects the domain-wide settings that govern Kerberos encryption type selection
    #>
    [CmdletBinding()]
    [OutputType('KrbEtypeInsight.DomainContext')]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter()]
        [switch]$SkipRegistry
    )

    begin {
        $correlationId = [System.Guid]::NewGuid()
        Write-Verbose "Starting $($MyInvocation.MyCommand.Name) - CorrelationId: $correlationId"

        if (-not (Get-Module -Name ActiveDirectory)) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
            }
            catch {
                Write-Error ('The ActiveDirectory module is required and could not be loaded. ' +
                    "Error: $($_.Exception.Message)") -ErrorAction Stop
                return
            }
        }

        $catalog = Get-KrbEtypeCatalog
        $adArgs = @{ ErrorAction = 'Stop' }
        if ($Server) { $adArgs['Server'] = $Server }
        if ($Credential) { $adArgs['Credential'] = $Credential }
    }

    process {
        try {
            $domain = Get-ADDomain @adArgs
            $forest = Get-ADForest @adArgs

            # Functional level is expressed as an enum whose ordinal ordering is meaningful,
            # but comparing the enum directly against a literal is fragile across module
            # versions. Matching the year out of the name is stable and reads clearly.
            $domainModeYear = 0
            if ("$($domain.DomainMode)" -match '(\d{4})') { $domainModeYear = [int]$Matches[1] }

            # Below Windows Server 2008 no account in the domain has an AES key, because the
            # KDC never derived one. This is a whole-domain blocker and outranks every
            # per-account finding an assessment could produce.
            $supportsAesKeyDerivation = ($domainModeYear -ge 2008 -or
                "$($domain.DomainMode)" -match '2008|2012|2016|2025|Unknown')

            Write-Verbose "Domain $($domain.DNSRoot) at functional level $($domain.DomainMode)"

            $krbtgt = Get-ADUser -Identity 'krbtgt' `
                -Properties 'msDS-SupportedEncryptionTypes', 'pwdLastSet', 'userAccountControl' @adArgs

            $krbtgtPasswordSet = if ($krbtgt.pwdLastSet -is [datetime]) { $krbtgt.pwdLastSet }
                                 elseif ($krbtgt.pwdLastSet) { [datetime]::FromFileTime([long]$krbtgt.pwdLastSet) }
                                 else { $null }

            $controllers = @(Get-ADDomainController -Filter * @adArgs)
            if ($ComputerName) {
                $controllers = @($controllers | Where-Object {
                    $_.HostName -in $ComputerName -or $_.Name -in $ComputerName
                })
                if (-not $controllers) {
                    Write-Error "None of the supplied computer names matched a domain controller" -ErrorAction Stop
                    return
                }
            }

            # Registry collection. Per-controller and deliberately fault-tolerant: an
            # unreachable controller becomes a row marked unreachable, not a failed run.
            $dcResults = [System.Collections.Generic.List[object]]::new()

            foreach ($dc in $controllers) {
                $reg = @{
                    DefaultDomainSupportedEncTypes = $null
                    PolicySupportedEncryptionTypes = $null
                    Reachable                      = $false
                    Error                          = $null
                }

                if (-not $SkipRegistry) {
                    $readPolicy = {
                        $result = @{
                            DefaultDomainSupportedEncTypes = $null
                            PolicySupportedEncryptionTypes = $null
                        }

                        # KB5021131 places this value directly under the KDC service key, not
                        # under a Parameters subkey. Reading the wrong path returns null,
                        # which is indistinguishable from "not configured" - and "not
                        # configured" is the answer that makes an assessment assume 0x27.
                        $kdc = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
                            -Name 'DefaultDomainSupportedEncTypes' -ErrorAction SilentlyContinue
                        if ($null -ne $kdc) {
                            $result.DefaultDomainSupportedEncTypes = $kdc.DefaultDomainSupportedEncTypes
                        }

                        # What the "Network security: Configure encryption types allowed for
                        # Kerberos" policy writes. On a domain controller this constrains the
                        # KDC itself, which is why it belongs in a domain baseline and not
                        # only in a client one.
                        $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\' +
                            'Policies\System\Kerberos\Parameters'

                        $policy = Get-ItemProperty -Path $policyPath `
                            -Name 'SupportedEncryptionTypes' -ErrorAction SilentlyContinue
                        if ($null -ne $policy) {
                            $result.PolicySupportedEncryptionTypes = $policy.SupportedEncryptionTypes
                        }

                        $result
                    }

                    try {
                        # The local controller is read in-process. Remoting to localhost
                        # requires WinRM to be configured even when the script is running on
                        # the controller itself, and failing there would make the module
                        # unusable in exactly the place it is most likely to be run.
                        $isLocal = $dc.HostName -eq [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName -or
                                   $dc.Name -eq $env:COMPUTERNAME

                        $values = if ($isLocal) {
                            & $readPolicy
                        }
                        else {
                            $icmArgs = @{
                                ComputerName = $dc.HostName
                                ScriptBlock  = $readPolicy
                                ErrorAction  = 'Stop'
                            }
                            if ($Credential) { $icmArgs['Credential'] = $Credential }
                            Invoke-Command @icmArgs
                        }

                        $reg.DefaultDomainSupportedEncTypes =
                            ConvertTo-KrbInt32 -Value $values.DefaultDomainSupportedEncTypes
                        $reg.PolicySupportedEncryptionTypes =
                            ConvertTo-KrbInt32 -Value $values.PolicySupportedEncryptionTypes
                        $reg.Reachable = $true
                    }
                    catch {
                        $reg.Error = $_.Exception.Message
                        Write-Warning ("Could not read Kerberos policy from $($dc.HostName): " +
                            "$($_.Exception.Message). Its contribution to the domain baseline is unknown.")
                    }
                }

                # The version 2 audit schema and the RFC 8009 SHA-2 encryption types both
                # depend on the controller build, so the report can explain a missing field
                # rather than treating it as a finding about the accounts.
                $osVersion = $null
                if ($dc.OperatingSystemVersion -match '^(\d+)\.(\d+)\s*\((\d+)\)') {
                    $osVersion = [int]$Matches[3]
                }

                $dcResults.Add([PSCustomObject]@{
                    PSTypeName = 'KrbEtypeInsight.DomainControllerContext'
                    Name       = $dc.Name
                    HostName   = $dc.HostName
                    Site       = $dc.Site
                    OperatingSystem = $dc.OperatingSystem
                    OperatingSystemBuild = $osVersion
                    IsReadOnly = $dc.IsReadOnly

                    # RFC 8009 SHA-2 encryption types arrived with Windows Server 2025
                    # (build 26100). Below that a SHA-2 etype in a report can only have come
                    # from a non-Windows KDC.
                    SupportsSha2Etypes = if ($osVersion) { $osVersion -ge 26100 } else { $null }

                    RegistryReachable = $reg.Reachable
                    RegistryError     = $reg.Error
                    DefaultDomainSupportedEncTypes = $reg.DefaultDomainSupportedEncTypes
                    DefaultDomainSupportedEncTypesDecoded = if ($null -ne $reg.DefaultDomainSupportedEncTypes) {
                        ConvertFrom-KrbEtype -SupportedEncryptionTypes $reg.DefaultDomainSupportedEncTypes
                    } else { $null }
                    PolicySupportedEncryptionTypes = $reg.PolicySupportedEncryptionTypes
                    PolicySupportedEncryptionTypesDecoded = if ($null -ne $reg.PolicySupportedEncryptionTypes) {
                        ConvertFrom-KrbEtype -SupportedEncryptionTypes $reg.PolicySupportedEncryptionTypes
                    } else { $null }
                    AgreesWithDomainDefault = $null   # filled in below, once the majority is known
                })
            }

            # Establish the effective domain default by majority vote. Where controllers
            # disagree, the most common EFFECTIVE value wins and the disagreement becomes a
            # finding - picking the first controller's value instead would make the whole
            # assessment depend on which controller happened to answer first.
            #
            # Every REACHABLE controller votes, including one whose registry value is absent.
            # That is the correction a real two-controller lab forced. An unset controller is
            # not abstaining: the KDC on it falls back to the documented Windows default of
            # 0x27, which is as much a position as any explicit value. Counting only the
            # explicitly-configured controllers - which is what this did - produces two
            # specific failures, and a domain with one configured and one unset controller
            # hits both at once:
            #
            #   1. One controller on 0x1C and one unset yields a single "configured" entry,
            #      so the group count is 1 and ControllersDisagreeOnDefault comes back FALSE
            #      while the controllers genuinely disagree. That is the exact condition the
            #      property exists to detect, silently inverted.
            #   2. The domain default resolves to 0x1C, so the UNSET controller then fails the
            #      agreement test and is named as the outlier - while the controller actually
            #      holding the divergent value is reported as agreeing.
            #
            # An UNREACHABLE controller is different again and must not vote. Its value is
            # unknown, not default, and folding it into the tally would let a firewalled or
            # RPC-blocked controller manufacture a majority. It is scored $null below.
            $voting = @($dcResults | Where-Object { $_.RegistryReachable -or $SkipRegistry })

            $votes = @(
                foreach ($row in $voting) {
                    if ($null -ne $row.DefaultDomainSupportedEncTypes) {
                        $row.DefaultDomainSupportedEncTypes
                    }
                    else {
                        $catalog.DefaultDomainSupportedEncTypes
                    }
                }
            )

            $domainDefault = $catalog.DefaultDomainSupportedEncTypes
            $domainDefaultSource = 'WindowsDefault'
            $controllersDisagree = $false

            if ($votes.Count -gt 0) {
                $grouped = @($votes | Group-Object | Sort-Object Count -Descending)
                $controllersDisagree = ($grouped.Count -gt 1)

                # Ties are resolved toward the Windows default rather than arbitrarily.
                #
                # A two-controller domain with one value set and one unset is a 1-1 split, and
                # there is no majority to take. Sort-Object then returns whichever group it
                # happened to order first, which made the outlier identification a coin flip -
                # and on the real pair it landed on the wrong one, naming the UNSET controller
                # as deviating from a default derived solely from the OTHER controller's
                # explicit value.
                #
                # The tie-break encodes what an administrator means by "the domain default":
                # an unset controller is running documented Windows behaviour, and a
                # controller carrying an explicit different value is the deliberate deviation.
                # So where the tied values include the Windows default, that wins. Where they
                # do not, the lowest value wins - arbitrary, but deterministic, which matters
                # more than which one is chosen when nothing distinguishes them.
                $top = @($grouped | Where-Object { $_.Count -eq $grouped[0].Count })

                if ($top.Count -eq 1) {
                    $domainDefault = [int]$top[0].Name
                }
                elseif (@($top | Where-Object { [int]$_.Name -eq $catalog.DefaultDomainSupportedEncTypes })) {
                    $domainDefault = $catalog.DefaultDomainSupportedEncTypes
                }
                else {
                    $domainDefault = [int](@($top.Name | Sort-Object { [int]$_ })[0])
                }

                # Sourced from the registry only if at least one controller actually had the
                # value written. A domain where every controller is unset is running the
                # documented default, and saying otherwise would present an assumption as a
                # measurement.
                if (@($voting | Where-Object { $null -ne $_.DefaultDomainSupportedEncTypes }).Count -gt 0) {
                    $domainDefaultSource = 'Registry'
                }
            }

            foreach ($row in $dcResults) {
                # Three states, and the third is the one that was missing. A controller whose
                # registry could not be read has an UNKNOWN position, not an agreeing one.
                # Scoring it $true - which is what comparing its absent value against the
                # Windows default did - means a firewalled or RPC-blocked controller reads as
                # consensus, and the operator sees agreement built partly from controllers
                # nobody actually asked. $null keeps "unknown" distinct from "agrees", and
                # RegistryError already carries the reason.
                $row.AgreesWithDomainDefault = if (-not ($row.RegistryReachable -or $SkipRegistry)) {
                    $null
                }
                elseif ($null -eq $row.DefaultDomainSupportedEncTypes) {
                    # Reachable and unset. The KDC falls back to the Windows default, so this
                    # controller agrees when that is what the domain resolved to.
                    $domainDefault -eq $catalog.DefaultDomainSupportedEncTypes
                }
                else {
                    $row.DefaultDomainSupportedEncTypes -eq $domainDefault
                }
            }

            if ($controllersDisagree) {
                Write-Warning ('Domain controllers do not agree on DefaultDomainSupportedEncTypes. ' +
                    'Clients will authenticate differently depending on which controller they reach, ' +
                    'which produces intermittent failures that cannot be reproduced on demand. ' +
                    'Inspect the DomainControllers collection on the returned object.')
            }

            # Trusts. A trust that omits AES pins every cross-realm ticket to RC4 no matter
            # what the accounts on either side support.
            $trusts = @(
                try {
                    Get-ADTrust -Filter * -Properties 'msDS-SupportedEncryptionTypes', 'trustAttributes' @adArgs |
                        ForEach-Object {
                            $trustEtypes = $_.'msDS-SupportedEncryptionTypes'
                            [PSCustomObject]@{
                                PSTypeName  = 'KrbEtypeInsight.TrustContext'
                                Name        = $_.Name
                                Target      = $_.Target
                                Direction   = $_.Direction
                                TrustType   = $_.TrustType
                                IsIntraForest = $_.IntraForest
                                SelectiveAuthentication = $_.SelectiveAuthentication
                                SupportedEncryptionTypesRaw = $trustEtypes
                                EncryptionTypes = ConvertFrom-KrbEtype -SupportedEncryptionTypes $trustEtypes `
                                    -DomainDefaultEncryptionTypes $domainDefault

                                # An intra-forest trust inherits the forest's behaviour and is
                                # rarely the problem. An external or forest trust with no AES
                                # bit is a hard blocker for cross-realm hardening and needs
                                # the other side's cooperation to fix, which makes it the
                                # longest-lead item in most projects.
                                IsCrossRealmRc4Risk = (-not $_.IntraForest) -and
                                    (-not (ConvertFrom-KrbEtype -SupportedEncryptionTypes $trustEtypes `
                                        -DomainDefaultEncryptionTypes $domainDefault).SupportsAes)
                            }
                        }
                }
                catch {
                    Write-Warning "Could not enumerate trusts: $($_.Exception.Message)"
                }
            )

            $krbtgtEtypes = ConvertFrom-KrbEtype `
                -SupportedEncryptionTypes $krbtgt.'msDS-SupportedEncryptionTypes' `
                -DomainDefaultEncryptionTypes $domainDefault

            [PSCustomObject]@{
                PSTypeName = 'KrbEtypeInsight.DomainContext'

                DomainName     = $domain.DNSRoot
                NetBiosName    = $domain.NetBIOSName
                DomainSid      = $domain.DomainSID.Value
                DomainMode     = "$($domain.DomainMode)"
                ForestName     = $forest.Name
                ForestMode     = "$($forest.ForestMode)"

                SupportsAesKeyDerivation = $supportsAesKeyDerivation

                DomainDefaultEncryptionTypes = $domainDefault
                DomainDefaultDecoded = ConvertFrom-KrbEtype -SupportedEncryptionTypes $domainDefault

                # Whether the baseline was measured or assumed. Every downstream conclusion
                # about an account with an unset attribute inherits this uncertainty, so it
                # travels with the data rather than living only in a log line.
                DomainDefaultSource = $domainDefaultSource
                ControllersDisagreeOnDefault = $controllersDisagree

                KrbtgtEncryptionTypes = $krbtgtEtypes
                KrbtgtSupportedEncryptionTypesRaw = $krbtgt.'msDS-SupportedEncryptionTypes'
                KrbtgtPasswordLastSet = $krbtgtPasswordSet
                KrbtgtPasswordAgeDays = if ($krbtgtPasswordSet) {
                    [int]((Get-Date) - $krbtgtPasswordSet).TotalDays
                } else { $null }

                DomainControllers = @($dcResults)
                Trusts            = $trusts
                TrustsWithRc4Only = @($trusts | Where-Object { $_.IsCrossRealmRc4Risk })

                CollectedAt   = Get-Date
                CorrelationId = $correlationId
            }
        }
        catch {
            $errorDetails = @{
                CorrelationId = $correlationId
                Function      = $MyInvocation.MyCommand.Name
                ErrorMessage  = $_.Exception.Message
                Line          = $_.InvocationInfo.ScriptLineNumber
            }
            Write-Verbose ('Domain context failure detail: ' + ($errorDetails | ConvertTo-Json -Compress))
            Write-Error ("Failed to collect domain encryption type context: " +
                $_.Exception.Message) -ErrorAction Stop
        }
    }

    end {
        Write-Verbose "Completed $($MyInvocation.MyCommand.Name) - CorrelationId: $correlationId"
    }
}
