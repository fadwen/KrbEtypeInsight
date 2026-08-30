#Requires -Version 7.4

function Get-KrbPrincipalEtype {
    <#
    .EXTERNALHELP KrbEtypeInsight-Help.xml
    .SYNOPSIS
        Reads the configured Kerberos encryption type posture of Active Directory principals
    #>

    # Two false positives from PSReviewUnusedParameter, suppressed with the reasoning here
    # because a SuppressMessageAttribute Justification must be a single unwrappable literal.
    #
    # -All is a parameter set discriminator. It is never read by name because the switch on
    # $PSCmdlet.ParameterSetName is what consumes it; removing it would remove the only way
    # to select the enumeration set.
    #
    # -DomainDefaultEncryptionTypes is used inside the $newPrincipal script block, which the
    # analyzer does not follow into. Removing it would silently judge every account with an
    # unset encryption type attribute against the wrong baseline.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'All',
        Justification = 'Parameter set discriminator. See comment above.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DomainDefaultEncryptionTypes',
        Justification = 'Used in the newPrincipal script block. See comment above.')]
    [CmdletBinding(DefaultParameterSetName = 'All')]
    [OutputType('KrbEtypeInsight.Principal')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Identity')]
        [ValidateNotNullOrEmpty()]
        [Alias('SamAccountName', 'DistinguishedName')]
        [string[]]$Identity,

        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName,
            ParameterSetName = 'ServicePrincipalName')]
        [ValidateNotNullOrEmpty()]
        [Alias('ServiceName', 'Spn')]
        [string[]]$ServicePrincipalName,

        [Parameter(Mandatory, ParameterSetName = 'All')]
        [switch]$All,

        [Parameter(ParameterSetName = 'All')]
        [switch]$ServiceAccountOnly,

        [Parameter(ParameterSetName = 'All')]
        [switch]$IncludeDisabled,

        [Parameter()]
        [int]$DomainDefaultEncryptionTypes = 0x27,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
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
                    "Install RSAT or run from a domain controller. Error: $($_.Exception.Message)") `
                    -ErrorAction Stop
                return
            }
        }

        # The full property set every path needs. Named explicitly rather than using
        # -Properties * because the wildcard pulls constructed and back-linked attributes
        # that cost the directory real work - memberOf and tokenGroups among them - for data
        # this function never reads.
        $properties = @(
            # sAMAccountName is NOT one of Get-ADObject's default properties - that set is
            # DistinguishedName, Name, ObjectClass and ObjectGUID only. Omitting it here
            # produces principal objects whose SamAccountName is silently empty, which then
            # becomes an empty key in the risk engine's account index and quietly loses the
            # correlation between events and directory configuration for every account.
            'sAMAccountName'
            'msDS-SupportedEncryptionTypes'
            'userAccountControl'
            'servicePrincipalName'
            'pwdLastSet'
            'whenCreated'
            'lastLogonTimestamp'
            'displayName'
            'description'
            'objectClass'
            'objectSid'
        )

        $adArgs = @{ ErrorAction = 'Stop' }
        if ($Server) { $adArgs['Server'] = $Server }
        if ($Credential) { $adArgs['Credential'] = $Credential }

        $now = Get-Date

        # Local function so the three parameter sets share one construction. Anything that
        # produces a Principal object goes through here, which is what keeps the output
        # schema identical no matter how the account was found.
        $newPrincipal = {
            param($adObject)

            $rawEtypes = $adObject.'msDS-SupportedEncryptionTypes'
            $spns = @($adObject.'servicePrincipalName')

            # pwdLastSet arrives as a FILETIME integer from Get-ADObject and as a DateTime
            # from Get-ADUser. Both shapes reach this function, so both are handled - a
            # missing conversion here silently produces a null password age, which reads in
            # the report as "age unknown" on precisely the accounts whose age matters most.
            $passwordLastSet = $null
            $raw = $adObject.'pwdLastSet'
            if ($raw -is [datetime]) {
                $passwordLastSet = $raw
            }
            elseif ($raw -and $raw -gt 0) {
                $passwordLastSet = [datetime]::FromFileTime([long]$raw)
            }

            $lastLogon = $null
            $rawLogon = $adObject.'lastLogonTimestamp'
            if ($rawLogon -is [datetime]) { $lastLogon = $rawLogon }
            elseif ($rawLogon -and $rawLogon -gt 0) { $lastLogon = [datetime]::FromFileTime([long]$rawLogon) }

            $control = ConvertFrom-KrbAccountControl -UserAccountControl $adObject.'userAccountControl'

            $etypes = ConvertFrom-KrbEtype -SupportedEncryptionTypes $rawEtypes `
                -DomainDefaultEncryptionTypes $DomainDefaultEncryptionTypes

            # objectClass is multi-valued and ordered least to most specific, so the last
            # entry is the one that names what the object actually is. Taking the first
            # returns 'top' for every object in the directory.
            $classes = @($adObject.objectClass)
            $objectClass = if ($classes) { $classes[-1] } else { $null }

            [PSCustomObject]@{
                PSTypeName        = 'KrbEtypeInsight.Principal'

                SamAccountName    = $adObject.SamAccountName
                DistinguishedName = $adObject.DistinguishedName
                Sid               = if ($adObject.objectSid) { $adObject.objectSid.Value } else { $null }
                ObjectClass       = $objectClass
                DisplayName       = $adObject.displayName
                Description       = $adObject.description

                # Enabled is derived from the account control bit rather than the ADAccount
                # Enabled property, because Get-ADObject does not supply that property and
                # this function must return the same schema whichever cmdlet found the object.
                Enabled           = if ($null -ne $control.Disabled) { -not $control.Disabled } else { $null }

                SupportedEncryptionTypesRaw = $rawEtypes
                EncryptionTypes   = $etypes
                AccountControl    = $control

                ServicePrincipalNames = $spns
                HasSpn            = ($spns.Count -gt 0)

                PasswordLastSet   = $passwordLastSet
                PasswordAgeDays   = if ($passwordLastSet) {
                    [int]($now - $passwordLastSet).TotalDays
                } else { $null }
                WhenCreated       = $adObject.whenCreated
                LastLogonTimestamp = $lastLogon

                # krbtgt is called out because its encryption types govern TGT issuance for
                # the entire domain. It is never a per-account finding and must never be
                # treated as one, but a report that omits it entirely has skipped the single
                # most consequential object in the assessment.
                IsKrbtgt          = ($adObject.SamAccountName -eq 'krbtgt' -or
                                     $adObject.SamAccountName -like 'krbtgt_*')

                CorrelationId     = $correlationId
            }
        }
    }

    process {
        try {
            switch ($PSCmdlet.ParameterSetName) {

                'Identity' {
                    foreach ($id in $Identity) {
                        if (-not $id.Trim()) {
                            Write-Error 'Identity cannot be empty or whitespace'
                            continue
                        }

                        try {
                            $found = Get-ADObject -Identity $id.Trim() -Properties $properties @adArgs
                        }
                        catch {
                            # Get-ADObject -Identity only accepts a DN or GUID. A
                            # sAMAccountName is the form an administrator actually has to
                            # hand, so fall back to a search rather than making the caller
                            # know the difference.
                            $escaped = ConvertTo-KrbLdapFilterValue -Value $id.Trim()
                            $found = @(Get-ADObject -LDAPFilter "(sAMAccountName=$escaped)" `
                                    -Properties $properties @adArgs)

                            if (-not $found) {
                                Write-Error "No account found matching identity '$id'"
                                continue
                            }
                        }

                        foreach ($item in @($found)) { & $newPrincipal $item }
                    }
                }

                'ServicePrincipalName' {
                    foreach ($spn in $ServicePrincipalName) {
                        if (-not $spn.Trim()) {
                            Write-Error 'ServicePrincipalName cannot be empty or whitespace'
                            continue
                        }

                        $escaped = ConvertTo-KrbLdapFilterValue -Value $spn.Trim()
                        $found = @(Get-ADObject -LDAPFilter "(servicePrincipalName=$escaped)" `
                                -Properties $properties @adArgs)

                        if (-not $found) {
                            # A 4769 ServiceName is frequently a bare account name rather
                            # than a full SPN - that is how the KDC writes it when the
                            # request named the account directly - so retry as one before
                            # giving up.
                            $found = @(Get-ADObject -LDAPFilter "(sAMAccountName=$escaped)" `
                                    -Properties $properties @adArgs)
                        }

                        if (-not $found) {
                            Write-Error ("No account owns service principal name '$spn'. An SPN in " +
                                'the event log with no owner in the directory usually means the ' +
                                'account was deleted or the SPN was moved.')
                            continue
                        }

                        if ($found.Count -gt 1) {
                            # Duplicate SPNs are a real and damaging misconfiguration: the KDC
                            # returns KDC_ERR_PRINCIPAL_NOT_UNIQUE and the service fails for
                            # everyone. Worth surfacing here even though it is not an
                            # encryption-type problem, because an assessment is when it gets found.
                            Write-Warning ("Service principal name '$spn' is registered on " +
                                "$($found.Count) accounts, which will cause authentication failures " +
                                'independently of any encryption type change.')
                        }

                        foreach ($item in $found) { & $newPrincipal $item }
                    }
                }

                'All' {
                    $clauses = [System.Collections.Generic.List[string]]::new()
                    $clauses.Add('(|(objectCategory=person)(objectCategory=computer))')

                    if ($ServiceAccountOnly) { $clauses.Add('(servicePrincipalName=*)') }

                    # userAccountControl:1.2.840.113556.1.4.803: is the LDAP_MATCHING_RULE_BIT_AND
                    # operator. Filtering disabled accounts server-side keeps a large domain's
                    # tombstoned service accounts out of the result set entirely rather than
                    # transferring them to be discarded locally.
                    if (-not $IncludeDisabled) {
                        $clauses.Add('(!(userAccountControl:1.2.840.113556.1.4.803:=2))')
                    }

                    $ldapFilter = '(&' + ($clauses -join '') + ')'
                    Write-Verbose "Enumerating principals with filter: $ldapFilter"

                    $found = Get-ADObject -LDAPFilter $ldapFilter -Properties $properties @adArgs

                    $count = 0
                    foreach ($item in $found) {
                        $count++
                        if ($count % 500 -eq 0) {
                            Write-Progress -Activity 'Reading principal encryption types' `
                                -Status "$count accounts processed"
                        }
                        & $newPrincipal $item
                    }

                    Write-Progress -Activity 'Reading principal encryption types' -Completed
                    Write-Verbose "Enumerated $count principal(s)"
                }
            }
        }
        catch {
            $errorDetails = @{
                CorrelationId = $correlationId
                Function      = $MyInvocation.MyCommand.Name
                ErrorMessage  = $_.Exception.Message
                Line          = $_.InvocationInfo.ScriptLineNumber
                ParameterSet  = $PSCmdlet.ParameterSetName
            }
            Write-Verbose ('Directory query failure detail: ' + ($errorDetails | ConvertTo-Json -Compress))
            Write-Error "Directory query failed: $($_.Exception.Message)" -ErrorAction Stop
        }
    }

    end {
        Write-Verbose "Completed $($MyInvocation.MyCommand.Name) - CorrelationId: $correlationId"
    }
}
