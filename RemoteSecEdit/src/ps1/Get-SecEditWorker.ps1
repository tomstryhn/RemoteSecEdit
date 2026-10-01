<#PSScriptInfo

.DESCRIPTION Returns the self-contained scriptblock that runs secedit /export on a target

.VERSION 1.5.0

.GUID f1f19af1-990c-40a0-96f6-674cbd3f5980

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2021-2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteSecEdit/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteSecEdit

#>

function Get-SecEditWorker {

    <#
    .SYNOPSIS
        Returns the self-contained scriptblock that runs secedit /export on a target.

    .DESCRIPTION
        The scriptblock this function returns is what actually runs on the target, local or
        remote, so it uses no module function, no module variable and no using: expression. It
        takes a single -SecEditPath parameter and depends on nothing else from the caller's
        session. It runs secedit /export twice, once plain and once with /mergedpolicy, validates
        the files it wrote, resolves every account referenced in [Privilege Rights] across both
        exports, and returns one flat object describing the target, both exports and the account
        table. It never throws: every step is wrapped in its own try/catch and appends to an
        Errors list instead. Invoke-SecEditLocal calls it directly for the local computer.
        Invoke-SecEditRemote passes it to Invoke-Command for every remote target.

    .NOTES
        FUNCTION: Get-SecEditWorker
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.ScriptBlock
    #>

    param()

    return {
        param(
            [string]$SecEditPath = (Join-Path -Path ([Environment]::GetFolderPath('System')) -ChildPath 'secedit.exe')
        )

        # Off here, not only in the public function, so the worker behaves the same in-process as on a remote target, where strict mode is off by default.
        Set-StrictMode -Off

        function Test-SecEditInfContent {
            <#
            .SYNOPSIS
                Checks whether a secedit export file has the expected structure.

            .DESCRIPTION
                Reads the raw bytes of one inf file and reports whether it looks like a real secedit
                export: a UTF-16 byte order mark, a first line of [Unicode], the [Version] section,
                and, for a plain export, the [System Access] and [Privilege Rights] sections with at
                least twenty setting lines outside [Unicode], [Version] and [Profile Description].
            #>
            param(
                [byte[]]$Bytes,
                [string]$Mode
            )

            $valid = $true
            $message = ''
            $sections = @()
            $settingLineCount = 0
            $lines = @()

            if ($Bytes.Length -lt 2 -or $Bytes[0] -ne 0xFF -or $Bytes[1] -ne 0xFE) {
                $valid = $false
                $message = 'file does not start with a UTF-16 LE BOM'
            }

            if ($valid) {
                # Byte offset 2 skips the BOM. GetString does not strip it, and a leftover U+FEFF would break the section-header regex on the first line.
                $text = [System.Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2)
                $lines = $text -split "`r`n|`n|`r"

                $firstNonEmpty = $null
                foreach ($line in $lines) {
                    if ($line.Trim().Length -gt 0) {
                        $firstNonEmpty = $line.Trim()
                        break
                    }
                }
                if ($firstNonEmpty -ne '[Unicode]') {
                    $valid = $false
                    $message = 'first non-empty line is not [Unicode]'
                }
            }

            if ($valid) {
                $currentSection = ''
                foreach ($line in $lines) {
                    if ($line -match '^\[(.+)\]\s*$') {
                        $sections += $matches[1]
                        $currentSection = $matches[1]
                        continue
                    }
                    if ($line -like '*=*' -and $currentSection -ne 'Unicode' -and $currentSection -ne 'Version' -and $currentSection -ne 'Profile Description') {
                        $settingLineCount++
                    }
                }

                if ($sections -notcontains 'Version') {
                    $valid = $false
                    $message = 'missing section [Version]'
                } elseif ($Mode -eq 'export') {
                    if ($sections -notcontains 'System Access') {
                        $valid = $false
                        $message = 'missing section [System Access]'
                    } elseif ($sections -notcontains 'Privilege Rights') {
                        $valid = $false
                        $message = 'missing section [Privilege Rights]'
                    } elseif ($settingLineCount -lt 20) {
                        $valid = $false
                        $message = 'fewer than 20 setting lines outside [Unicode], [Version] and [Profile Description]'
                    }
                }
            }

            return [pscustomobject]@{
                Valid            = $valid
                Message          = $message
                Sections         = @($sections)
                SettingLineCount = $settingLineCount
            }
        }

        $errors = @()

        #region Step 1: identity
        $dnsHostName = $null
        $domain = $null
        $partOfDomain = $false
        $domainRole = -1
        $osCaption = $null
        $osVersion = $null
        $currentBuild = $null
        $ubr = $null
        $displayVersion = $null
        $editionId = $null
        $installationType = $null
        $culture = $null
        $timeZoneId = $null
        $isElevated = $false
        $collectedBy = $null

        try {
            $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            $currentBuild = $cv.CurrentBuild
            if ($null -ne $cv.UBR) { $ubr = $cv.UBR.ToString() }
            $displayVersion = $cv.DisplayVersion
            $editionId = $cv.EditionID
            $installationType = $cv.InstallationType
        } catch {
            $errors += "CurrentVersion key: $($_.Exception.Message)"
        }

        $os = $null
        $cs = $null
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop -Verbose:$false
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop -Verbose:$false
        } catch {
            $errors += "Get-CimInstance failed: $($_.Exception.Message)"
        }

        if ($null -ne $os) {
            $osCaption = $os.Caption
            $osVersion = $os.Version
        }
        if ($null -ne $cs) {
            $dnsHostName = $cs.DNSHostName
            $domain = $cs.Domain
            $partOfDomain = [bool]$cs.PartOfDomain
            if ($null -ne $cs.DomainRole) { $domainRole = [int]$cs.DomainRole }
        }

        try {
            $culture = [System.Globalization.CultureInfo]::CurrentCulture.Name
        } catch {
            $errors += "culture: $($_.Exception.Message)"
        }

        try {
            $timeZoneId = [System.TimeZoneInfo]::Local.Id
        } catch {
            $errors += "time zone: $($_.Exception.Message)"
        }

        try {
            $winIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $collectedBy = $winIdentity.Name
            $winPrincipal = New-Object System.Security.Principal.WindowsPrincipal($winIdentity)
            $isElevated = $winPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch {
            $errors += "elevation check: $($_.Exception.Message)"
            $isElevated = $false
        }

        #region Computer identity
        $computerId = $null
        $machineGuid = $null
        try {
            $product = $null
            $product = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop -Verbose:$false
            if ($null -ne $product -and $null -ne $product.PSObject.Properties['UUID'] -and -not [string]::IsNullOrWhiteSpace([string]$product.UUID)) {
                $computerId = ([string]$product.UUID).Trim().ToUpperInvariant()
            }
        }
        catch { $errors += "identity: ComputerId: $($_.Exception.Message)" }
        try {
            $machineGuid = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
        }
        catch { $errors += "identity: MachineGuid: $($_.Exception.Message)" }
        #endregion
        #endregion

        #region Steps 2 to 4: work folder, both exports, removal
        # The removal sits in a finally, not after the exports, so a throw anywhere between creating the folder and the end of the export loop still deletes it; a work folder left behind on a target holds a policy export.
        $workFolder = $null
        try {
            #region Step 2: work folder
            # Built inside the try so a failure of the name itself (for example an unset TEMP) also reaches the finally.
            $workFolder = Join-Path $env:TEMP ('RemoteSecEdit-' + [guid]::NewGuid().ToString('N'))
            try {
                New-Item -Path $workFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            } catch {
                $errors += "create work folder: $($_.Exception.Message)"
            }

            $secEditExists = $false
            try {
                # -ErrorAction Stop so a failed read of the path is reported by the catch, not mistaken for a missing file.
                $secEditExists = Test-Path -LiteralPath $SecEditPath -ErrorAction Stop
            } catch {
                $errors += "test secedit path: $($_.Exception.Message)"
            }
            if (-not $secEditExists) {
                $errors += "secedit path not found: $SecEditPath"
            }

            $secEditVersion = $null
            if ($secEditExists) {
                try {
                    $secEditVersion = (Get-Item -LiteralPath $SecEditPath -ErrorAction Stop).VersionInfo.FileVersion
                } catch {
                    $errors += "secedit version: $($_.Exception.Message)"
                }
            }
            #endregion

            #region Step 3: run both export modes
            $exports = @()
            $infBytesByMode = @{}
            $modes = @('export', 'mergedpolicy')
            foreach ($mode in $modes) {
                $infPath = Join-Path $workFolder ($mode + '.inf')
                $logPath = Join-Path $workFolder ($mode + '.log')
                $argList = @('/export', '/cfg', $infPath, '/log', $logPath)
                if ($mode -eq 'mergedpolicy') { $argList += '/mergedpolicy' }
                $commandLine = $argList -join ' '

                $exitCode = $null
                $stdOut = ''
                $durationMs = 0

                if ($secEditExists) {
                    $prevEap = $ErrorActionPreference
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    try {
                        # Stdout and stderr are merged and rendered to plain text because native stderr does not throw in a local console but does once this runs under Invoke-Command.
                        $ErrorActionPreference = 'Continue'
                        $stdOut = (& $SecEditPath @argList 2>&1 | ForEach-Object { "$_" } | Out-String)
                        $exitCode = $LASTEXITCODE
                    } catch {
                        $errors += "secedit $mode invocation failed: $($_.Exception.Message)"
                    } finally {
                        $ErrorActionPreference = $prevEap
                        $stopwatch.Stop()
                    }
                    $durationMs = [int]$stopwatch.ElapsedMilliseconds

                    if ($null -ne $exitCode -and $exitCode -ne 0) {
                        # The embedded stdout text has every run of whitespace, line breaks included, collapsed to one space, the same rule RemoteService and RemoteScheduledTask apply.
                        $errors += "secedit $mode exit ${exitCode}: $($stdOut.Trim() -replace '\s+', ' ')"
                        if ($exitCode -eq 740) {
                            $errors += "secedit $mode exit 740: not elevated, run from an elevated PowerShell"
                        }
                    }
                }

                $infBytes = $null
                try {
                    if (Test-Path -LiteralPath $infPath) {
                        $infBytes = [System.IO.File]::ReadAllBytes($infPath)
                    }
                } catch {
                    $errors += "read inf $mode : $($_.Exception.Message)"
                }

                $logBytes = $null
                try {
                    if (Test-Path -LiteralPath $logPath) {
                        $logBytes = [System.IO.File]::ReadAllBytes($logPath)
                    }
                } catch {
                    $errors += "read log $mode : $($_.Exception.Message)"
                }

                $scesrvText = $null
                try {
                    $scesrvPath = Join-Path $env:windir 'security\logs\scesrv.log'
                    if (Test-Path -LiteralPath $scesrvPath) {
                        $scesrvText = Get-Content -LiteralPath $scesrvPath -Raw -ErrorAction Stop
                    }
                } catch {
                    $errors += "read scesrv.log: $($_.Exception.Message)"
                }

                if ($null -ne $infBytes) {
                    $validation = Test-SecEditInfContent -Bytes $infBytes -Mode $mode
                } else {
                    $validation = [pscustomobject]@{
                        Valid            = $false
                        Message          = "inf file not found: $infPath"
                        Sections         = @()
                        SettingLineCount = 0
                    }
                }

                # Recorded in Errors too, not only as Valid=$false, so a target-side problem is visible even when a caller only reads Errors.
                if (-not $validation.Valid) {
                    $errors += "$mode invalid: $($validation.Message)"
                }

                $infSha256 = $null
                $infLength = 0
                if ($null -ne $infBytes) {
                    $infLength = $infBytes.Length
                    try {
                        # Get-FileHash over a stream, not a hand-built provider and hex loop; New-Object rather than ::new, matching every other .NET construction in this scriptblock.
                        $infSha256 = (Get-FileHash -InputStream (New-Object System.IO.MemoryStream(,$infBytes)) -Algorithm SHA256).Hash.ToLowerInvariant()
                    } catch {
                        $errors += "sha256 $mode : $($_.Exception.Message)"
                    }
                }

                $infBase64 = $null
                if ($null -ne $infBytes) {
                    $infBase64 = [Convert]::ToBase64String($infBytes)
                    # Kept per mode for the accounts step, which reads the same bytes instead of decoding InfBase64 again.
                    $infBytesByMode[$mode] = $infBytes
                }
                $logBase64 = $null
                if ($null -ne $logBytes) { $logBase64 = [Convert]::ToBase64String($logBytes) }

                $exports += [pscustomobject]@{
                    Mode              = $mode
                    CommandLine       = $commandLine
                    ExitCode          = $exitCode
                    StdOut            = $stdOut
                    DurationMs        = $durationMs
                    InfBase64         = $infBase64
                    InfSha256         = $infSha256
                    InfLength         = $infLength
                    LogBase64         = $logBase64
                    ScesrvLogText     = $scesrvText
                    Valid             = $validation.Valid
                    ValidationMessage = $validation.Message
                    Sections          = @($validation.Sections)
                    SettingLineCount  = $validation.SettingLineCount
                }
            }
            #endregion
        } finally {
            #region Step 4: remove work folder
            try {
                if ($workFolder -and (Test-Path -LiteralPath $workFolder)) {
                    Remove-Item -LiteralPath $workFolder -Recurse -Force -ErrorAction Stop
                }
            } catch {
                $errors += "remove work folder: $($_.Exception.Message)"
            }
            #endregion
        }
        #endregion

        #region Step 5: accounts
        $accounts = @()
        $accountCount = 0
        $accountUnresolvedCount = 0
        $accountsDurationMs = 0

        $stopwatchAccounts = [System.Diagnostics.Stopwatch]::StartNew()

        # Extraction, grouping and every lookup sit inside one try/catch, so a failure anywhere in this step never stops the worker from returning: the account data for this run is simply empty, with the reason in $errors.
        try {
            $tokenSettings = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
            $tokenOrder = New-Object System.Collections.Generic.List[string]

            foreach ($exp in $exports) {
                $tokenInfBytes = $infBytesByMode[$exp.Mode]
                if ($null -eq $tokenInfBytes -or $tokenInfBytes.Length -lt 2) { continue }

                # Byte offset 2 skips the BOM, the same offset the structural validation uses.
                $tokenText = [System.Text.Encoding]::Unicode.GetString($tokenInfBytes, 2, $tokenInfBytes.Length - 2)
                $tokenLines = $tokenText -split "`r`n|`n|`r"

                $inPrivilegeRights = $false
                foreach ($line in $tokenLines) {
                    if ($line -match '^\[(.+)\]\s*$') {
                        $inPrivilegeRights = ($matches[1] -ieq 'Privilege Rights')
                        continue
                    }
                    if (-not $inPrivilegeRights) { continue }
                    if ($line -notmatch '^\s*([^=]+?)\s*=\s*(.*)$') { continue }

                    $settingKey = $matches[1]
                    $settingValue = $matches[2]
                    $settingLabel = $exp.Mode + ':' + $settingKey

                    # A HashSet per line, not per token overall, so a token repeated within one value list still counts as one setting line, matching a token appearing on two different lines twice.
                    $lineTokens = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($piece in ($settingValue -split ',')) {
                        $pieceTrimmed = $piece.Trim()
                        if ($pieceTrimmed.Length -eq 0) { continue }
                        if (-not $lineTokens.Add($pieceTrimmed)) { continue }

                        if (-not $tokenSettings.ContainsKey($pieceTrimmed)) {
                            $tokenSettings[$pieceTrimmed] = New-Object System.Collections.Generic.List[string]
                            [void]$tokenOrder.Add($pieceTrimmed)
                        }
                        [void]$tokenSettings[$pieceTrimmed].Add($settingLabel)
                    }
                }
            }

            $tokenOrder.Sort( [Comparison[string]] { param($a, $b) [string]::Compare($a, $b, [System.StringComparison]::Ordinal) } )

            foreach ($token in $tokenOrder) {
                # Token extraction only: the leading * secedit writes on every Sid-kind token is ignored for the Kind check and stripped for the lookup, then the rest of this region matches the resolver in Get-ScheduledTaskInventoryWorker.ps1 (accounts step).
                $sidCandidate = $token
                if ($sidCandidate.StartsWith('*', [System.StringComparison]::Ordinal)) { $sidCandidate = $sidCandidate.Substring(1) }

                $kind = 'Name'
                if ($sidCandidate -match '^S-1-\d+(-\d+)+$') { $kind = 'Sid' }

                $sid = $null
                $accountName = $null
                $status = 'Resolved'
                $acctError = ''

                if ($kind -eq 'Sid') {
                    # The token without the * is kept as Sid always, resolved or not.
                    $sid = $sidCandidate
                    try {
                        $securityId = New-Object System.Security.Principal.SecurityIdentifier($sidCandidate)
                        $translatedAccount = $securityId.Translate([System.Security.Principal.NTAccount])
                        $accountName = $translatedAccount.Value
                    } catch {
                        $status = 'NotFound'
                        $accountName = $null
                        $rawMessage = $_.Exception.GetBaseException().Message
                        $acctError = ([string]$rawMessage).Trim() -replace '\s+', ' '
                    }
                } else {
                    $lookupName = $token
                    try {
                        if ($token -ieq 'LocalSystem') {
                            # The Service Control Manager's own alias, not a real account, so it never goes through a lookup.
                            $sid = 'S-1-5-18'
                        } else {
                            if ($token.StartsWith('.\', [System.StringComparison]::Ordinal)) {
                                $lookupName = $env:COMPUTERNAME + $token.Substring(1)
                            }
                            $ntAccount = New-Object System.Security.Principal.NTAccount($lookupName)
                            $translated = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
                            $sid = $translated.Value
                        }
                    } catch {
                        $status = 'NotFound'
                        $sid = $null
                        $rawMessage = $_.Exception.GetBaseException().Message
                        $acctError = ([string]$rawMessage).Trim() -replace '\s+', ' '
                    }
                    # The name handed to the lookup after the rewrites above, not the raw token, kept even when the lookup itself failed.
                    $accountName = $lookupName
                }

                $tokenSettingsList = $tokenSettings[$token]

                $accounts += [pscustomobject]@{
                    Token          = $token
                    Kind           = $kind
                    Sid            = $sid
                    Name           = $accountName
                    Status         = $status
                    ReferenceCount = $tokenSettingsList.Count
                    References     = @($tokenSettingsList.ToArray())
                    Error          = $acctError
                }

                if ($status -eq 'NotFound') { $accountUnresolvedCount++ }
            }

            $accountCount = $accounts.Count
        } catch {
            $errors += "accounts: $($_.Exception.Message)"
            $accounts = @()
            $accountCount = 0
            $accountUnresolvedCount = 0
        } finally {
            $stopwatchAccounts.Stop()
            $accountsDurationMs = [int]$stopwatchAccounts.ElapsedMilliseconds
        }
        #endregion

        #region Step 6: return the flat result
        $collectedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)

        [pscustomobject]@{
            ComputerName           = $env:COMPUTERNAME
            DnsHostName            = $dnsHostName
            Domain                 = $domain
            OSCaption              = $osCaption
            OSVersion              = $osVersion
            CurrentBuild           = $currentBuild
            UBR                    = $ubr
            DisplayVersion         = $displayVersion
            EditionID              = $editionId
            InstallationType       = $installationType
            Culture                = $culture
            TimeZoneId             = $timeZoneId
            PSVersion              = $PSVersionTable.PSVersion.ToString()
            CollectedBy            = $collectedBy
            PartOfDomain           = [bool]$partOfDomain
            IsElevated             = [bool]$isElevated
            DomainRole             = [int]$domainRole
            CollectedUtc           = $collectedUtc
            ComputerId             = $computerId
            MachineGuid            = $machineGuid
            SecEditPath            = $SecEditPath
            SecEditVersion         = $secEditVersion
            AccountCount           = [int]$accountCount
            AccountUnresolvedCount = [int]$accountUnresolvedCount
            AccountsDurationMs     = [int]$accountsDurationMs
            Exports                = @($exports)
            Accounts               = @($accounts)
            Errors                 = @($errors | ForEach-Object { ([string]$_).Trim() -replace '\s+', ' ' })
        }
        #endregion
    }
}
