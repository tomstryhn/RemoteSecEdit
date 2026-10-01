<#PSScriptInfo

.DESCRIPTION Turns one worker object into a result row, and writes its per-computer folder

.VERSION 1.5.0

.GUID e34d428f-462e-4cc0-9375-831779f907d5

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2021-2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteSecEdit/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteSecEdit

#>

function Complete-SecEditComputer {

    <#
    .SYNOPSIS
        Turns one worker object into a result row, and writes its per-computer folder.

    .DESCRIPTION
        Turns one worker object, or nothing plus the errors that explain why there is none, into
        a result row. When a worker object is present, it also writes the per-computer folder.
        Called once per computer: a caller with several local aliases for the same computer calls
        this once for the first alias and copies the returned row for every later one, changing
        only ComputerName, so no two rows for one folder can ever disagree on Status, a count or
        Errors.

    .PARAMETER RequestedComputerName
        The name as the caller requested it, used for the result row and any error messages.

    .PARAMETER Transport
        Local or WinRM.

    .PARAMETER RunFolder
        The run folder a new per-computer folder is created under.

    .PARAMETER WorkerObject
        The object Get-SecEditWorker's scriptblock returned, or $null when the target produced
        nothing.

    .PARAMETER ExtraErrors
        Errors already known before this call, folded into the row's Errors alongside anything
        found here. May be empty or $null.

    .NOTES
        FUNCTION: Complete-SecEditComputer
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSObject, type name RemoteSecEdit.Result
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$RequestedComputerName,

        [Parameter(Mandatory = $true)]
        [string]$Transport,

        [Parameter(Mandatory = $true)]
        [string]$RunFolder,

        [AllowNull()]
        [psobject]$WorkerObject,

        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ExtraErrors
    )

    $errors = @()
    # Every host-side message added to $errors is collapsed to one trimmed line where it is added: the list goes to system.json as it stands, and the message of a failed write or a remote call can carry a line break.
    if ($ExtraErrors) { $errors += @($ExtraErrors | ForEach-Object { ([string]$_).Trim() -replace '\s+', ' ' }) }

    if ($null -eq $WorkerObject) {
        return ConvertTo-SecEditResultRow -ComputerName $RequestedComputerName -Status 'Failed' -Transport $Transport -Errors $errors
    }

    # Set before the try so the catch-all below always has a value to return, even when the very first read inside the try throws.
    $computerIdValue = $null

    try {
        # Kept apart from $errors (which also folds in ExtraErrors, host-side) so Status can test the worker's own Errors alone, per the shared output convention.
        # A malformed worker object can carry $null or empty-string entries in Errors, dropped here so a summary or a results row never shows a blank line for one.
        $workerErrors = @(Get-SecEditSafeProperty -InputObject $WorkerObject -Name 'Errors' -Default @() | Where-Object { -not [string]::IsNullOrEmpty($_) })
        $errors += $workerErrors

        # A computer that was reached still carries its ComputerId even when a later step here throws.
        $computerIdValue = Get-SecEditSafeProperty -InputObject $WorkerObject -Name 'ComputerId' -Default $null

        $exportsRaw = @(Get-SecEditSafeProperty -InputObject $WorkerObject -Name 'Exports' -Default @())
        $exportModeObj = $null
        $mergedModeObj = $null
        foreach ($exp in $exportsRaw) {
            $mode = Get-SecEditSafeProperty -InputObject $exp -Name 'Mode' -Default ''
            if ($mode -eq 'export') { $exportModeObj = $exp }
            if ($mode -eq 'mergedpolicy') { $mergedModeObj = $exp }
        }

        $exportValid = [bool](Get-SecEditSafeProperty -InputObject $exportModeObj -Name 'Valid' -Default $false)
        $mergedValid = [bool](Get-SecEditSafeProperty -InputObject $mergedModeObj -Name 'Valid' -Default $false)

        $accountCountValue = Get-SecEditSafeProperty -InputObject $WorkerObject -Name 'AccountCount' -Default $null
        $accountUnresolvedCountValue = Get-SecEditSafeProperty -InputObject $WorkerObject -Name 'AccountUnresolvedCount' -Default $null

        # Shared output convention: Failed when neither export is valid, Success when both are valid and the worker's own Errors is empty, Partial otherwise. A behaviour change from 1.2.0, where Status came from the two Valid flags alone.
        if (-not $exportValid -and -not $mergedValid) {
            $status = 'Failed'
        } elseif ($exportValid -and $mergedValid -and $workerErrors.Count -eq 0) {
            $status = 'Success'
        } else {
            $status = 'Partial'
        }

        $reportedName = Get-SecEditSafeProperty -InputObject $WorkerObject -Name 'ComputerName' -Default $RequestedComputerName
        if ([string]::IsNullOrWhiteSpace($reportedName)) { $reportedName = $RequestedComputerName }
        $reportedNameUpper = $reportedName.ToUpperInvariant()
        # The reported name comes from the target. A name carrying path separators, dots or wildcard characters must not steer the folder outside the run folder or trip the provider, so anything outside letters, digits, underscore and hyphen becomes an underscore. ASCII NetBIOS names are unchanged; a name with other letters gets underscores and stays unique through the suffix rule.
        $safeReportedName = [regex]::Replace($reportedNameUpper, '[^A-Za-z0-9_-]', '_')

        $buildNumber = Get-SecEditSafeProperty -InputObject $WorkerObject -Name 'CurrentBuild' -Default $null
        if ([string]::IsNullOrWhiteSpace($buildNumber)) { $buildNumber = 'unknown' }
        # The build number is a registry string from the target too, so it gets the same reduction; the timestamp is generated on this host and stays as it is.
        $safeBuildNumber = [regex]::Replace([string]$buildNumber, '[^A-Za-z0-9_-]', '_')

        $folderStamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
        $folderName = '{0}_{1}_{2}Z' -f $safeReportedName, $safeBuildNumber, $folderStamp
        $outputFolder = Resolve-SecEditUniqueFolder -Path (Join-Path $RunFolder $folderName)

        $modeInfo = @{}
        foreach ($pair in @(@{ Mode = 'export'; Obj = $exportModeObj; Prefix = 'secedit-export' }, @{ Mode = 'mergedpolicy'; Obj = $mergedModeObj; Prefix = 'secedit-mergedpolicy' })) {
            $mode = $pair.Mode
            $exp = $pair.Obj
            $prefix = $pair.Prefix

            $infDiskSha256 = $null
            if ($null -ne $exp) {
                $infFilePath = Join-Path $outputFolder ($prefix + '.inf')
                $infBase64 = Get-SecEditSafeProperty -InputObject $exp -Name 'InfBase64' -Default $null
                if ($infBase64) {
                    # Write and the disk-hash read-back are separate try/catch blocks, so a write failure and a hash-verification failure are reported distinctly, and the hash always covers the bytes actually on disk.
                    try {
                        $infBytes = [Convert]::FromBase64String($infBase64)
                        [System.IO.File]::WriteAllBytes($infFilePath, $infBytes)
                    } catch {
                        $errors += ("write inf $mode on ${RequestedComputerName}: $($_.Exception.Message)" -replace '\s+', ' ').Trim()
                    }

                    try {
                        if (Test-Path -LiteralPath $infFilePath) {
                            $diskBytes = [System.IO.File]::ReadAllBytes($infFilePath)
                            $infDiskSha256 = (Get-FileHash -InputStream (New-Object System.IO.MemoryStream(,$diskBytes)) -Algorithm SHA256).Hash.ToLowerInvariant()
                            $targetSha256 = Get-SecEditSafeProperty -InputObject $exp -Name 'InfSha256' -Default $null
                            if ($targetSha256 -and $infDiskSha256 -and ($targetSha256 -ne $infDiskSha256)) {
                                $errors += "$mode sha256 mismatch after write"
                            }
                        }
                    } catch {
                        $errors += ("$mode sha256 read back on ${RequestedComputerName}: $($_.Exception.Message)" -replace '\s+', ' ').Trim()
                    }
                }

                $logBase64 = Get-SecEditSafeProperty -InputObject $exp -Name 'LogBase64' -Default $null
                if ($logBase64) {
                    try {
                        $logBytes = [Convert]::FromBase64String($logBase64)
                        [System.IO.File]::WriteAllBytes((Join-Path $outputFolder ($prefix + '.log')), $logBytes)
                    } catch {
                        $errors += ("write log $mode on ${RequestedComputerName}: $($_.Exception.Message)" -replace '\s+', ' ').Trim()
                    }
                }

                $scesrvText = Get-SecEditSafeProperty -InputObject $exp -Name 'ScesrvLogText' -Default $null
                if ($scesrvText) {
                    try {
                        Write-SecEditTextFile -Path (Join-Path $outputFolder ($prefix + '.scesrv.log')) -Content $scesrvText
                    } catch {
                        $errors += ("write scesrv log $mode on ${RequestedComputerName}: $($_.Exception.Message)" -replace '\s+', ' ').Trim()
                    }
                }

                $stdOut = Get-SecEditSafeProperty -InputObject $exp -Name 'StdOut' -Default ''
                if ($stdOut -and $stdOut.Trim().Length -gt 0) {
                    try {
                        Write-SecEditTextFile -Path (Join-Path $outputFolder ($prefix + '.stdout.txt')) -Content $stdOut
                    } catch {
                        $errors += ("write stdout $mode on ${RequestedComputerName}: $($_.Exception.Message)" -replace '\s+', ' ').Trim()
                    }
                }
            }

            $modeInfo[$mode] = [pscustomobject]@{
                Mode              = $mode
                CommandLine       = Get-SecEditSafeProperty -InputObject $exp -Name 'CommandLine' -Default $null
                ExitCode          = Get-SecEditSafeProperty -InputObject $exp -Name 'ExitCode' -Default $null
                DurationMs        = Get-SecEditSafeProperty -InputObject $exp -Name 'DurationMs' -Default $null
                InfLength         = Get-SecEditSafeProperty -InputObject $exp -Name 'InfLength' -Default 0
                InfSha256Target   = Get-SecEditSafeProperty -InputObject $exp -Name 'InfSha256' -Default $null
                InfSha256Disk     = $infDiskSha256
                Valid             = Get-SecEditSafeProperty -InputObject $exp -Name 'Valid' -Default $false
                ValidationMessage = Get-SecEditSafeProperty -InputObject $exp -Name 'ValidationMessage' -Default ''
                Sections          = @(Get-SecEditSafeProperty -InputObject $exp -Name 'Sections' -Default @())
                SettingLineCount  = Get-SecEditSafeProperty -InputObject $exp -Name 'SettingLineCount' -Default 0
            }
        }

        $accounts = @(Get-SecEditSafeProperty -InputObject $WorkerObject -Name 'Accounts' -Default @())

        try {
            $accountsJson = ConvertTo-Json -InputObject @($accounts) -Depth 4
            Write-SecEditTextFile -Path (Join-Path $outputFolder 'accounts.json') -Content $accountsJson
        } catch {
            $errors += ("write accounts.json on ${RequestedComputerName}: $($_.Exception.Message)" -replace '\s+', ' ').Trim()
        }

        try {
            $accountCsvColumns = @('Token', 'Kind', 'Sid', 'Name', 'Status', 'ReferenceCount', 'Error')
            $accountCsvRows = @($accounts | Select-Object -Property $accountCsvColumns)
            Write-SecEditCsvFile -Row $accountCsvRows -Path (Join-Path $outputFolder 'accounts.csv') -Column $accountCsvColumns
        } catch {
            $errors += ("write accounts.csv on ${RequestedComputerName}: $($_.Exception.Message)" -replace '\s+', ' ').Trim()
        }

        try {
            $unresolvedTokens = @($accounts | Where-Object { (Get-SecEditSafeProperty -InputObject $_ -Name 'Status' -Default '') -eq 'NotFound' } | ForEach-Object { $_.Token })
            $accountsDurationMsValue = Get-SecEditSafeProperty -InputObject $WorkerObject -Name 'AccountsDurationMs' -Default $null
            $summaryObject = [ordered]@{
                AccountCount            = $accountCountValue
                AccountUnresolvedCount  = $accountUnresolvedCountValue
                AccountUnresolvedTokens = $unresolvedTokens
                AccountsDurationMs      = $accountsDurationMsValue
                Exports                 = @($modeInfo['export'], $modeInfo['mergedpolicy'])
            }
            $summaryJson = ConvertTo-Json -InputObject ([pscustomobject]$summaryObject) -Depth 6
            Write-SecEditTextFile -Path (Join-Path $outputFolder 'summary.json') -Content $summaryJson
        } catch {
            $errors += ("write summary.json on ${RequestedComputerName}: $($_.Exception.Message)" -replace '\s+', ' ').Trim()
        }

        try {
            # Built as an explicit ordered list of names, not by enumerating $WorkerObject.PSObject.Properties, so the key order in system.json always matches the output convention regardless of how a worker object happened to be built (a live worker return or a PSSerializer round trip).
            $systemObject = [ordered]@{}
            $identityPropertyOrder = @('ComputerName', 'DnsHostName', 'Domain', 'OSCaption', 'OSVersion', 'CurrentBuild', 'UBR',
                'DisplayVersion', 'EditionID', 'InstallationType', 'Culture', 'TimeZoneId', 'PSVersion', 'CollectedBy',
                'PartOfDomain', 'IsElevated', 'DomainRole', 'CollectedUtc', 'ComputerId', 'MachineGuid')
            foreach ($name in $identityPropertyOrder) {
                $systemObject[$name] = Get-SecEditSafeProperty -InputObject $WorkerObject -Name $name -Default $null
            }

            $systemObject['Collector'] = 'RemoteSecEdit'
            $systemObject['CollectorVersion'] = $MyInvocation.MyCommand.Module.Version.ToString()
            $systemObject['RunId'] = Split-Path -Path $RunFolder -Leaf

            $modulePropertyOrder = @('SecEditPath', 'SecEditVersion', 'AccountCount', 'AccountUnresolvedCount', 'AccountsDurationMs')
            foreach ($name in $modulePropertyOrder) {
                $systemObject[$name] = Get-SecEditSafeProperty -InputObject $WorkerObject -Name $name -Default $null
            }

            $systemObject['Errors'] = @($errors)
            $systemObject['Transport'] = $Transport
            $systemObject['RequestedComputerName'] = $RequestedComputerName
            $systemObject['Status'] = $status

            $systemJson = [pscustomobject]$systemObject | ConvertTo-Json -Depth 6
            Write-SecEditTextFile -Path (Join-Path $outputFolder 'system.json') -Content $systemJson
        } catch {
            $errors += ("write system.json on ${RequestedComputerName}: $($_.Exception.Message)" -replace '\s+', ' ').Trim()
        }

        $isElevatedValue = Get-SecEditSafeProperty -InputObject $WorkerObject -Name 'IsElevated' -Default $null
        if ($null -ne $isElevatedValue) { $isElevatedValue = [bool]$isElevatedValue }

        return ConvertTo-SecEditResultRow -ComputerName $RequestedComputerName -ComputerId $computerIdValue -Status $status -Transport $Transport `
            -OutputFolder $outputFolder -IsElevated $isElevatedValue `
            -ExportExitCode (Get-SecEditSafeProperty -InputObject $exportModeObj -Name 'ExitCode' -Default $null) `
            -MergedPolicyExitCode (Get-SecEditSafeProperty -InputObject $mergedModeObj -Name 'ExitCode' -Default $null) `
            -ExportValid $exportValid -MergedPolicyValid $mergedValid `
            -ExportSettingLines (Get-SecEditSafeProperty -InputObject $exportModeObj -Name 'SettingLineCount' -Default $null) `
            -MergedPolicySettingLines (Get-SecEditSafeProperty -InputObject $mergedModeObj -Name 'SettingLineCount' -Default $null) `
            -AccountCount $accountCountValue -AccountUnresolvedCount $accountUnresolvedCountValue `
            -Errors $errors
    } catch {
        $errors += ("unexpected error processing ${RequestedComputerName}: $($_.Exception.Message)" -replace '\s+', ' ').Trim()
        return ConvertTo-SecEditResultRow -ComputerName $RequestedComputerName -ComputerId $computerIdValue -Status 'Failed' -Transport $Transport -Errors $errors
    }
}
