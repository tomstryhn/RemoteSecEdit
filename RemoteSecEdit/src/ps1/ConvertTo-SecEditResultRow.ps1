<#PSScriptInfo

.DESCRIPTION Builds one RemoteSecEdit.Result row

.VERSION 1.6.0

.GUID 5fa5a49f-df88-412b-bfc1-d7d3e8e3f451

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2021-2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteSecEdit/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteSecEdit

#>

function ConvertTo-SecEditResultRow {

    <#
    .SYNOPSIS
        Builds one RemoteSecEdit.Result row.

    .DESCRIPTION
        Every optional property defaults to the "not reached" shape, so a caller only needs to
        override what it actually knows. Error is derived from Errors here, as the first entry,
        rather than being supplied separately, so the two can never disagree about which message
        came first.

    .PARAMETER ComputerName
        The name as requested by the caller.

    .PARAMETER ComputerId
        The computer's own identity (Win32_ComputerSystemProduct.UUID, upper case), or $null when
        the target was never reached.

    .PARAMETER Status
        Success, Partial, or Failed.

    .PARAMETER Transport
        Local or WinRM.

    .PARAMETER OutputFolder
        The per-computer folder, or $null when the target was never reached.

    .PARAMETER IsElevated
        Elevation as reported by the target, or $null when unknown.

    .PARAMETER ExportExitCode
        Exit code of the plain export, or $null.

    .PARAMETER MergedPolicyExitCode
        Exit code of the /mergedpolicy export, or $null.

    .PARAMETER ExportValid
        Whether the plain export passed the structural check, or $null on a Failed row where the
        target was never reached.

    .PARAMETER MergedPolicyValid
        Whether the /mergedpolicy export passed the structural check, or $null on a Failed row
        where the target was never reached.

    .PARAMETER ExportSettingLines
        SettingLineCount of the plain export, or $null.

    .PARAMETER MergedPolicySettingLines
        SettingLineCount of the /mergedpolicy export, or $null. 0 is a legitimate value.

    .PARAMETER AccountCount
        Number of distinct accounts referenced in [Privilege Rights] across both exports, or
        $null when the worker object carries no such property.

    .PARAMETER AccountUnresolvedCount
        Number of those accounts that did not resolve, or $null when the worker object carries no
        such property.

    .PARAMETER Errors
        Every error message seen for this computer, target and host side. May be empty.
        ErrorCount, the count of Errors, is derived here, the same way Error is.

    .NOTES
        FUNCTION: ConvertTo-SecEditResultRow
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSObject, type name RemoteSecEdit.Result
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [AllowNull()]
        $ComputerId,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Transport,

        [AllowNull()]
        [string]$OutputFolder,

        [AllowNull()]
        $IsElevated,

        [AllowNull()]
        $ExportExitCode,

        [AllowNull()]
        $MergedPolicyExitCode,

        [AllowNull()]
        $ExportValid,

        [AllowNull()]
        $MergedPolicyValid,

        [AllowNull()]
        $ExportSettingLines,

        [AllowNull()]
        $MergedPolicySettingLines,

        [AllowNull()]
        $AccountCount,

        [AllowNull()]
        $AccountUnresolvedCount,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Errors
    )

    # Every message is made one line here, host-side ones included (a remote connection error spans several lines), so Error and Errors never carry a line break into results.csv, run.json or a warning.
    $errorList = @($Errors | ForEach-Object { ([string]$_).Trim() -replace '\s+', ' ' })

    return [pscustomobject]@{
        PSTypeName               = 'RemoteSecEdit.Result'
        ComputerName              = $ComputerName
        ComputerId                = $ComputerId
        Status                    = $Status
        Transport                 = $Transport
        OutputFolder              = $OutputFolder
        IsElevated                = $IsElevated
        ExportExitCode            = $ExportExitCode
        MergedPolicyExitCode      = $MergedPolicyExitCode
        ExportValid               = $ExportValid
        MergedPolicyValid         = $MergedPolicyValid
        ExportSettingLines        = $ExportSettingLines
        MergedPolicySettingLines  = $MergedPolicySettingLines
        AccountCount              = $AccountCount
        AccountUnresolvedCount    = $AccountUnresolvedCount
        Error                     = $(if ($errorList.Count -gt 0) { $errorList[0] } else { '' })
        ErrorCount                = $errorList.Count
        Errors                    = [string[]]$errorList
    }
}
