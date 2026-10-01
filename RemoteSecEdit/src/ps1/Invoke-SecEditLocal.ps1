<#PSScriptInfo

.DESCRIPTION Runs the worker in-process on the local computer

.VERSION 1.5.0

.GUID 031722ea-3ffc-4ee3-87b0-105a72af5da7

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2021-2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteSecEdit/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteSecEdit

#>

function Invoke-SecEditLocal {

    <#
    .SYNOPSIS
        Runs the worker in-process on the local computer.

    .DESCRIPTION
        Kept as its own function, separate from the worker scriptblock, so tests can mock the
        local call without touching the real secedit.exe. Takes no parameters and has no logic of
        its own beyond the call, which is deliberate: every local alias in the same
        Get-SecEditExport call shares this one run instead of each alias triggering its own.

    .NOTES
        FUNCTION: Invoke-SecEditLocal
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSObject
    #>

    param()

    return & (Get-SecEditWorker)
}
