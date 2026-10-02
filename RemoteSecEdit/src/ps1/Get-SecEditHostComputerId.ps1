<#PSScriptInfo

.DESCRIPTION Returns the collecting computer's own ComputerId, or null on failure

.VERSION 1.6.0

.GUID 77cc8a38-ac3c-4cbc-9290-72812398c432

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2021-2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteSecEdit/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteSecEdit

#>

function Get-SecEditHostComputerId {

    <#
    .SYNOPSIS
        Returns the collecting computer's own ComputerId, or null on failure.

    .DESCRIPTION
        Reads Win32_ComputerSystemProduct.UUID on the collecting computer, the same way the
        worker scriptblock reads it for a target: through CIM, the value trimmed and upper-cased.
        Returns null when the class or the property is missing or the read throws, so a bad read
        here never stops run.json from being written. Used once, for run.json's HostComputerId.

    .NOTES
        FUNCTION: Get-SecEditHostComputerId
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        System.String
    #>

    param()

    $computerId = $null
    try {
        $product = $null
        $product = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop -Verbose:$false
        if ($null -ne $product -and $null -ne $product.PSObject.Properties['UUID'] -and -not [string]::IsNullOrWhiteSpace([string]$product.UUID)) {
            $computerId = ([string]$product.UUID).Trim().ToUpperInvariant()
        }
    } catch {
        $computerId = $null
    }

    return $computerId
}
