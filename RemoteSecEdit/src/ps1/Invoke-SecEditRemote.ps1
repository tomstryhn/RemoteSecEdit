<#PSScriptInfo

.DESCRIPTION Runs the worker on one or more remote computers with a single Invoke-Command call

.VERSION 1.5.0

.GUID fc12b7fd-c52e-4d1d-8a73-42c678611f7a

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2021-2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteSecEdit/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteSecEdit

#>

function Invoke-SecEditRemote {

    <#
    .SYNOPSIS
        Runs the worker on one or more remote computers with a single Invoke-Command call.

    .DESCRIPTION
        Kept as its own function, rather than calling Invoke-Command directly from the public
        function, so tests can mock this one boundary and control both the streamed worker
        objects and the error records without depending on -ErrorVariable behaviour under a mock.
        Each worker-shaped object carrying a PSComputerName note property is passed to -OnResult
        as it arrives from the pipeline, one at a time, so the caller can finish with one result
        (write its folder, build its row) and drop its reference before the next one is held,
        rather than holding every target's result until the whole pipeline ends. Every error
        record Invoke-Command collects through -ErrorVariable is returned once the pipeline has
        ended.

    .PARAMETER ComputerName
        The remote targets to contact, already resolved and de-duplicated.

    .PARAMETER Credential
        Forwarded to Invoke-Command when supplied. Omitted entirely, not passed as $null, when
        the caller supplies nothing.

    .PARAMETER ThrottleLimit
        Forwarded to Invoke-Command.

    .PARAMETER OnResult
        Invoked once per worker-shaped object as it arrives from Invoke-Command, before the next
        one is read from the pipeline.

    .PARAMETER UseSSL
        Forwarded to Invoke-Command as UseSSL when set. Omitted entirely, not passed as
        $false, when the caller does not supply it.

    .NOTES
        FUNCTION: Invoke-SecEditRemote
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSObject
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true)]
        [int]$ThrottleLimit,

        [Parameter(Mandatory = $true)]
        [scriptblock]$OnResult,

        [switch]$UseSSL
    )

    $invokeParams = @{
        ComputerName  = @($ComputerName)
        ScriptBlock   = Get-SecEditWorker
        ThrottleLimit = $ThrottleLimit
        ErrorAction   = 'SilentlyContinue'
        ErrorVariable = 'remoteErrors'
    }
    if ($Credential) { $invokeParams['Credential'] = $Credential }
    if ($UseSSL) { $invokeParams['UseSSL'] = $true }

    $remoteErrors = $null
    Invoke-Command @invokeParams | ForEach-Object { & $OnResult $_ }

    return [pscustomobject]@{
        Errors = @($remoteErrors)
    }
}
