<#PSScriptInfo

.VERSION 1.5.0
.GUID 9fa1fa26-aa3c-433c-adf8-4fa8baf71c9b
.AUTHOR Tom Stryhn
.COMPANYNAME Tom Stryhn
.COPYRIGHT 2021-2026 (c) Tom Stryhn
.TAGS RemoteSecEdit SecEdit SecurityPolicy
.LICENSEURI https://raw.githubusercontent.com/tomstryhn/RemoteSecEdit/main/LICENSE
.PROJECTURI https://github.com/tomstryhn/RemoteSecEdit
.DESCRIPTION Test double for secedit.exe, mimicking a run that exits 0 but writes no inf.

#>

<#
.SYNOPSIS
    Test double for secedit.exe: exits 0 but writes no inf.

.DESCRIPTION
    Models an edge case, for example a full disk, distinct from the 740 case: secedit reports
    success but the cfg file never appears. The log file is written normally. Parses the argument
    array the same way secedit would: /cfg <path>, /log <path>, optional /mergedpolicy.
#>

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ArgList
)

$logIndex = [Array]::IndexOf($ArgList, '/log')

$logPath = $null
if ($logIndex -ge 0 -and ($logIndex + 1) -lt $ArgList.Count) { $logPath = $ArgList[$logIndex + 1] }

$encoding = [System.Text.Encoding]::Unicode

if ($logPath) {
    [System.IO.File]::WriteAllText($logPath, "The task has completed successfully.`r`n", $encoding)
}

Write-Output 'The task has completed successfully.'
exit 0
