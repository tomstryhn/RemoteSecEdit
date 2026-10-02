<#PSScriptInfo

.VERSION 1.6.0
.GUID d693e7b2-68fd-44da-93e1-1004fabd6d21
.AUTHOR Tom Stryhn
.COMPANYNAME Tom Stryhn
.COPYRIGHT 2021-2026 (c) Tom Stryhn
.TAGS RemoteSecEdit SecEdit SecurityPolicy
.LICENSEURI https://raw.githubusercontent.com/tomstryhn/RemoteSecEdit/main/LICENSE
.PROJECTURI https://github.com/tomstryhn/RemoteSecEdit
.DESCRIPTION Test double for secedit.exe, mimicking a run without administrative rights.

#>

<#
.SYNOPSIS
    Test double for secedit.exe: not elevated.

.DESCRIPTION
    Mimics secedit /export run without administrative rights: exit code 740, the permission
    message on stdout, no cfg file, an empty log file. Parses the argument array the same way
    secedit would: /cfg <path>, /log <path>, optional /mergedpolicy.
#>

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ArgList
)

$logIndex = [Array]::IndexOf($ArgList, '/log')

$logPath = $null
if ($logIndex -ge 0 -and ($logIndex + 1) -lt $ArgList.Count) { $logPath = $ArgList[$logIndex + 1] }

if ($logPath) {
    New-Item -Path $logPath -ItemType File -Force | Out-Null
}

# The real secedit 740 message, captured live 2026-09-25: a double space after the first
# sentence, then a second line, so the worker's whitespace-collapse rule (both the double space
# and the line break) is exercised the same way a live secedit capture is.
Write-Output 'You do not have sufficient permissions to perform this command.  Make sure that you are running as the local administrator'
Write-Output "or have opened the command prompt using the 'Run as administrator' option."
exit 740
