<#PSScriptInfo

.VERSION 1.6.0
.GUID a430d292-934b-4f48-a99b-ed4cda159ee1
.AUTHOR Tom Stryhn
.COMPANYNAME Tom Stryhn
.COPYRIGHT 2021-2026 (c) Tom Stryhn
.TAGS RemoteSecEdit SecEdit SecurityPolicy
.LICENSEURI https://raw.githubusercontent.com/tomstryhn/RemoteSecEdit/main/LICENSE
.PROJECTURI https://github.com/tomstryhn/RemoteSecEdit
.DESCRIPTION Test double for secedit.exe, mimicking a merged export that carries Privilege Rights.

#>

<#
.SYNOPSIS
    Test double for secedit.exe: the ok stub with a merged export that carries Privilege Rights.

.DESCRIPTION
    Plain mode behaves exactly like secedit-ok.ps1. The /mergedpolicy mode, instead of the
    workgroup-style empty file, writes [Unicode], [Version], [Profile Description] and a
    [Privilege Rights] section in the lowercase GptTmpl.inf key form, so a token referenced by
    both exports and a token referenced by the merged export only are both covered by the same
    worker run. Parses the argument array the same way secedit would: /cfg <path>, /log <path>,
    optional /mergedpolicy.
#>

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ArgList
)

$cfgIndex = [Array]::IndexOf($ArgList, '/cfg')
$logIndex = [Array]::IndexOf($ArgList, '/log')

$cfgPath = $null
if ($cfgIndex -ge 0 -and ($cfgIndex + 1) -lt $ArgList.Count) { $cfgPath = $ArgList[$cfgIndex + 1] }

$logPath = $null
if ($logIndex -ge 0 -and ($logIndex + 1) -lt $ArgList.Count) { $logPath = $ArgList[$logIndex + 1] }

$isMerged = $ArgList -contains '/mergedpolicy'

$encoding = [System.Text.Encoding]::Unicode

if ($isMerged) {
    $lines = @(
        '[Unicode]',
        'Unicode=yes',
        '[Version]',
        'signature="$CHICAGO$"',
        'Revision=1',
        '[Profile Description]',
        'Description',
        '[Privilege Rights]',
        'seinteractivelogonright = *S-1-5-32-544,*S-1-5-11'
    )
} else {
    $lines = @(
        '[Unicode]',
        'Unicode=yes',
        '[System Access]',
        'MinimumPasswordAge = 1',
        'MaximumPasswordAge = 42',
        'MinimumPasswordLength = 8',
        'PasswordComplexity = 1',
        'PasswordHistorySize = 24',
        'LockoutBadCount = 5',
        'ResetLockoutCount = 30',
        'LockoutDuration = 30',
        'RequireLogonToChangePassword = 0',
        'ForceLogoffWhenHourExpire = 0',
        'NewAdministratorName = "Administrator"',
        'NewGuestName = "Guest"',
        'ClearTextPassword = 0',
        'LSAAnonymousNameLookup = 0',
        'EnableAdminAccount = 1',
        'EnableGuestAccount = 0',
        '[Event Audit]',
        'AuditSystemEvents = 3',
        'AuditLogonEvents = 3',
        'AuditObjectAccess = 0',
        'AuditPrivilegeUse = 0',
        'AuditPolicyChange = 3',
        'AuditAccountManage = 3',
        'AuditProcessTracking = 0',
        'AuditDSAccess = 0',
        'AuditAccountLogon = 3',
        '[Registry Values]',
        'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1',
        'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect=4,15',
        '[Privilege Rights]',
        'SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545',
        'SeBackupPrivilege = *S-1-5-32-544',
        'SeRestorePrivilege = *S-1-5-32-544',
        'SeShutdownPrivilege = *S-1-5-32-544',
        'SeDebugPrivilege = *S-1-5-32-544',
        'SeRemoteShutdownPrivilege = *S-1-5-32-544',
        'SeTakeOwnershipPrivilege = *S-1-5-32-544',
        'SeInteractiveLogonRight = Guest,*S-1-5-32-544,*S-1-5-32-545',
        'SeDenyNetworkLogonRight = Guest',
        'SeServiceLogonRight = *S-1-5-21-1111111111-2222222222-3333333333-1105,CONTOSO\nosuchuser',
        '[Version]',
        'signature="$CHICAGO$"',
        'Revision=1'
    )
}

if ($cfgPath) {
    [System.IO.File]::WriteAllText($cfgPath, ($lines -join "`r`n") + "`r`n", $encoding)
}

if ($logPath) {
    [System.IO.File]::WriteAllText($logPath, "The task has completed successfully.`r`n", $encoding)
}

Write-Output 'The task has completed successfully.'
exit 0
