<#PSScriptInfo

.VERSION 1.6.0
.GUID 93cdff47-f581-4831-9d33-6d1324ec0500
.AUTHOR Tom Stryhn
.COMPANYNAME Tom Stryhn
.COPYRIGHT 2021-2026 (c) Tom Stryhn
.TAGS RemoteSecEdit SecEdit SecurityPolicy
.LICENSEURI https://raw.githubusercontent.com/tomstryhn/RemoteSecEdit/main/LICENSE
.PROJECTURI https://github.com/tomstryhn/RemoteSecEdit
.DESCRIPTION Test double for secedit.exe, mimicking the happy path.

#>

<#
.SYNOPSIS
    Test double for secedit.exe: the happy path.

.DESCRIPTION
    Mimics real secedit /export behaviour observed on Windows 11, non-domain-joined: the plain
    export holds the full effective configuration. The /mergedpolicy export, on a workgroup
    machine, exits 0 with "The task has completed successfully." and writes a small file holding
    only [Unicode], [Version] and [Profile Description], with zero setting lines. Both are valid.
    Parses the argument array the same way secedit would: /cfg <path>, /log <path>, optional
    /mergedpolicy.
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
        'Description'
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
