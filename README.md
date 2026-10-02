# RemoteSecEdit PowerShell Module

Collects the raw output of `secedit /export`, plain and `/mergedpolicy`, from local and remote computers over WinRM, and resolves every account the user rights reference, without changing anything.

## Table of Content

- [Version Changes](#version-changes)
- [Background](#background)
  - [Risk(s)](#risks)
  - [Mitigation](#mitigation)
- [Requirements](#requirements)
- [Output Data Handling](#output-data-handling)
- [Importing the Module](#importing-the-module)
- [Examples](#examples)
- [Functions](#functions)
  - [Get-SecEditExport](#get-seceditexport)
- [How it works](#how-it-works)
- [Testing](#testing)
- [Support and versioning](#support-and-versioning)
- [References](#references)
- [License](#license)

## Version Changes

##### 1.6.0

- The worker reads four SID reference values and `system.json` carries them directly after
  `MachineGuid`: `MachineSid` (the SID of the computer's own account database, without the RID),
  `DomainSid`, `ComputerAccountSid` (the full SID of the computer's own domain account) and
  `DomainNetbiosName`. They say whose an `S-1-5-21` SID is; none is used as identity.
- New `-SkipSidReference` switch leaves the four values unread (null in `system.json`), for a
  caller that runs several collectors against the same computers and needs the reference from one
  of them only, as RemoteBaseline does. `run.json` gains `SkipSidReference` directly after `UseSSL`.
- `MachineSid` is null on a domain controller. The three domain values are null on a workgroup
  computer. A domain-joined computer that cannot resolve its own account gets
  `identity: DomainSid: <message>` in `Errors` and a `Partial` row.
- Output convention 1.3: `run.json` `SchemaVersion` is now `1.3`.

##### 1.5.0

- Every error message and every csv cell is one line: the worker and the collecting computer
  trim each message and collapse runs of whitespace to one space, and the csv writer does the same
  for every string cell. `run.json` and the other json files keep the values as they were.
- The per-computer folder name is built from the reported computer name and the build number with anything outside
  letters, digits, underscore and hyphen replaced by an underscore, so a name carrying path
  separators or dots cannot steer the folder outside the run folder. Real NetBIOS names are
  unchanged, and the name inside the json files is still the one the target gave.
- The result callback for a remote target never ends the run: a failure while completing one
  computer's result gives that computer a `Failed` row with an error starting `host: `, and the
  warning for a result that matches no requested name is written after the remote call has
  returned.
- The module loader reads the install folder with `-LiteralPath` and `-Filter`, so an install path
  with brackets or other wildcard characters imports completely.
- The worker removes its temporary work folder in a `finally` block, so a failure between creating
  the folder and the end of the exports no longer leaves the exports behind on the target. The
  work folder name is built inside that block too, and a failed read of the secedit path is
  reported as its own error instead of as a missing file.
- The SHA-256 of each inf file is computed with `Get-FileHash` on the target and on the collecting
  computer; the value is unchanged and the internal `Get-SecEditSha256Hex` function is removed.
- Known limits, Automation, File formats, Support and versioning and workgroup prerequisites
  are stated in this README, and `SECURITY.md` is added.
- The examples show sample names and identifiers instead of those of a lab.
- Output convention 1.2: `run.json` `SchemaVersion` is now `1.2`.

##### 1.4.1

- A worker result carrying an empty entry in its error list no longer ends the run; empty entries are dropped.
- Local aliases in one call get identical rows apart from ComputerName, also when writing a file fails.
- Remote results are completed and written as each target answers, not after the last one.
- system.json is built from a fixed property list, so its key order and the Collector, CollectorVersion and RunId keys no longer depend on the shape of the worker result.
- The Get-WmiObject fallback behind the CIM reads is removed; a CIM failure is reported in Errors without a second attempt.
- A remote result that matches no requested computer name is dropped with a warning instead of getting a folder that no row points to.
- Internal simplifications with no change in output.
- No output or data format change.

##### 1.4.0

- New `-UseSSL` switch: remote targets are reached over WinRM HTTPS (port 5986) instead
  of HTTP. The name passed must match the target's listener certificate, normally the
  FQDN, and certificate checks are never skipped. Local targets ignore it.
- `run.json` gains `UseSSL` after `ThrottleLimit`, and the output convention moves to
  version 1.1 (`SchemaVersion` `1.1`). Nothing else in the output changes.
- README: FQDN recommended for remote targets, with the HTTPS requirements.

##### 1.3.1

- Comments in published files no longer point at working documents that are not part of
  the repository; the rules they cited are now stated in place.
- No behaviour, output or data format change.

##### 1.3.0

- Every computer now carries a `ComputerId` (`Win32_ComputerSystemProduct.UUID`, upper case,
  read on the target and on the collecting computer alike) and a `MachineGuid`, so a computer
  that was renamed, reinstalled, or moved between domains still joins across runs. `ComputerId`
  is `$null` on a `Failed` row where the target was never reached.
- `run.json` and `system.json` now carry `Collector`, `CollectorVersion` and (`system.json`
  only) `RunId`, and `run.json` gains `SchemaVersion` and `HostComputerId`, so the same loader
  can read the output of this module, RemoteService and RemoteScheduledTask.
- `summary.json` is now one object, `{ AccountCount, AccountUnresolvedCount,
  AccountUnresolvedTokens, AccountsDurationMs, Exports }`, instead of a bare array of the two
  export summaries. `Exports` holds the same two objects the array used to hold.
- Every result row, and `results.csv`, gain `ErrorCount`, the number of messages in `Errors`,
  kept in step with `Errors` even when a remote error is matched to a row after it was built.
- On a `Failed` row where the target was never reached, `ExportValid` and `MergedPolicyValid`
  are now `$null` (a blank cell in `results.csv`), not `False`.
- The account table renames `SettingCount` to `ReferenceCount` and `Settings` to `References`,
  in `accounts.json`, `accounts.csv` and the row `Get-SecEditWorker`'s scriptblock returns.
- `Status` is now `Partial`, not `Success`, when both exports validate but the worker itself
  reported an error (a failed identity or account-resolution read on the target, for example).
  A worker with no errors of its own is unaffected.

##### 1.2.0

- Every account referenced in `[Privilege Rights]`, across both exports, is now looked up on the
  target itself, in both directions: a `*S-1-...` token is translated to its account name, and a
  bare name (such as `Guest`) is translated to its SID. An account the target cannot resolve is
  recorded as `NotFound` with the lookup's own message and never changes a row's `Status`, the
  same way an empty `/mergedpolicy` export does not.
- Two files are added to every per-computer folder: `accounts.json` (the full account table) and
  `accounts.csv` (`Token`, `Kind`, `Sid`, `Name`, `Status`, `SettingCount`, `Error`).
- Each result row, and `results.csv`, gain two columns: `AccountCount` and
  `AccountUnresolvedCount`.
- Every csv file this module writes (`results.csv`, `accounts.csv`) now carries a UTF-8 byte
  order mark on both Windows PowerShell 5.1 and PowerShell 7.

##### 1.1.0

- Renamed from `Get-UserRightsAssignments`, the single script from October 2021. This module
  grew out of that script. None of its code remains.
- Both export modes are collected for every computer, not user rights only: the plain
  `secedit /export` (the full effective local security policy) and `/mergedpolicy` (the
  settings Group Policy actually delivers), covering every area `secedit /export` writes, not
  only `USER_RIGHTS`.
- Every computer's identity is collected alongside its exports (name, domain, OS version and
  build, elevation, the account that ran the collection), together with every error seen, on
  the collecting computer or on the target, instead of the run stopping or silently producing
  nothing on the first problem.
- Files are written byte-exact, with a SHA-256 hash computed on the target and rechecked after
  the host writes the file to disk, instead of a single CSV per computer built from parsed
  values.
- Works against the local computer in-process and against any number of remote computers over
  WinRM in the same call, instead of one script per computer.
- Runs on Windows PowerShell 5.1 and PowerShell 7, with a Pester test suite covering both
  engines.

##### 1.0.0

- The original October 2021 script, `Get-UserRightsAssignments`: collected user rights
  assignments only, through `secedit /export` run over `Invoke-Command`, covering the
  `USER_RIGHTS` area of the export.
- It wrote one CSV per computer and had no error handling. A problem on one target
  could stop the whole run or leave that computer's output silently missing.

## Background

Computers get moved between domains, forests, or out to a workgroup more often than the
security implications get checked at the time. A computer's local security policy is partly
its own and partly delivered by whichever Group Policy Objects apply to it. When it moves, the
GPOs it used to receive stop applying, and nothing on the computer itself records what used to
be there.

### Risk(s)

A computer moved to another domain or environment loses the security settings its source GPOs
delivered, silently. Services, scheduled tasks, and hardening baselines that were relying on
those settings (a user right, a registry-backed policy, an audit setting) keep running until
something that depended on the setting fails, which can be long after the move and hard to
trace back to it.

### Mitigation

Collect both exports from every computer before the move: the plain export shows the full
policy as it stands, and the `/mergedpolicy` export shows exactly what the source GPOs were
delivering. After the move, compare the `/mergedpolicy` export against the GPOs that apply in
the target environment to see what, if anything, needs to be replicated locally or through a
new GPO.

## Requirements

Only three things:

- `secedit.exe` present on every target (it ships with Windows, so this is normally already true).
- Windows PowerShell 5.1 or PowerShell 7 on the collecting computer; the targets run Windows PowerShell 5.1.
- Administrative rights on every target for the account running the collection. Without them, secedit returns
  exit code 740 and writes no export file. The run still completes, but that computer's rows are
  marked `Failed` with that reason.

Nothing else is required. There is no dependency on any other PowerShell module, no domain
requirement, and nothing in the module refers to any specific domain, server, or account name.
It runs the same way on a domain-joined computer and on a workgroup computer, and against a mix
of both in the same run. Local collection never uses WinRM. Remote collection needs WinRM
reachable from the computer you run this from. If you do not pass `-Credential`, it uses your own
logged-on identity, exactly as any other remote PowerShell command would.

Hardening baselines can switch remote collection off. The CIS Level 2 benchmarks, for example,
set "Allow remote server management through WinRM" to Disabled, which removes the WinRM
listener on member servers and domain controllers. A remote call to such a computer returns a
`Failed` row with the connection error, and the other computers in the same call are not
affected. Run the command locally on those computers instead, for example through your software
distribution tool or a scheduled task, and collect the output folders afterwards. A local run
never uses WinRM and gives the same output.

Use the fully qualified domain name (FQDN) for remote targets, for example
`SRV010.contoso.com` rather than `SRV010` or an IP address. Kerberos, which WinRM uses by
default in a domain, needs a name it can match to the computer's account, and an IP
address falls back to rules that need TrustedHosts and explicit credentials. With
`-UseSSL` the FQDN is normally required: the collection then connects over WinRM HTTPS
(port 5986), and the name you pass must match the subject or subject alternative name of
the target's listener certificate, which normally carries only the FQDN. A short name or
an IP address then fails with WinRM error 12175, a certificate name mismatch. The target
needs an HTTPS listener and an inbound firewall rule for port 5986, and the collecting
computer must trust the certificate's issuing CA. Certificate checks are never skipped:
the module offers no SkipCACheck or SkipCNCheck option, by design. A target in a workgroup, or addressed by IP, needs the collecting computer to list it in TrustedHosts and, for a local administrator account that is not the built-in Administrator, `LocalAccountTokenFilterPolicy` set to 1 on the target; the module changes neither setting.

Known limits. The module was verified on Windows Server 2016, 2019, 2022 and 2025 as local runs and as WinRM targets over HTTP, Windows Server 2022 over HTTPS, and Windows 11. Windows client editions and non-English Windows installations are untested: the code matches no English console text and reads SIDs and numeric codes, so locale risk is low, but it is not proven. The module runs in FullLanguage mode only: under ConstrainedLanguage mode, which an enforced WDAC or AppLocker policy produces, the worker fails at its first .NET call and the computer's row comes back `Failed` with that error; no file is left behind. The module files are not signed, so an AllSigned execution policy or a publisher rule refuses the import (see Importing the Module). A JEA endpoint does not run the worker: the module has no -ConfigurationName.

Automation. The functions never throw and the process exit code is 0 even when every row is `Failed`: a wrapper decides on the `Status` column of `results.csv` or the row objects, not on the exit code. No timeout parameter exists; a remote call uses the WinRM defaults (operation timeout 3 minutes). Running twice into the same `-OutputPath` never overwrites: every run gets its own UTC-stamped run folder. A caller's -WarningAction Stop turns a warning into a terminating error; the collectors emit their warnings after the run files are written, so the output on disk is complete in that case too.

## Output Data Handling

The output is a configuration inventory of every computer you collect from. It holds no
password, key or password hash that the module reads on purpose, but it describes the computers
in a detail that is useful to an attacker: which accounts run what, with which rights, from
which path. Treat every output folder as confidential.

What the output contains:

- The two `.inf` exports: the full local security policy, including password and lockout
  policy, audit policy, user rights assignments, security options, and the registry, service
  and file permissions set by policy.
- The `.log`, `.scesrv.log` and `.stdout.txt` files: secedit's own record of each export.
- `accounts.csv` and `accounts.json`: every account and group named in the user rights, with
  their SIDs and names.
- `results.csv`, `run.json`, `summary.json` and each computer's `system.json`: the computers
  collected, their names, domain, OS build, hardware UUID (`ComputerId`), `MachineGuid` and the
  SID reference (`MachineSid`, `DomainSid`, `ComputerAccountSid`, `DomainNetbiosName`), and the
  result and errors of each.

Nothing is redacted. secedit exports policy, not credentials: no password or password hash is in
these files.

Recommended handling:

- Write the output to a folder that only administrators can read. The module creates its run
  folder under `-OutputPath` and sets no permissions of its own, so the run folder inherits the
  permissions of its parent.
- Move the output only as an encrypted archive or over an encrypted channel, never by
  unencrypted email or an open file share.
- Keep each run folder intact. Its files refer to each other by `RunId` and `ComputerId`, and an
  edited file cannot be told apart from an original one.
- Delete the output when the analysis is finished, following your own retention rules.

The collection writes nothing to the computers it reads, apart from a temporary work folder
under the collecting account's `%TEMP%` that holds the two exports and is removed at the end of
the run. A remote run returns its data over WinRM, which encrypts the traffic of a Kerberos or
NTLM authenticated session even over HTTP, unless unencrypted traffic has been allowed on the
endpoint.

File formats. The csv files are UTF-8 with a byte order mark, every cell quoted, one row per line (whitespace inside a cell is collapsed to one space); the json files are UTF-8 without a byte order mark, and a top-level array is an array at zero and one element too. The csv is for spreadsheets; a loader that needs the source form of a value, or the null against empty-string distinction, reads the json.

## Importing the Module

From an elevated Windows PowerShell 5.1 or PowerShell 7 prompt, on the computer you want to
collect from or run the collection from. The module is not signed, so a copy downloaded or copied from elsewhere
needs unblocking and a process-scoped execution policy relaxed before it will import. This does
not bypass a Group Policy-enforced `AllSigned` execution policy, which overrides the process
scope and still blocks the import:

```powershell
Get-ChildItem C:\Path\To\RemoteSecEdit -Recurse | Unblock-File
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Import-Module C:\Path\To\RemoteSecEdit\RemoteSecEdit\RemoteSecEdit.psd1
```

## Examples

Collecting from the local computer only:

```powershell
PS C:\> Get-SecEditExport -OutputPath C:\SecEditRuns

ComputerName             : WS01
ComputerId               : 11111111-2222-3333-4444-555555555501
Status                   : Success
Transport                : Local
OutputFolder             : C:\SecEditRuns\RemoteSecEdit-20260927-111810Z\WS01_26200_20260927-111811Z
IsElevated               : True
ExportExitCode           : 0
MergedPolicyExitCode     : 0
ExportValid              : True
MergedPolicyValid        : True
ExportSettingLines       : 120
MergedPolicySettingLines : 0
AccountCount             : 16
AccountUnresolvedCount   : 0
Error                    :
ErrorCount               : 0
Errors                   : {}
```

Collecting from a mix of remote computers, including a name that does not resolve. The bad name
still comes back as a `Failed` row instead of stopping the run:

```powershell
PS C:\SecEditTest> 'SRV020', 'DC01', 'dc01.contoso.com', 'DC02', 'SRV050', 'WS01', 'NOSUCHHOST01' |
    Get-SecEditExport -OutputPath 'out' |
    Format-Table -Property ComputerName, ComputerId, Status, Transport, ExportSettingLines, MergedPolicySettingLines, AccountCount, AccountUnresolvedCount, ErrorCount, Error

ComputerName     ComputerId                           Status  Transport ExportSettingLines MergedPolicySettingLines AccountCount AccountUnresolvedCount ErrorCount Error
------------     ----------                           ------  --------- ------------------ ------------------------ ------------ ---------------------- ---------- -----
SRV020           11111111-2222-3333-4444-555555555503 Success Local                    116                       20           16                      0          0
DC01             11111111-2222-3333-4444-555555555504 Success WinRM                    122                       47           18                      1          0
dc01.contoso.com 11111111-2222-3333-4444-555555555504 Success WinRM                    122                       47           18                      1          0
DC02             11111111-2222-3333-4444-555555555505 Success WinRM                    124                       47           19                      0          0
SRV050           11111111-2222-3333-4444-555555555506 Success WinRM                    118                       20           18                      0          0
WS01             11111111-2222-3333-4444-555555555507 Success WinRM                    134                       17           15                      0          0
WARNING: NOSUCHHOST01: Connecting to remote server NOSUCHHOST01 failed with the following error message : WinRM cannot process the request. The following error occurred while using Kerberos authentication: Cannot find the computer NOSUCHHOST01. Verify that the computer exists on the network and that the name provided is spelled correctly. For more information, see the about_Remote_Troubleshooting Help topic.
NOSUCHHOST01                                          Failed  WinRM                                                                                              1 Connecting to remote server NOSUCHHOST01 failed with the following error message : WinRM ca...
```

Computer names can also be passed with `-ComputerName` instead of the pipeline, and a credential
supplied for remote targets that the caller's own account does not have rights on:

```powershell
'SRV01', 'SRV02', 'SRV03' | Get-SecEditExport -Credential (Get-Credential) -OutputPath C:\SecEditRuns
```

`.`, `localhost`, your own computer name, and your own DNS name (any case) are all treated as
local and never go over WinRM. Anything else goes over WinRM through a single `Invoke-Command`
call.

Over WinRM HTTPS with `-UseSSL`, using the FQDN that the target's listener certificate
carries:

```powershell
PS C:\UseSSLTest> Get-SecEditExport -ComputerName 'SRV099.contoso.com' -UseSSL -OutputPath 'out' | Format-Table -Property ComputerName, ComputerId, Status, Transport, ExportSettingLines, ErrorCount

ComputerName       ComputerId                           Status  Transport ExportSettingLines ErrorCount
------------       ----------                           ------  --------- ------------------ ----------
SRV099.contoso.com 11111111-2222-3333-4444-555555555502 Success WinRM                    113          0
```

## Functions

The list of the functions contained in this module.

### Get-SecEditExport

```PowerShell
<#
.SYNOPSIS
    Collects the raw output of secedit /export from local or remote computers.

.DESCRIPTION
    Runs secedit /export twice per computer, once plain and once with /mergedpolicy, on the
    local computer in-process or on remote computers over WinRM (one Invoke-Command call for
    every remote target). Nothing in the exported files is parsed, except for the account
    references in [Privilege Rights], which the target itself resolves in both directions (a
    SID to a name, a name to a SID) so the raw files and the account table can travel
    together. The raw inf and log bytes are written to a per-computer folder under
    -OutputPath together with the identity of the computer and every error seen on the way. A
    separate project analyses the files.

    The identity also carries four SID reference values, MachineSid, DomainSid,
    ComputerAccountSid and DomainNetbiosName, that say whose an S-1-5-21 SID is. MachineSid is
    the SID of the computer's own account database, read as the local account with RID 500
    through CIM (Win32_UserAccount filtered on the computer's own name), with the RID removed.
    The three domain values come from the computer's own domain account, through the same
    account lookup the module uses for the account table, and are read only on a
    domain-joined computer. No Active Directory module and no LDAP is used. A domain
    controller has no MachineSid, so it stays null without an error. The domain values are
    null on a workgroup computer.

    Every computer carries a ComputerId (Win32_ComputerSystemProduct.UUID, upper case, $null
    when the target was never reached) alongside its ComputerName, so a computer that was
    renamed or moved between domains still joins across runs. The output layout, key order and
    types are shared with RemoteService and RemoteScheduledTask.

    Prerequisites, and nothing beyond them: secedit.exe present on the target, Windows
    PowerShell 5.1 on the target, and administrative rights on the target (secedit /export
    without administrative rights returns exit code 740 and writes no cfg file). Remote
    targets additionally need WinRM reachable from the caller. Local targets never use WinRM.
    Remote targets called without -Credential use the caller's own identity, exactly like any
    other Invoke-Command call. Nothing in this module is specific to any domain, server name,
    or account. It works unchanged on a domain-joined computer or on a workgroup computer.

    Writes <OutputPath>\RemoteSecEdit-<yyyyMMdd-HHmmss>Z\ containing run.json, results.csv,
    and one folder per computer that was actually reached. Each result row carries ComputerId,
    AccountCount, AccountUnresolvedCount and ErrorCount alongside the export counts, and each
    per-computer folder gains accounts.json and accounts.csv beside the raw export files. On a
    Failed row where the target was never reached, every module column, including the two
    booleans, is $null rather than false. An account the target could not resolve is data for
    the analysis, not a reason to mark the row anything other than what its exports already
    earned. Every failure short of a bad -OutputPath or an empty -ComputerName list becomes a
    result row plus one Write-Warning. It is never a terminating error.

.PARAMETER ComputerName
    Targets. '.', 'localhost', '127.0.0.1', '::1', the local NetBIOS name and the local FQDN
    (case-insensitive) run in-process without WinRM. Everything else goes through one
    Invoke-Command call. Accepts pipeline input by value and by property name. Duplicates are
    removed case-insensitively. The first-seen order is kept. Defaults to the local computer
    name when nothing is supplied.

.PARAMETER Credential
    Passed to Invoke-Command for remote targets only. Ignored for local targets (a
    Write-Verbose line records that it was ignored). When omitted, remote targets are
    contacted with the caller's own identity.

.PARAMETER UseSSL
    Connects to remote targets over WinRM HTTPS (port 5986) instead of HTTP. Each target
    needs an HTTPS listener with a certificate the calling computer trusts, and the name you
    pass must match the certificate's subject or subject alternative name, which is normally
    the computer's fully qualified domain name (FQDN). A short name or an IP address fails
    the certificate name check with WinRM error 12175. Certificate checks are never skipped:
    the module offers no SkipCACheck or SkipCNCheck option, by design. Ignored for local
    targets, which never use WinRM. Recorded as UseSSL in run.json.

.PARAMETER OutputPath
    Root folder for the run. May be relative. Resolved once, against the current location,
    before any collection starts. Created if missing. Must be writable. This is tested by
    creating the run folder before any collection starts, so a bad -OutputPath fails before
    any target is contacted.

.PARAMETER ThrottleLimit
    Passed to Invoke-Command for remote targets. From 1 to 256. Defaults to 32.

.PARAMETER SkipSidReference
    Leaves the SID reference unread: MachineSid, DomainSid, ComputerAccountSid and
    DomainNetbiosName are null in system.json, and run.json records SkipSidReference true.
    Meant for a caller that runs several collectors against the same computers and needs the
    reference from one of them only, as RemoteBaseline does. Without the switch every run
    reads it.

.EXAMPLE
    PS C:\> Get-SecEditExport -OutputPath C:\SecEditRuns

    ComputerName             : WS01
    ComputerId               : 11111111-2222-3333-4444-555555555501
    Status                   : Success
    Transport                : Local
    OutputFolder             : C:\SecEditRuns\RemoteSecEdit-20260927-111810Z\WS01_26200_20260927-111811Z
    IsElevated               : True
    ExportExitCode           : 0
    MergedPolicyExitCode     : 0
    ExportValid              : True
    MergedPolicyValid        : True
    ExportSettingLines       : 120
    MergedPolicySettingLines : 0
    AccountCount             : 16
    AccountUnresolvedCount   : 0
    Error                    :
    ErrorCount               : 0
    Errors                   : {}

    Collects from the local computer only, run elevated on a workgroup Windows 11 host.

.EXAMPLE
    PS C:\SecEditTest> 'SRV020', 'DC01', 'dc01.contoso.com', 'DC02', 'SRV050', 'WS01', 'NOSUCHHOST01' |
        Get-SecEditExport -OutputPath 'out' |
        Format-Table -Property ComputerName, ComputerId, Status, Transport, ExportSettingLines, MergedPolicySettingLines, AccountCount, AccountUnresolvedCount, ErrorCount, Error

    ComputerName     ComputerId                           Status  Transport ExportSettingLines MergedPolicySettingLines AccountCount AccountUnresolvedCount ErrorCount Error
    ------------     ----------                           ------  --------- ------------------ ------------------------ ------------ ---------------------- ---------- -----
    SRV020           11111111-2222-3333-4444-555555555503 Success Local                    116                       20           16                      0          0
    DC01             11111111-2222-3333-4444-555555555504 Success WinRM                    122                       47           18                      1          0
    dc01.contoso.com 11111111-2222-3333-4444-555555555504 Success WinRM                    122                       47           18                      1          0
    DC02             11111111-2222-3333-4444-555555555505 Success WinRM                    124                       47           19                      0          0
    SRV050           11111111-2222-3333-4444-555555555506 Success WinRM                    118                       20           18                      0          0
    WS01             11111111-2222-3333-4444-555555555507 Success WinRM                    134                       17           15                      0          0
    WARNING: NOSUCHHOST01: Connecting to remote server NOSUCHHOST01 failed with the following error message : WinRM cannot process the request. The following error occurred while using Kerberos authentication: Cannot find the computer NOSUCHHOST01. Verify that the computer exists on the network and that the name provided is spelled correctly. For more information, see the about_Remote_Troubleshooting Help topic.
    NOSUCHHOST01                                          Failed  WinRM                                                                                              1 Connecting to remote server NOSUCHHOST01 failed with the following error message : WinRM ca...

    Run from SRV020, a Server 2016 domain member, against a mix of remote computers plus one
    name that does not resolve. That row still comes back as a Failed result row, not a
    terminating error. DC01 reports one unresolved account, a well-known SID that Server 2022
    cannot translate, which is data for the analysis and not a failure.

.EXAMPLE
    PS C:\UseSSLTest> Get-SecEditExport -ComputerName 'SRV099.contoso.com' -UseSSL -OutputPath 'out' | Format-Table -Property ComputerName, ComputerId, Status, Transport, ExportSettingLines, ErrorCount

    ComputerName       ComputerId                           Status  Transport ExportSettingLines ErrorCount
    ------------       ----------                           ------  --------- ------------------ ----------
    SRV099.contoso.com 11111111-2222-3333-4444-555555555502 Success WinRM                    113          0

    Collects from one domain member over WinRM HTTPS (port 5986). The name is the FQDN, which
    matches the subject of the member's listener certificate. The short name SRV099 would fail the
    certificate name check with WinRM error 12175.

.NOTES
    FUNCTION: Get-SecEditExport
    AUTHOR:   Tom Stryhn
    GITHUB:   https://github.com/tomstryhn/

.INPUTS
    System.String[]. ComputerName is accepted from the pipeline, by value and by property
    name.

.OUTPUTS
    System.Management.Automation.PSObject, type name RemoteSecEdit.Result

.LINK
    https://github.com/tomstryhn/RemoteSecEdit
#>
```

## How it works

Two exports are collected per computer: the plain `secedit /export` (the full effective local
security policy) and `secedit /export /mergedpolicy` (domain Group Policy settings only, if
any. An empty merged export is a legitimate result on a computer with no applicable Group
Policy, not a failure).

Both run through one self-contained worker: in-process for local targets, or once per call
through `Invoke-Command` for remote targets, regardless of how many local aliases or remote
names were requested. The worker reads the target's identity, including a `ComputerId`
(`Win32_ComputerSystemProduct.UUID`, upper case) and a `MachineGuid`, runs both exports, reads
back the `.inf` and `.log` files it wrote plus `%windir%\security\logs\scesrv.log` if present,
checks each export's basic structure, resolves the account table, and returns everything as one
object. It never throws, every step records its own error and moves on. The collecting computer
reads its own `ComputerId` the same way, once, for `run.json`.

The worker also reads four SID reference values, with two reads and nothing else. `MachineSid` is
the local account with RID 500, read through CIM (`Win32_UserAccount` filtered on the computer's own
name, so only the local accounts come back), with the RID removed; `Win32_UserAccount` lists no local
account on a domain controller, so it is null there. `DomainSid`, `ComputerAccountSid` and `DomainNetbiosName`
come from the computer's own domain account through the same account lookup used for the account
table, and only on a domain-joined computer; they are null on a workgroup computer. A domain-joined
computer that cannot resolve its own account gets `identity: DomainSid: <message>` in `Errors` and a
`Partial` row. No Active Directory module and no LDAP is used. `-SkipSidReference` leaves all four
null with no error.

After both exports, the worker reads every token in `[Privilege Rights]` across both files
(`*S-1-...` and a bare local name such as `Guest`) and resolves each one once, never once per
line. A token that starts with `*` is a SID and is translated to its account name, and every
other token is a name and is translated to its SID. The literal `LocalSystem` (case-insensitive)
resolves to `S-1-5-18` without a lookup, and a name starting with `.\` has the `.` replaced with
the target's own computer name before the lookup runs. A token that does not resolve is recorded
as `NotFound` with the lookup's own message and never turns a row into anything other than what
its exports already earned: the account may belong to a domain the target cannot reach, to a
local account that does not exist there, or to a well-known SID that a newer Windows version
defines and the target's own version does not, and that is exactly the kind of fact the analysis side
needs to see, not a reason to treat the collection itself as having failed. The lookup runs on
the target because a local account, a virtual account and a domain account only resolve where the
target itself can reach them, and it carries no time bound beyond what the operating system
itself imposes.

Each run creates one new, timestamped folder under `-OutputPath`:

```
C:\SecEditRuns\RemoteSecEdit-<run timestamp>Z\
    run.json                       summary of the whole run, including SkipSidReference
    results.csv                    one row per computer, opens in Excel
    <COMPUTER>_<build>_<timestamp>Z\   one folder per computer actually reached
        system.json                      identity, with MachineSid, DomainSid, ComputerAccountSid
                                          and DomainNetbiosName after MachineGuid
        secedit-export.inf / .log
        secedit-export.scesrv.log        only when %windir%\security\logs\scesrv.log was present
        secedit-export.stdout.txt        only when secedit wrote something to stdout
        secedit-mergedpolicy.inf / .log
        secedit-mergedpolicy.scesrv.log  only when present, same as above
        secedit-mergedpolicy.stdout.txt  only when non-empty, same as above
        accounts.json                    every account referenced in [Privilege Rights]
        accounts.csv                     Token, Kind, Sid, Name, Status, ReferenceCount, Error
        summary.json                     one object: AccountCount, AccountUnresolvedCount,
                                          AccountUnresolvedTokens, AccountsDurationMs,
                                          Exports (the two mode summaries)
```

A computer that could not be reached at all (WinRM failure, wrong name, and so on) still gets a
row in `results.csv` and `run.json`, but no folder of its own, since nothing was collected from
it. Nothing in a per-computer folder is modified after the run.

Each computer's row has a `Status`:

- **Success**: both exports were collected and passed the basic structural check (right file
  format, expected sections present), and the worker itself reported no error. An empty
  `/mergedpolicy` export is still `Success`. It means no Group Policy security settings apply
  there, which is itself useful information, not a failure.
- **Partial**: one of the two exports came back valid and the other did not, or both are valid
  but the worker reported an error of its own (a failed identity read, an account lookup that
  raised something other than "not found", and so on). An unresolved account never causes this.
  See below.
- **Failed**: neither export is valid, or the computer could not be reached at all. When the
  computer was never reached, every column this module adds, including `ExportValid` and
  `MergedPolicyValid`, is empty rather than `False`, so a never-reached row cannot be mistaken
  for one where the exports actually ran and failed the structural check.

An account that did not resolve (`AccountUnresolvedCount` greater than 0) never changes `Status`
on its own. It is reported through the account table, the same way an empty `/mergedpolicy`
export is reported through `MergedPolicySettingLines` rather than through `Status`.

Every row also carries `Error` (the first problem seen, blank when there was none), `ErrorCount`
(how many messages `Errors` holds), and `Errors` itself (every problem seen, in `run.json` only,
not in the CSV). For anything other than `Success`, the same message is also written as a
`Write-Warning` while the command runs, so you will see it scroll past in the console as well as
find it in the output files afterwards.

Common reasons for less than `Success`:

- `740` in `ExportExitCode` or `MergedPolicyExitCode`: the account was not elevated on that
  computer. This applies to local runs. On a remote target a non-administrator account normally
  never reaches secedit at all, since WinRM itself refuses the connection with an access-denied
  error first, so a remote row is far more likely to show a WinRM connection error than a 740
  exit code.
- A WinRM error in `Error`: the computer was unreachable, the name was wrong, or the account
  lacks rights to connect.
- `no result and no error returned`: WinRM did not report either a result or an error for that
  computer. Treat it the same as unreachable and try again.

No security setting is changed on any target. This module only reads. secedit itself still
overwrites `%windir%\security\logs\scesrv.log` on every target it runs against (that is secedit's
own behaviour, not something this module adds), and the collector creates, then removes, one work
folder under the connecting account's own temp folder on each target for the duration of that
target's collection.

### What to send back

Send the whole `RemoteSecEdit-<timestamp>Z` folder (zipped is fine). It contains everything the
analysis side needs: `run.json`, `results.csv`, and every reached computer's folder with its raw
`.inf` and `.log` files. Do not edit any file inside it before sending. Nothing in a per-computer
folder is touched again after the run, and the analysis relies on that.

## Testing

`tests\Invoke-Tests.ps1` runs `PSScriptAnalyzer` (pinned to 1.25.0) over the module and tests
folder using `PSScriptAnalyzerSettings.psd1`, then runs the Pester suite (pinned to 6.1.0). It
exits 1 on any analyzer Error or Warning finding, on any failed test, or when zero tests ran.

The gate needs Pester 6.1.0 and PSScriptAnalyzer 1.25.0 exactly; Windows PowerShell 5.1 ships Pester 3.4, so install both once per engine with `Install-Module Pester -RequiredVersion 6.1.0 -Scope CurrentUser -Force` and `Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Scope CurrentUser`. Without them the gate exits 1 before any test runs. A few tests that need administrative rights report Inconclusive in an unelevated session, which does not fail the gate; run the gate once elevated per release to cover them.

Run it under both engines from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\Invoke-Tests.ps1
pwsh -NoProfile -File tests\Invoke-Tests.ps1
```

Every path inside the test suite is derived from `$PSScriptRoot`, so it also passes from a
relocated copy of the repository.

## Support and versioning

Versions follow semantic versioning: a patch release changes no output file, column or value; a minor release may add columns, keys or files and may change a value's rule, and the five Remote collectors release such a change together under one output convention version; a major release would change an existing column or key. Every release is a tagged commit (`v<version>`) and the Version Changes list above is the change log. Report a defect or a question as an issue on the project repository (ProjectUri in the manifest); report a security concern as described in SECURITY.md. The module is provided under the MIT licence without a support contract; fixes land in the next release.

## References

- [secedit export - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export)

## License

Tom Stryhn, https://github.com/tomstryhn

MIT License, see [LICENSE](LICENSE)
