@{
    RootModule           = 'RemoteSecEdit.psm1'
    ModuleVersion        = '1.5.0'
    GUID                 = '69e5a969-ad16-4a08-bcae-e57bbfcf6349'
    Author               = 'Tom Stryhn'
    CompanyName          = 'Tom Stryhn'
    Copyright            = 'Copyright (c) 2021-2026 Tom Stryhn'
    Description          = 'PowerShell Module to collect the raw secedit /export output, plain and mergedpolicy, from local and remote computers'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @('Get-SecEditExport')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    FileList = @(
        'RemoteSecEdit.psd1',
        'RemoteSecEdit.psm1',
        'LICENSE',
        'src\ps1\Complete-SecEditComputer.ps1',
        'src\ps1\ConvertTo-SecEditResultRow.ps1',
        'src\ps1\Get-SecEditExport.ps1',
        'src\ps1\Get-SecEditHostComputerId.ps1',
        'src\ps1\Get-SecEditSafeProperty.ps1',
        'src\ps1\Get-SecEditWorker.ps1',
        'src\ps1\Initialize-SecEditRunFolder.ps1',
        'src\ps1\Invoke-SecEditLocal.ps1',
        'src\ps1\Invoke-SecEditRemote.ps1',
        'src\ps1\Resolve-SecEditComputerList.ps1',
        'src\ps1\Resolve-SecEditRemoteErrorName.ps1',
        'src\ps1\Resolve-SecEditUniqueFolder.ps1',
        'src\ps1\Test-SecEditLocalName.ps1',
        'src\ps1\Write-SecEditCsvFile.ps1',
        'src\ps1\Write-SecEditTextFile.ps1'
    )

    PrivateData = @{
        PSData = @{
            Tags         = @('PSEdition_Desktop', 'PSEdition_Core', 'Windows', 'Security', 'SecEdit', 'SecurityPolicy', 'GroupPolicy')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/tomstryhn/RemoteSecEdit'
            ReleaseNotes = '1.5.0: unelevated runs report the shortfall and come back Partial (RemoteScheduledTask, RemoteService); every error message and csv cell is one line; the per-computer folder name (reported name and build number) is sanitised; the result callback never ends the run; loader hardened against wildcard paths; the worker work folder is removed in a finally block, SHA-256 through Get-FileHash (Get-SecEditSha256Hex removed), secedit path test reports its own failures; README Known limits, Automation, File formats, Support and versioning, workgroup prerequisites; SECURITY.md; examples anonymised; output convention 1.2 (run.json SchemaVersion 1.2). RemoteSecEdit 1.4.1. A worker result carrying an empty entry in its error list no longer ends the run, local aliases in one call get identical rows apart from ComputerName, remote results are completed and written as each target answers, and system.json is built from a fixed property list. The Get-WmiObject fallback is removed and internal code is simplified. No output or data format change. RemoteSecEdit 1.4.0. New -UseSSL switch: remote targets are reached over WinRM HTTPS (port 5986) instead of HTTP, and run.json gains UseSSL after ThrottleLimit; the output convention moves to version 1.1 (SchemaVersion 1.1). RemoteSecEdit 1.3.1. Comments in published files no longer point at working documents that are not part of the repository; the rules they cited are stated in place. No behaviour, output or data format change. RemoteSecEdit 1.3.0. Output now follows the shared layout used by RemoteService and RemoteScheduledTask: ComputerId and MachineGuid identify every computer independently of its name, run.json and system.json carry Collector, CollectorVersion, SchemaVersion and RunId, summary.json is one object with an Exports array instead of a bare array of two, and every row gains ErrorCount. accounts.csv and the account table rename SettingCount to ReferenceCount and Settings to References. RemoteSecEdit 1.2.0. Resolves every account referenced in the user rights of both exports on the target, in both directions, and writes accounts.json and accounts.csv per computer. Every csv file now carries a UTF-8 byte order mark on both engines. RemoteSecEdit 1.1.0. Renamed from Get-UserRightsAssignments (October 2021), a single script that collected the user rights assignments through secedit over Invoke-Command without error handling and with a CSV per computer as its only output. This version collects the full secedit export in both modes, the identity of each computer and every error, and writes the raw files for a separate analysis.'
        }
    }
}
