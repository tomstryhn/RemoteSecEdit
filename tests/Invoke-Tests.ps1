<#PSScriptInfo

.VERSION 1.6.0
.GUID fcc82c04-edde-41c3-8a45-0fd535769b6b
.AUTHOR Tom Stryhn
.COMPANYNAME Tom Stryhn
.COPYRIGHT 2021-2026 (c) Tom Stryhn
.TAGS RemoteSecEdit SecEdit SecurityPolicy
.LICENSEURI https://raw.githubusercontent.com/tomstryhn/RemoteSecEdit/main/LICENSE
.PROJECTURI https://github.com/tomstryhn/RemoteSecEdit
.DESCRIPTION Runs PSScriptAnalyzer and the Pester suite for RemoteSecEdit.

#>

<#
.SYNOPSIS
    Runs PSScriptAnalyzer and the Pester suite for RemoteSecEdit.

.DESCRIPTION
    Runs PSScriptAnalyzer over the module and tests folder, then runs the Pester suite. Exits 1
    on any analyzer Error or Warning finding, on any failed test, or when zero tests ran. Exits 0
    only when analysis is clean and at least one test ran and passed. Every path is derived from
    $PSScriptRoot, so this still works from a relocated copy of the repository.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$modulePath = Join-Path -Path $repoRoot -ChildPath 'RemoteSecEdit'
$testsPath = $PSScriptRoot
$settingsPath = Join-Path -Path $repoRoot -ChildPath 'PSScriptAnalyzerSettings.psd1'
$testFilePath = Join-Path -Path $testsPath -ChildPath 'RemoteSecEdit.Tests.ps1'

Write-Verbose "Repo root: $repoRoot"

try {
    Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force -ErrorAction Stop
} catch {
    Write-Error "Could not load PSScriptAnalyzer 1.25.0: $($_.Exception.Message)"
    exit 1
}

$analyzerResults = @()
$analyzerResults += Invoke-ScriptAnalyzer -Path $modulePath -Recurse -Settings $settingsPath
$analyzerResults += Invoke-ScriptAnalyzer -Path $testsPath -Recurse -Settings $settingsPath

$analyzerFindings = @($analyzerResults | Where-Object { $_.Severity -eq 'Error' -or $_.Severity -eq 'Warning' })

if ($analyzerFindings.Count -gt 0) {
    $analyzerFindings | Format-Table -Property Severity, RuleName, ScriptName, Line, Message -AutoSize -Wrap | Out-String | Write-Output
    Write-Error "PSScriptAnalyzer reported $($analyzerFindings.Count) Error/Warning finding(s)."
    exit 1
}

Write-Output 'PSScriptAnalyzer: clean, no Error or Warning findings.'

try {
    Import-Module Pester -RequiredVersion 6.1.0 -Force -ErrorAction Stop
} catch {
    Write-Error "Could not load Pester 6.1.0: $($_.Exception.Message)"
    exit 1
}

$config = New-PesterConfiguration
# Pester resolves Run.Path as a wildcard, so escape it: a repository folder path containing [ or ]
# would otherwise silently match nothing.
$config.Run.Path = [Management.Automation.WildcardPattern]::Escape($testFilePath)
$config.Run.PassThru = $true
$config.Run.Exit = $false
$config.Output.Verbosity = 'Detailed'

$pesterResult = Invoke-Pester -Configuration $config

$totalCount = 0
if ($pesterResult -and $pesterResult.PSObject.Properties['TotalCount']) {
    $totalCount = $pesterResult.TotalCount
}

Write-Output "Pester total tests run: $totalCount"

if ($totalCount -eq 0) {
    Write-Error 'Zero Pester tests ran.'
    exit 1
}

if ($pesterResult.FailedCount -gt 0) {
    Write-Error "$($pesterResult.FailedCount) Pester test(s) failed."
    exit 1
}

Write-Output 'PSScriptAnalyzer and Pester both passed.'
exit 0
