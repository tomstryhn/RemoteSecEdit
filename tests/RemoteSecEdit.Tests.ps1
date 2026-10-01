<#PSScriptInfo

.VERSION 1.5.0
.GUID 1fd3e34a-d1e2-4c44-82d1-055d28abbe2c
.AUTHOR Tom Stryhn
.COMPANYNAME Tom Stryhn
.COPYRIGHT 2021-2026 (c) Tom Stryhn
.TAGS RemoteSecEdit SecEdit SecurityPolicy
.LICENSEURI https://raw.githubusercontent.com/tomstryhn/RemoteSecEdit/main/LICENSE
.PROJECTURI https://github.com/tomstryhn/RemoteSecEdit
.DESCRIPTION Pester tests for the RemoteSecEdit module.

#>

<#
Pester tests for the RemoteSecEdit module, written for Pester 6.1.0. Covers the worker
scriptblock against four stub secedit executables, the ComputerId and MachineGuid identity read,
local name detection, local alias folder sharing, relative OutputPath resolution, the public
function against a mocked remote transport, credential forwarding to Invoke-Command, the account
table resolved from [Privilege Rights], run.json, system.json, results.csv and accounts.csv key
order, summary.json as one object, Write-SecEditCsvFile, parameter validation, and the module
manifest. Every path is derived from $PSScriptRoot, so the suite still passes from a relocated
copy of the repository. The ok stub names the built-in guest account by its English name, Guest,
so the account assertions expect a host where that account has not been renamed by policy or
localised.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Path $PSScriptRoot -Parent
    $script:ManifestPath = Join-Path -Path $script:RepoRoot -ChildPath 'RemoteSecEdit\RemoteSecEdit.psd1'
    $script:Psm1Path = Join-Path -Path $script:RepoRoot -ChildPath 'RemoteSecEdit\RemoteSecEdit.psm1'
    $script:StubsPath = Join-Path -Path $PSScriptRoot -ChildPath 'stubs'
    $script:OkStub = Join-Path -Path $script:StubsPath -ChildPath 'secedit-ok.ps1'
    $script:Stub740 = Join-Path -Path $script:StubsPath -ChildPath 'secedit-740.ps1'
    $script:StubEmpty = Join-Path -Path $script:StubsPath -ChildPath 'secedit-empty.ps1'
    $script:StubMerged = Join-Path -Path $script:StubsPath -ChildPath 'secedit-merged.ps1'
    $script:StubMissing = Join-Path -Path $script:StubsPath -ChildPath 'does-not-exist.ps1'

    Import-Module $script:ManifestPath -Force
    $script:Module = Get-Module RemoteSecEdit

    # The computer names a fake worker object reports about itself, kept in variables so no test hard-codes a ComputerName argument.
    $script:FixtureNameOne = 'REMOTE1'
    $script:FixtureNameTwo = 'REMOTE2'

    function Get-Sha256Hex {
        param([byte[]]$Bytes)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $sha.ComputeHash($Bytes)
        } finally {
            $sha.Dispose()
        }
        return -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
    }

    function Get-FakeExportObject {
        param(
            [string]$Mode,
            [bool]$Valid = $true,
            [int]$SettingLineCount = 25,
            [string[]]$Sections = @('System Access', 'Privilege Rights', 'Version'),
            [string]$Content = 'dummy content for hashing'
        )
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content + $Mode)
        [pscustomobject]@{
            Mode              = $Mode
            CommandLine       = "/export /cfg x /log y" + $(if ($Mode -eq 'mergedpolicy') { ' /mergedpolicy' } else { '' })
            ExitCode          = 0
            StdOut            = ''
            DurationMs        = 10
            InfBase64         = [Convert]::ToBase64String($bytes)
            InfSha256         = Get-Sha256Hex -Bytes $bytes
            InfLength         = $bytes.Length
            LogBase64         = $null
            ScesrvLogText     = $null
            Valid             = $Valid
            ValidationMessage = $(if ($Valid) { '' } else { 'forced invalid for test' })
            Sections          = @($Sections)
            SettingLineCount  = $SettingLineCount
        }
    }

    function Get-FakeWorkerObject {
        param(
            [string]$ComputerName = 'FAKEPC',
            [string]$PSComputerNameValue,
            [bool]$ExportValid = $true,
            [bool]$MergedValid = $true,
            [int]$MergedSettingLineCount = 0,
            [string]$ComputerIdValue = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE',
            [string]$MachineGuidValue = '11111111-2222-3333-4444-555555555555',
            [string[]]$WorkerErrors = @()
        )
        # One Resolved Sid-kind account with two settings, one NotFound Name-kind account with one setting.
        $accounts = @(
            [pscustomobject]@{
                Token          = '*S-1-5-32-544'
                Kind           = 'Sid'
                Sid            = 'S-1-5-32-544'
                Name           = 'BUILTIN\Administrators'
                Status         = 'Resolved'
                ReferenceCount = 2
                References     = @('export:SeBackupPrivilege', 'export:SeRestorePrivilege')
                Error          = ''
            },
            [pscustomobject]@{
                Token          = 'CONTOSO\nosuchuser'
                Kind           = 'Name'
                Sid            = $null
                Name           = 'CONTOSO\nosuchuser'
                Status         = 'NotFound'
                ReferenceCount = 1
                References     = @('export:SeServiceLogonRight')
                Error          = 'Some or all identity references could not be translated.'
            }
        )
        $accountUnresolvedCount = @($accounts | Where-Object { $_.Status -eq 'NotFound' }).Count

        $obj = [pscustomobject]@{
            ComputerName           = $ComputerName
            DnsHostName            = "$ComputerName.example"
            Domain                 = 'WORKGROUP'
            OSCaption              = 'Windows Server 2022 Standard'
            OSVersion              = '10.0.20348'
            CurrentBuild           = '20348'
            UBR                    = '1'
            DisplayVersion         = '21H2'
            EditionID              = 'ServerStandard'
            InstallationType       = 'Server'
            Culture                = 'en-US'
            TimeZoneId             = 'UTC'
            PSVersion              = '5.1.20348.1'
            CollectedBy            = 'WORKGROUP\Administrator'
            PartOfDomain           = $false
            IsElevated             = $true
            DomainRole             = 0
            CollectedUtc           = '2026-09-25T00:00:00Z'
            ComputerId             = $ComputerIdValue
            MachineGuid            = $MachineGuidValue
            SecEditPath            = 'C:\Windows\System32\secedit.exe'
            SecEditVersion         = '10.0.20348.1'
            AccountCount           = $accounts.Count
            AccountUnresolvedCount = $accountUnresolvedCount
            AccountsDurationMs     = 5
            Exports                = @(
                (Get-FakeExportObject -Mode 'export' -Valid $ExportValid -SettingLineCount 25),
                (Get-FakeExportObject -Mode 'mergedpolicy' -Valid $MergedValid -SettingLineCount $MergedSettingLineCount -Sections @('Version'))
            )
            Accounts               = @($accounts)
            Errors                 = @($WorkerErrors)
        }
        if ($PSComputerNameValue) {
            $obj | Add-Member -MemberType NoteProperty -Name 'PSComputerName' -Value $PSComputerNameValue
        }
        return $obj
    }
}

Describe 'Worker scriptblock' {
    BeforeAll {
        $script:Worker = & (Get-Module RemoteSecEdit) { Get-SecEditWorker }
    }

    It 'runs both exports for the ok stub: valid, sha256 matches, sections listed, errors empty, work folder removed' {
        $tempBefore = @(Get-ChildItem -Path $env:TEMP -Directory -Filter 'RemoteSecEdit-*' -ErrorAction SilentlyContinue)

        $result = & $script:Worker -SecEditPath $script:OkStub

        $result.Errors.Count | Should -Be 0
        $result.Exports.Count | Should -Be 2

        foreach ($exp in $result.Exports) {
            $exp.Valid | Should -BeTrue
            $exp.ExitCode | Should -Be 0
            $exp.Sections.Count | Should -BeGreaterThan 0
            $bytes = [Convert]::FromBase64String($exp.InfBase64)
            (Get-Sha256Hex -Bytes $bytes) | Should -Be $exp.InfSha256
        }

        $tempAfter = @(Get-ChildItem -Path $env:TEMP -Directory -Filter 'RemoteSecEdit-*' -ErrorAction SilentlyContinue)
        $tempAfter.Count | Should -Be $tempBefore.Count
    }

    It 'reads ComputerId upper case and MachineGuid as a GUID string on the test host' {
        $result = & $script:Worker -SecEditPath $script:OkStub

        $result.ComputerId | Should -Not -BeNullOrEmpty
        $result.ComputerId | Should -Be $result.ComputerId.ToUpperInvariant()
        $result.MachineGuid | Should -Match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    }

    It 'reports the workgroup-style merged export as valid with SettingLineCount 0 while the plain export stays fully valid' {
        # On a workgroup machine /mergedpolicy exits 0 and writes a small file holding only [Unicode], [Version] and [Profile Description]. This is a legitimate zero, not a validation failure.
        $result = & $script:Worker -SecEditPath $script:OkStub

        $exportExp = $result.Exports | Where-Object { $_.Mode -eq 'export' }
        $mergedExp = $result.Exports | Where-Object { $_.Mode -eq 'mergedpolicy' }

        $exportExp.Valid | Should -BeTrue
        $exportExp.SettingLineCount | Should -BeGreaterOrEqual 20

        $mergedExp.Valid | Should -BeTrue
        $mergedExp.SettingLineCount | Should -Be 0
        $mergedExp.Sections | Should -Contain 'Version'
    }

    It 'reports exit 740, no inf, Valid false, and the 740 error for the 740 stub' {
        $result = & $script:Worker -SecEditPath $script:Stub740

        foreach ($exp in $result.Exports) {
            $exp.ExitCode | Should -Be 740
            $exp.Valid | Should -BeFalse
            $exp.InfBase64 | Should -BeNullOrEmpty
        }
        ($result.Errors -join ' ; ') | Should -Match 'exit 740'
    }

    It 'collapses the embedded stdout whitespace (double space and line break) in the exit-code error for the 740 stub' {
        $result = & $script:Worker -SecEditPath $script:Stub740

        $exitErrors = @($result.Errors | Where-Object { $_ -match 'secedit export exit 740:.*sufficient permissions' })
        $exitErrors.Count | Should -Be 1
        $exitErrors[0] | Should -Be "secedit export exit 740: You do not have sufficient permissions to perform this command. Make sure that you are running as the local administrator or have opened the command prompt using the 'Run as administrator' option."
        $exitErrors[0] | Should -Not -Match '  '
        $exitErrors[0] | Should -Not -Match '[\r\n]'
    }

    It 'reports exit 0, no inf, Valid false with the message naming the file for the empty stub' {
        $result = & $script:Worker -SecEditPath $script:StubEmpty

        foreach ($exp in $result.Exports) {
            $exp.ExitCode | Should -Be 0
            $exp.Valid | Should -BeFalse
            $exp.ValidationMessage | Should -Match 'inf file not found'
            $exp.ValidationMessage | Should -Match ([regex]::Escape($exp.Mode))
        }
    }

    It 'reports exit code null and an error naming the path for a non-existent secedit path' {
        $result = & $script:Worker -SecEditPath $script:StubMissing

        foreach ($exp in $result.Exports) {
            $exp.ExitCode | Should -BeNullOrEmpty
        }
        ($result.Errors -join ' ; ') | Should -Match ([regex]::Escape($script:StubMissing))
    }

    It 'appends a validation-failure error naming the mode when an export is invalid' {
        $result = & $script:Worker -SecEditPath $script:StubEmpty

        $joined = $result.Errors -join ' ; '
        $joined | Should -Match 'export invalid:'
        $joined | Should -Match 'mergedpolicy invalid:'
    }

    It 'resolves every account referenced in [Privilege Rights] for the ok stub, in both directions, sorted ordinal by token' {
        $result = & $script:Worker -SecEditPath $script:OkStub

        $result.Errors.Count | Should -Be 0
        $result.AccountCount | Should -Be 5
        $result.AccountUnresolvedCount | Should -Be 2

        $tokens = @($result.Accounts | Select-Object -ExpandProperty Token)
        $tokens | Should -Be @(
            '*S-1-5-21-1111111111-2222222222-3333333333-1105',
            '*S-1-5-32-544',
            '*S-1-5-32-545',
            'CONTOSO\nosuchuser',
            'Guest'
        )

        $sid544 = $result.Accounts | Where-Object { $_.Token -eq '*S-1-5-32-544' }
        $sid544.Kind | Should -Be 'Sid'
        $sid544.Sid | Should -Be 'S-1-5-32-544'
        $sid544.Status | Should -Be 'Resolved'
        $sid544.Name | Should -Not -BeNullOrEmpty
        $sid544.ReferenceCount | Should -Be 8
        $sid544.References[0] | Should -Be 'export:SeNetworkLogonRight'

        $sid545 = $result.Accounts | Where-Object { $_.Token -eq '*S-1-5-32-545' }
        $sid545.ReferenceCount | Should -Be 2
        @($sid545.References) | Should -Be @('export:SeNetworkLogonRight', 'export:SeInteractiveLogonRight')

        $guest = $result.Accounts | Where-Object { $_.Token -eq 'Guest' }
        $guest.Kind | Should -Be 'Name'
        $guest.Name | Should -Be 'Guest'
        $guest.Sid | Should -Match '-501$'
        $guest.Status | Should -Be 'Resolved'
        $guest.ReferenceCount | Should -Be 2

        $unresolvedSid = $result.Accounts | Where-Object { $_.Token -eq '*S-1-5-21-1111111111-2222222222-3333333333-1105' }
        $unresolvedSid.Status | Should -Be 'NotFound'
        $unresolvedSid.Sid | Should -Be 'S-1-5-21-1111111111-2222222222-3333333333-1105'
        $unresolvedSid.Name | Should -BeNullOrEmpty
        $unresolvedSid.Error | Should -Not -BeNullOrEmpty

        $contoso = $result.Accounts | Where-Object { $_.Token -eq 'CONTOSO\nosuchuser' }
        $contoso.Status | Should -Be 'NotFound'
        $contoso.Sid | Should -BeNullOrEmpty
        $contoso.Error | Should -Not -BeNullOrEmpty
    }

    It 'counts a token referenced by both exports once per referencing line for the merged stub' {
        $result = & $script:Worker -SecEditPath $script:StubMerged

        $sid544 = $result.Accounts | Where-Object { $_.Token -eq '*S-1-5-32-544' }
        @($sid544.References) | Should -Contain 'export:SeNetworkLogonRight'
        @($sid544.References) | Should -Contain 'mergedpolicy:seinteractivelogonright'
        $sid544.ReferenceCount | Should -Be 9

        $sid11 = $result.Accounts | Where-Object { $_.Token -eq '*S-1-5-11' }
        @($sid11.References) | Should -Be @('mergedpolicy:seinteractivelogonright')
        $sid11.Status | Should -Be 'Resolved'
    }

    It 'reports a CIM failure as one Get-CimInstance failed entry, leaves the identity fields null and never calls Get-WmiObject' {
        Mock -ModuleName RemoteSecEdit -CommandName Get-CimInstance -MockWith { throw 'simulated CIM failure' }
        # Get-WmiObject is not present on every PowerShell 7 host, so it is only mocked where it resolves; where it does not, a call to it would show up as a Get-WmiObject entry in Errors.
        $wmiExists = [bool](Get-Command -Name Get-WmiObject -ErrorAction SilentlyContinue)
        if ($wmiExists) {
            Mock -ModuleName RemoteSecEdit -CommandName Get-WmiObject -MockWith { throw 'Get-WmiObject must not be called' }
        }

        $result = & $script:Worker -SecEditPath $script:OkStub

        @($result.Errors) | Should -Contain 'Get-CimInstance failed: simulated CIM failure'
        @($result.Errors) | Should -Contain 'identity: ComputerId: simulated CIM failure'
        ($result.Errors -join ' ; ') | Should -Not -Match 'Get-WmiObject'
        @($result.Errors | Where-Object { $_ -like 'Get-CimInstance failed*' }).Count | Should -Be 1
        $result.OSCaption | Should -BeNull
        $result.OSVersion | Should -BeNull
        $result.DnsHostName | Should -BeNull
        $result.Domain | Should -BeNull
        $result.ComputerId | Should -BeNull
        $result.DomainRole | Should -Be -1
        $result.Exports.Count | Should -Be 2
        if ($wmiExists) {
            Should -Invoke -ModuleName RemoteSecEdit -CommandName Get-WmiObject -Times 0 -Exactly -Scope It
        }
    }

    It 'reads CollectedBy and IsElevated from the one WindowsIdentity of the process, with no collected-by error' {
        $result = & $script:Worker -SecEditPath $script:OkStub

        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        $result.CollectedBy | Should -Be $identity.Name
        $result.IsElevated | Should -Be $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        ($result.Errors -join ' ; ') | Should -Not -Match 'collected-by|elevation check'
    }

    It 'gives an empty Accounts and both counts 0, with no accounts: error, for the 740 stub and for a missing path' {
        foreach ($path in @($script:Stub740, $script:StubMissing)) {
            $result = & $script:Worker -SecEditPath $path

            @($result.Accounts).Count | Should -Be 0
            $result.AccountCount | Should -Be 0
            $result.AccountUnresolvedCount | Should -Be 0
            ($result.Errors -join ' ; ') | Should -Not -Match 'accounts:'
        }
    }

    It 'removes the work folder even when a step after its creation throws outside every per-step try/catch' {
        # Join-Path is mocked for the plain export's inf path only. That call sits in the export loop outside the per-step try/catch blocks, so the throw leaves the worker; every other Join-Path call reaches the real cmdlet.
        $probe = @{ WorkFolder = $null; ExistedAtThrow = $false }
        Mock -ModuleName RemoteSecEdit -CommandName Join-Path -MockWith { Microsoft.PowerShell.Management\Join-Path -Path $Path -ChildPath $ChildPath }
        Mock -ModuleName RemoteSecEdit -CommandName Join-Path -ParameterFilter { $ChildPath -eq 'export.inf' } -MockWith {
            $probe.WorkFolder = $Path
            $probe.ExistedAtThrow = Test-Path -LiteralPath $Path
            throw 'simulated failure in the export step'
        }

        { & $script:Worker -SecEditPath $script:OkStub } | Should -Throw -ExpectedMessage '*simulated failure in the export step*'

        $probe.ExistedAtThrow | Should -BeTrue -Because 'the folder must exist at the moment of the throw, or this test proves nothing'
        (Test-Path -LiteralPath $probe.WorkFolder) | Should -BeFalse
    }

    It 'reports InfSha256 as the lower case SHA-256 Get-FileHash gives for the bytes it returns' {
        $result = & $script:Worker -SecEditPath $script:OkStub

        foreach ($exp in $result.Exports) {
            $file = Join-Path -Path $TestDrive -ChildPath ($exp.Mode + '.inf')
            [System.IO.File]::WriteAllBytes($file, [Convert]::FromBase64String($exp.InfBase64))
            $exp.InfSha256 | Should -BeExactly (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

    It 'reports the known SHA-256 of the two inf files the stub writes, so the worker side is checked against a fixed value and not only against Get-FileHash' {
        # Both digests were computed once with Get-FileHash -Algorithm SHA256 over the file secedit-ok.ps1 writes for /cfg (the plain export, then the /mergedpolicy export), on Windows PowerShell 5.1 and PowerShell 7. The stub's lines are fixed text, so the bytes and digests do not change unless the stub does; then these two values are recomputed the same way.
        $knownDigest = @{
            export       = '7cdfc49465f152e9841133667ba13aa9e22c0d398b50640c887a6eb0bb3b94d9'
            mergedpolicy = '3bfc9069d23b83a74d17298296904cafe1ebca91548c88d4db1d509f34d6ae56'
        }
        $result = & $script:Worker -SecEditPath $script:OkStub

        @($result.Exports).Count | Should -Be 2
        foreach ($exp in $result.Exports) {
            $knownDigest.ContainsKey($exp.Mode) | Should -BeTrue -Because "mode $($exp.Mode) has a known digest"
            $exp.InfSha256 | Should -BeExactly $knownDigest[$exp.Mode]
        }
    }
}

Describe 'Worker scriptblock - the script text' {
    BeforeAll {
        $script:WorkerBlock = & (Get-Module RemoteSecEdit) { Get-SecEditWorker }
    }

    # The name differs from the RemoteFirewall suite's: this worker takes one parameter, -SecEditPath, so the check is that it takes that one and nothing else.
    It 'is a scriptblock whose only parameter is SecEditPath and that switches strict mode off as its first statement' {
        $script:WorkerBlock | Should -BeOfType [scriptblock]
        @($script:WorkerBlock.Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) | Should -Be @('SecEditPath')
        $firstStatement = $script:WorkerBlock.Ast.EndBlock.Statements[0]
        $firstStatement.Extent.Text | Should -Be 'Set-StrictMode -Off'
    }

    It 'calls no module function and uses no using: expression, so it runs on a target that has no module' {
        $definedInside = @($script:WorkerBlock.Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
        $commandNames = @($script:WorkerBlock.Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        $moduleCalls = @($commandNames | Where-Object { $_ -like '*-SecEdit*' -and $_ -notin $definedInside })
        $moduleCalls.Count | Should -Be 0 -Because "called but not defined inside the scriptblock: $($moduleCalls -join ', ')"
        @($script:WorkerBlock.Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.UsingExpressionAst] }, $true)).Count | Should -Be 0
        $definedInside | Should -Contain 'Test-SecEditInfContent'
    }

    It 'never changes anything: it calls no Set-, New-, Remove-, Add- or Clear- cmdlet on the target' {
        $commandNames = @($script:WorkerBlock.Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        $definedInside = @($script:WorkerBlock.Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
        # New-Item and Remove-Item are the only two commands with a changing verb this test allows: the worker creates its own temporary work folder and deletes it again, the one thing it writes on the target. Set-StrictMode and New-Object only touch the worker's own session and an in-memory object, as in the RemoteFirewall test. Any other command with one of these verbs, or Invoke-Expression, fails the test.
        $allowed = @('New-Item', 'Remove-Item', 'Set-StrictMode', 'New-Object')
        $changing = @($commandNames | Where-Object { ($_ -match '^(Set|New|Remove|Add|Clear|Stop|Start|Restart|Disable|Enable|Update|Write)-' -or $_ -eq 'Invoke-Expression') -and $_ -notin $definedInside -and $_ -notin $allowed })
        $changing.Count | Should -Be 0 -Because "changing cmdlets found: $($changing -join ', ')"
    }
}

Describe 'Get-SecEditExport - local name detection' {
    BeforeAll {
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote
    }

    It 'treats <_> as a local target' -ForEach @('.', 'localhost', $env:COMPUTERNAME, $env:COMPUTERNAME.ToLowerInvariant()) {
        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName $_ -OutputPath $outPath)
        $rows.Count | Should -Be 1
        $rows[0].Transport | Should -Be 'Local'
    }

    It 'never calls Invoke-SecEditRemote for local-only requests' {
        # -Scope Describe aggregates over every It in this Describe, including the -ForEach cases above. -Scope It would miss calls made in earlier It blocks and always pass regardless of what happened.
        Should -Invoke -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -Times 0 -Scope Describe
    }
}

Describe 'Get-SecEditExport - local alias folder sharing' {
    It 'runs the worker once for multiple local aliases and points every alias row at the same OutputFolder' {
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName @('.', 'localhost', $env:COMPUTERNAME) -OutputPath $outPath)

        $rows.Count | Should -Be 3
        (@($rows | Select-Object -ExpandProperty OutputFolder -Unique)).Count | Should -Be 1
        foreach ($row in $rows) {
            $row.Transport | Should -Be 'Local'
            $row.OutputFolder | Should -Not -BeNullOrEmpty
        }

        Should -Invoke -ModuleName RemoteSecEdit -CommandName Invoke-SecEditLocal -Exactly -Times 1 -Scope It
    }

    It 'collapses the message of a failed write, a line break and repeated spaces included, to one line in system.json and in the row' {
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }
        # Fails only the summary.json write, with a message that carries a line break, which the target or the disk can produce.
        Mock -ModuleName RemoteSecEdit -CommandName Write-SecEditTextFile -MockWith {
            if ($Path -like '*summary.json') { throw "disk full`r`n  while   writing`n" }
            [System.IO.File]::WriteAllText($Path, $Content)
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName $env:COMPUTERNAME -OutputPath $outPath)

        $rows.Count | Should -Be 1
        $expected = "write summary.json on $($rows[0].ComputerName): disk full while writing"
        @($rows[0].Errors | Where-Object { $_ -like 'write summary.json*' }) | Should -Be @($expected)
        $system = Get-Content -LiteralPath (Join-Path -Path $rows[0].OutputFolder -ChildPath 'system.json') -Raw | ConvertFrom-Json
        @($system.Errors | Where-Object { $_ -like 'write summary.json*' }) | Should -Be @($expected)
    }
    It 'gives every local alias row identical properties, changing only ComputerName, when writing summary.json fails' {
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }
        # Fails only the summary.json write, so the first alias completes with a host-side error that a later alias must carry too.
        Mock -ModuleName RemoteSecEdit -CommandName Write-SecEditTextFile -MockWith {
            if ($Path -like '*summary.json') { throw 'simulated disk failure' }
            [System.IO.File]::WriteAllText($Path, $Content)
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName @('.', 'localhost', $env:COMPUTERNAME) -OutputPath $outPath)

        $rows.Count | Should -Be 3
        $firstRow = $rows[0]
        $firstRow.ErrorCount | Should -Be 1
        $firstRow.Errors[0] | Should -Match 'write summary.json'

        $propertyNames = @($firstRow.PSObject.Properties.Name)
        for ($i = 1; $i -lt $rows.Count; $i++) {
            @($rows[$i].PSObject.Properties.Name) | Should -Be $propertyNames
            $rows[$i].ComputerName | Should -Not -Be $firstRow.ComputerName
            foreach ($propertyName in $propertyNames) {
                if ($propertyName -eq 'ComputerName') { continue }
                (@($rows[$i].$propertyName) -join '|') | Should -Be (@($firstRow.$propertyName) -join '|')
            }
        }

        Should -Invoke -ModuleName RemoteSecEdit -CommandName Invoke-SecEditLocal -Exactly -Times 1 -Scope It
    }
}

Describe 'Resolve-SecEditUniqueFolder - folder collisions' {
    It 'creates a folder without -Force and appends _2, _3 on collision' {
        InModuleScope RemoteSecEdit {
            $base = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))

            $first = Resolve-SecEditUniqueFolder -Path $base
            $second = Resolve-SecEditUniqueFolder -Path $base
            $third = Resolve-SecEditUniqueFolder -Path $base

            $first | Should -Be $base
            $second | Should -Be ($base + '_2')
            $third | Should -Be ($base + '_3')
            (Test-Path -LiteralPath $first) | Should -BeTrue
            (Test-Path -LiteralPath $second) | Should -BeTrue
            (Test-Path -LiteralPath $third) | Should -BeTrue
        }
    }
}

Describe 'Get-SecEditExport - UseSSL' {
    BeforeAll {
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }
    }

    It 'writes a Verbose message when -UseSSL is given for a local target' {
        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $verboseOutput = Get-SecEditExport -ComputerName $env:COMPUTERNAME -OutputPath $outPath -UseSSL -Verbose 4>&1
        $verboseOutput | Where-Object { $_ -match 'UseSSL ignored for local targets' } | Should -Not -BeNullOrEmpty
    }

    It 'calls Invoke-SecEditRemote with UseSSL true and writes run.json with UseSSL true when -UseSSL is given' {
        $reachedName = 'remote8'
        $reportedName = 'REMOTE8'
        $goodWorker = Get-FakeWorkerObject -ComputerName $reportedName -PSComputerNameValue $reachedName
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $null = @($reachedName | Get-SecEditExport -OutputPath $outPath -UseSSL)

        Should -Invoke -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -Exactly -Times 1 -ParameterFilter {
            $UseSSL -eq $true
        }

        $runFolder = @(Get-ChildItem -Path $outPath -Directory -Filter 'RemoteSecEdit-*')[0].FullName
        $runJson = Get-Content -LiteralPath (Join-Path -Path $runFolder -ChildPath 'run.json') -Raw | ConvertFrom-Json
        $runJson.UseSSL | Should -Be $true
    }

    It 'calls Invoke-SecEditRemote with UseSSL false when -UseSSL is not given' {
        $reachedName = 'remote9'
        $reportedName = 'REMOTE9'
        $goodWorker = Get-FakeWorkerObject -ComputerName $reportedName -PSComputerNameValue $reachedName
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $null = @($reachedName | Get-SecEditExport -OutputPath $outPath)

        Should -Invoke -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -Exactly -Times 1 -ParameterFilter {
            $UseSSL -eq $false
        }
    }
}

Describe 'Get-SecEditExport - relative OutputPath' {
    It 'resolves a relative OutputPath against the current location, not the script root' {
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }

        $workDir = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        New-Item -Path $workDir -ItemType Directory -Force | Out-Null

        Push-Location -Path $workDir
        try {
            $rows = @(Get-SecEditExport -ComputerName 'localhost' -OutputPath 'relative-out')
        } finally {
            Pop-Location
        }

        $rows[0].OutputFolder | Should -Not -BeNullOrEmpty
        $expectedRoot = Join-Path -Path $workDir -ChildPath 'relative-out'
        (Test-Path -LiteralPath $expectedRoot) | Should -BeTrue
        $rows[0].OutputFolder | Should -Match ([regex]::Escape($workDir))
    }
}

Describe 'Get-SecEditExport - remote, Invoke-SecEditRemote mocked' {
    It 'builds rows for one successful worker result and one error record, writes files, csv, run.json, and rechecks sha256' {
        $reachedName = 'remote1'
        $unreachedName = 'remote2'
        $reportedName = 'REMOTE1'
        $goodWorker = Get-FakeWorkerObject -ComputerName $reportedName -PSComputerNameValue $reachedName
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new('WinRM cannot complete the operation.'),
            'RemotingError',
            [System.Management.Automation.ErrorCategory]::OperationTimeout,
            $unreachedName
        )

        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @($errorRecord) }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @($reachedName, $unreachedName) | Get-SecEditExport -OutputPath $outPath

        $rows.Count | Should -Be 2

        $row1 = $rows | Where-Object { $_.ComputerName -eq 'remote1' }
        $row1.Status | Should -Be 'Success'
        $row1.Transport | Should -Be 'WinRM'
        $row1.ComputerId | Should -Be $goodWorker.ComputerId
        $row1.OutputFolder | Should -Not -BeNullOrEmpty
        $row1.ExportSettingLines | Should -Be 25
        $row1.MergedPolicySettingLines | Should -Be 0
        $row1.ErrorCount | Should -Be $row1.Errors.Count
        (Test-Path -LiteralPath (Join-Path -Path $row1.OutputFolder -ChildPath 'secedit-export.inf')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path -Path $row1.OutputFolder -ChildPath 'secedit-mergedpolicy.inf')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path -Path $row1.OutputFolder -ChildPath 'system.json')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path -Path $row1.OutputFolder -ChildPath 'summary.json')) | Should -BeTrue
        ($row1.Errors -join ' ; ') | Should -Not -Match 'sha256 mismatch'

        $row2 = $rows | Where-Object { $_.ComputerName -eq 'remote2' }
        $row2.Status | Should -Be 'Failed'
        $row2.ComputerId | Should -BeNull
        $row2.OutputFolder | Should -BeExactly ''
        $row2.Error | Should -Match 'WinRM cannot complete'
        $row2.ErrorCount | Should -Be $row2.Errors.Count
        # Never reached: every module column, including the two booleans, is $null rather than false.
        $row2.ExportValid | Should -BeNullOrEmpty
        $row2.MergedPolicyValid | Should -BeNullOrEmpty
        $row2.ExportExitCode | Should -BeNullOrEmpty
        $row2.AccountCount | Should -BeNullOrEmpty

        $runFolder = @(Get-ChildItem -Path $outPath -Directory -Filter 'RemoteSecEdit-*')
        $runFolder.Count | Should -Be 1
        (Test-Path -LiteralPath (Join-Path -Path $runFolder[0].FullName -ChildPath 'run.json')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path -Path $runFolder[0].FullName -ChildPath 'results.csv')) | Should -BeTrue

        $runJson = Get-Content -LiteralPath (Join-Path -Path $runFolder[0].FullName -ChildPath 'run.json') -Raw | ConvertFrom-Json
        $runJson.RequestedComputers.Count | Should -Be 2
        $runJson.Results.Count | Should -Be 2

        $expectedRunKeys = @('RunId', 'Collector', 'CollectorVersion', 'SchemaVersion', 'HostComputer', 'HostComputerId', 'HostUser', 'PSVersion', 'StartUtc', 'EndUtc', 'RequestedComputers', 'ThrottleLimit', 'UseSSL', 'Results')
        @($runJson.PSObject.Properties.Name) | Should -Be $expectedRunKeys
        $runJson.Collector | Should -Be 'RemoteSecEdit'
        $runJson.SchemaVersion | Should -Be '1.2'
        $runJson.UseSSL | Should -Be $false

        $csvHeaderLine = (Get-Content -LiteralPath (Join-Path -Path $runFolder[0].FullName -ChildPath 'results.csv'))[0]
        $expectedResultsColumns = @('ComputerName', 'ComputerId', 'Status', 'Transport', 'OutputFolder', 'IsElevated', 'ExportExitCode', 'MergedPolicyExitCode', 'ExportValid', 'MergedPolicyValid', 'ExportSettingLines', 'MergedPolicySettingLines', 'AccountCount', 'AccountUnresolvedCount', 'Error', 'ErrorCount')
        $csvHeaderLine | Should -Be (($expectedResultsColumns | ForEach-Object { '"' + $_ + '"' }) -join ',')

        $csv = Import-Csv -LiteralPath (Join-Path -Path $runFolder[0].FullName -ChildPath 'results.csv')
        $csv.Count | Should -Be 2
        ($csv[0].PSObject.Properties.Name) | Should -Not -Contain 'Errors'
        ($csv[0].PSObject.Properties.Name) | Should -Contain 'ExportSettingLines'
        ($csv[0].PSObject.Properties.Name) | Should -Contain 'MergedPolicySettingLines'

        $systemJson = Get-Content -LiteralPath (Join-Path -Path $row1.OutputFolder -ChildPath 'system.json') -Raw | ConvertFrom-Json
        $expectedSystemKeys = @('ComputerName', 'DnsHostName', 'Domain', 'OSCaption', 'OSVersion', 'CurrentBuild', 'UBR', 'DisplayVersion', 'EditionID', 'InstallationType', 'Culture', 'TimeZoneId', 'PSVersion', 'CollectedBy', 'PartOfDomain', 'IsElevated', 'DomainRole', 'CollectedUtc', 'ComputerId', 'MachineGuid', 'Collector', 'CollectorVersion', 'RunId', 'SecEditPath', 'SecEditVersion', 'AccountCount', 'AccountUnresolvedCount', 'AccountsDurationMs', 'Errors', 'Transport', 'RequestedComputerName', 'Status')
        @($systemJson.PSObject.Properties.Name) | Should -Be $expectedSystemKeys
        $systemJson.Collector | Should -Be 'RemoteSecEdit'
        $systemJson.RunId | Should -Be $runJson.RunId

        $summaryJson = Get-Content -LiteralPath (Join-Path -Path $row1.OutputFolder -ChildPath 'summary.json') -Raw | ConvertFrom-Json
        @($summaryJson.PSObject.Properties.Name) | Should -Be @('AccountCount', 'AccountUnresolvedCount', 'AccountUnresolvedTokens', 'AccountsDurationMs', 'Exports')
        @($summaryJson.Exports).Count | Should -Be 2
        @($summaryJson.AccountUnresolvedTokens) | Should -Contain 'CONTOSO\nosuchuser'
        $summaryJson.AccountsDurationMs | Should -Be $goodWorker.AccountsDurationMs

        $accountsCsvHeaderLine = (Get-Content -LiteralPath (Join-Path -Path $row1.OutputFolder -ChildPath 'accounts.csv'))[0]
        $accountsCsvHeaderLine | Should -Be '"Token","Kind","Sid","Name","Status","ReferenceCount","Error"'
    }

    It 'records a Status Success row and MergedPolicySettingLines 0 when the merged export is the workgroup-style empty one' {
        # Coverage at the public-function layer: a valid but empty merged export must not drag Status down when the plain export is fully valid.
        $targetName = 'remote3'
        $reportedName = 'REMOTE3'
        $goodWorker = Get-FakeWorkerObject -ComputerName $reportedName -PSComputerNameValue $targetName -MergedValid $true -MergedSettingLineCount 0

        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName $targetName -OutputPath $outPath)

        $rows[0].Status | Should -Be 'Success'
        $rows[0].MergedPolicySettingLines | Should -Be 0
        $rows[0].ExportSettingLines | Should -Be 25
    }

    It 'records a mismatch error when the recomputed sha256 does not match the target-reported sha256' {
        $targetName = 'remote4'
        $reportedName = 'REMOTE4'
        $badWorker = Get-FakeWorkerObject -ComputerName $reportedName -PSComputerNameValue $targetName
        $badWorker.Exports[0].InfSha256 = 'not-a-real-hash'

        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $badWorker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName $targetName -OutputPath $outPath)

        ($rows[0].Errors -join ' ; ') | Should -Match 'sha256 mismatch'
    }

    It 'gives a Failed row with "no result and no error returned" when a remote name is neither returned nor errored' {
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            [pscustomobject]@{ Errors = @() }
        }

        $targetName = 'remote5'
        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName $targetName -OutputPath $outPath)

        $rows[0].Status | Should -Be 'Failed'
        $rows[0].Error | Should -Match 'no result and no error returned'
    }

    It 'reports Status Partial when only one export is valid' {
        $targetName = 'remote7'
        $reportedName = 'REMOTE7'
        $partialWorker = Get-FakeWorkerObject -ComputerName $reportedName -PSComputerNameValue $targetName -ExportValid $true -MergedValid $false

        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $partialWorker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName $targetName -OutputPath $outPath)

        $rows[0].Status | Should -Be 'Partial'
    }

    It 'reports Status Partial when both exports are valid but the worker reports an error of its own' {
        # Shared output convention: Success also requires the worker's own Errors to be empty, so a row cannot be Success while the worker's Errors is not.
        $targetName = 'remote9'
        $reportedName = 'REMOTE9'
        $workerWithError = Get-FakeWorkerObject -ComputerName $reportedName -PSComputerNameValue $targetName -ExportValid $true -MergedValid $true -WorkerErrors @('culture: some read failure on the target')

        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $workerWithError
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName $targetName -OutputPath $outPath)

        $rows[0].Status | Should -Be 'Partial'
        $rows[0].Error | Should -Be 'culture: some read failure on the target'
        $rows[0].ErrorCount | Should -Be 1
    }

    It 'keeps the row computed from a worker result and appends a same-name error rather than overwriting it' {
        $targetName = 'remote6'
        $reportedName = 'REMOTE6'
        $goodWorker = Get-FakeWorkerObject -ComputerName $reportedName -PSComputerNameValue $targetName
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new('Transient WinRM warning for remote6.'),
            'TransientError',
            [System.Management.Automation.ErrorCategory]::NotSpecified,
            $targetName
        )

        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @($errorRecord) }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName $targetName -OutputPath $outPath)

        $rows.Count | Should -Be 1
        $rows[0].Status | Should -Be 'Success'
        $rows[0].Error | Should -Match 'Transient WinRM warning'
        ($rows[0].Errors -join ' ; ') | Should -Match 'Transient WinRM warning'
    }

    It 'recounts ErrorCount and Error, in the row, run.json and results.csv, when a late remote error is matched to a row a worker result already produced' {
        # Reproduces the reviewer's finding: one worker result plus one ErrorRecord for the same host. The row already exists (built by Complete-SecEditComputer with an empty Errors list) before Get-SecEditExport appends this error onto it, so ErrorCount must be recomputed here rather than left at the value the row was built with.
        $targetName = 'remote8'
        $reportedName = 'REMOTE8'
        $goodWorker = Get-FakeWorkerObject -ComputerName $reportedName -PSComputerNameValue $targetName
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new('Late WinRM error for remote8.'),
            'LateError',
            [System.Management.Automation.ErrorCategory]::NotSpecified,
            $targetName
        )

        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @($errorRecord) }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName $targetName -OutputPath $outPath)

        $rows.Count | Should -Be 1
        $rows[0].Errors.Count | Should -Be 1
        $rows[0].ErrorCount | Should -Be $rows[0].Errors.Count
        $rows[0].Error | Should -Be 'Late WinRM error for remote8.'

        $runFolder = @(Get-ChildItem -Path $outPath -Directory -Filter 'RemoteSecEdit-*')[0].FullName
        $runJson = Get-Content -LiteralPath (Join-Path -Path $runFolder -ChildPath 'run.json') -Raw | ConvertFrom-Json
        $jsonRow = $runJson.Results | Where-Object { $_.ComputerName -eq $targetName }
        $jsonRow.ErrorCount | Should -Be 1
        $jsonRow.Error | Should -Be 'Late WinRM error for remote8.'
        @($jsonRow.Errors).Count | Should -Be 1

        $csv = Import-Csv -LiteralPath (Join-Path -Path $runFolder -ChildPath 'results.csv')
        $csvRow = $csv | Where-Object { $_.ComputerName -eq $targetName }
        [int]$csvRow.ErrorCount | Should -Be 1
        $csvRow.Error | Should -Be 'Late WinRM error for remote8.'
    }

    It 'completes each remote result as it arrives: the folder of the first result is on disk before the callback for the second is invoked' {
        $firstWorker = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue 'remote1'
        $secondWorker = Get-FakeWorkerObject -ComputerName $script:FixtureNameTwo -PSComputerNameValue 'remote2'
        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $seenBeforeSecond = [System.Collections.Generic.List[string]]::new()

        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $firstWorker
            # Everything on disk at the moment the second result is about to be delivered, as folder name plus file name.
            foreach ($file in @(Get-ChildItem -LiteralPath $outPath -Recurse -File -Filter 'system.json')) { $seenBeforeSecond.Add($file.Directory.Name + '\' + $file.Name) }
            foreach ($file in @(Get-ChildItem -LiteralPath $outPath -Recurse -File -Filter 'summary.json')) { $seenBeforeSecond.Add($file.Directory.Name + '\' + $file.Name) }
            & $OnResult $secondWorker
            [pscustomobject]@{ Errors = @() }
        }

        $rows = @(Get-SecEditExport -ComputerName @('remote1', 'remote2') -OutputPath $outPath)

        $rows.Count | Should -Be 2
        @($seenBeforeSecond).Count | Should -Be 2
        foreach ($entry in @($seenBeforeSecond)) { $entry | Should -Match '^REMOTE1_' }
        @($rows | ForEach-Object { $_.Status }) | Should -Be @('Success', 'Success')
        (Test-Path -LiteralPath (Join-Path -Path $rows[1].OutputFolder -ChildPath 'system.json')) | Should -BeTrue
    }

    It 'drops a remote result that matches no requested name with one warning, giving exactly the requested rows and one computer folder' {
        $requestedName = 'remote1'
        $strayName = 'stray-host'
        $requestedWorker = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue $requestedName
        $strayWorker = Get-FakeWorkerObject -ComputerName $script:FixtureNameTwo -PSComputerNameValue $strayName

        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $requestedWorker
            & $OnResult $strayWorker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName $requestedName -OutputPath $outPath -WarningVariable strayWarnings -WarningAction SilentlyContinue)

        $rows.Count | Should -Be 1
        $rows[0].ComputerName | Should -Be $requestedName
        $rows[0].Status | Should -Be 'Success'

        $runFolder = @(Get-ChildItem -Path $outPath -Directory -Filter 'RemoteSecEdit-*')[0].FullName
        @(Get-ChildItem -LiteralPath $runFolder -Directory).Count | Should -Be 1

        @($strayWarnings).Count | Should -Be 1
        [string]$strayWarnings[0] | Should -Be "Unattributed remote result, matched no requested computer name: $strayName"
    }
}

Describe 'Get-SecEditExport - per-computer folder name from the reported name' {
    It 'turns a reported name with path separators and dots into a safe folder name inside the run folder' {
        $targetName = 'remote1'
        $reportedName = '..\..\ESCAPED'
        # Dots, backslashes and letters in the name the target reports: the folder name keeps only letters, digits, underscore and hyphen, so each of the six leading characters becomes an underscore.
        $hostileWorker = Get-FakeWorkerObject -ComputerName $reportedName -PSComputerNameValue $targetName
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $hostileWorker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName $targetName -OutputPath $outPath)

        $runFolder = @(Get-ChildItem -LiteralPath $outPath -Directory -Filter 'RemoteSecEdit-*')[0].FullName
        $rows[0].Status | Should -Be 'Success'
        (Split-Path -Path $rows[0].OutputFolder -Parent) | Should -Be $runFolder
        (Split-Path -Path $rows[0].OutputFolder -Leaf) | Should -Match '^______ESCAPED_20348_\d{8}-\d{6}Z$'
        # Nothing outside the run folder: the output path holds the run folder and nothing else.
        @(Get-ChildItem -LiteralPath $outPath -Force).Count | Should -Be 1

        # The value in the json keeps the reported name as the target gave it.
        $systemJson = Get-Content -LiteralPath (Join-Path -Path $rows[0].OutputFolder -ChildPath 'system.json') -Raw | ConvertFrom-Json
        $systemJson.ComputerName | Should -BeExactly '..\..\ESCAPED'
    }
}

Describe 'Get-SecEditExport - the result callback never throws' {
    It 'reports a computer Failed with a host: error when completing its result throws, and leaves the other computers unaffected' {
        $firstWorker = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue 'remote1'
        $secondWorker = Get-FakeWorkerObject -ComputerName $script:FixtureNameTwo -PSComputerNameValue 'remote2'
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $firstWorker
            & $OnResult $secondWorker
            [pscustomobject]@{ Errors = @() }
        }
        $realComplete = & $script:Module { Get-Command -Name Complete-SecEditComputer }
        # Throws for the first computer only; the default mock below hands every other call to the real function.
        Mock -ModuleName RemoteSecEdit -CommandName Complete-SecEditComputer -MockWith { & $realComplete @PesterBoundParameters }
        Mock -ModuleName RemoteSecEdit -CommandName Complete-SecEditComputer -ParameterFilter { $RequestedComputerName -eq 'remote1' } -MockWith { throw 'simulated host failure' }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName @('remote1', 'remote2') -OutputPath $outPath -WarningAction SilentlyContinue)

        $rows.Count | Should -Be 2
        $rows[0].ComputerName | Should -Be 'remote1'
        $rows[0].Status | Should -Be 'Failed'
        $rows[0].Error | Should -BeExactly 'host: simulated host failure'
        $rows[0].ErrorCount | Should -Be 1
        $rows[1].ComputerName | Should -Be 'remote2'
        $rows[1].Status | Should -Be 'Success'
        $rows[1].ErrorCount | Should -Be 0
        (Test-Path -LiteralPath (Join-Path -Path $rows[1].OutputFolder -ChildPath 'system.json')) | Should -BeTrue
    }

    It 'warns about a remote error that matches no requested computer only as the last step, after run.json and results.csv are written' {
        $requestedName = 'remote1'
        $goodWorker = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue $requestedName
        $script:UnattributedErrorEvents = [System.Collections.Generic.List[string]]::new()
        $script:UnattributedErrorOutPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $goodWorker
            $script:UnattributedErrorEvents.Add('remote call returned')
            # An error record that names no computer, arriving after the requested computer already answered: it cannot be put on a row, so it is reported as a warning, and that warning must not come before the files exist.
            [pscustomobject]@{ Errors = @([System.Management.Automation.ErrorRecord]::new([System.InvalidOperationException]::new('orphan transport error'), 'OrphanError', [System.Management.Automation.ErrorCategory]::NotSpecified, $null)) }
        }
        # Records, at the moment the warning is written, how many of the two run files are on disk: under a caller's -WarningAction Stop the warning ends the call, so both must already be there.
        Mock -ModuleName RemoteSecEdit -CommandName Write-Warning -MockWith {
            $filesOnDisk = @(Get-ChildItem -LiteralPath $script:UnattributedErrorOutPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @('run.json', 'results.csv') })
            $script:UnattributedErrorEvents.Add('warning with ' + $filesOnDisk.Count + ' run files on disk: ' + $Message)
        }

        $rows = @($requestedName | Get-SecEditExport -OutputPath $script:UnattributedErrorOutPath)

        $rows.Count | Should -Be 1
        $rows[0].ComputerName | Should -Be $requestedName
        $rows[0].Status | Should -BeExactly 'Success'
        @($script:UnattributedErrorEvents) | Should -Be @('remote call returned', 'warning with 2 run files on disk: Unattributed remote error, matched no requested computer name: orphan transport error')
    }
    It 'warns about a result that matches no requested name only after run.json and results.csv are written, and creates no row for it' {
        $targetName = 'remote1'
        $strayWorker = Get-FakeWorkerObject -ComputerName $script:FixtureNameTwo -PSComputerNameValue 'stray-host'
        $requestedWorker = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue 'remote1'
        $events = [System.Collections.Generic.List[string]]::new()
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $strayWorker
            & $OnResult $requestedWorker
            $events.Add('remote call returns')
            [pscustomobject]@{ Errors = @() }
        }
        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        # Records, at the moment of each warning, whether the two run files already exist.
        Mock -ModuleName RemoteSecEdit -CommandName Write-Warning -MockWith {
            $runJsonThere = @(Get-ChildItem -LiteralPath $outPath -Recurse -File -Filter 'run.json').Count -eq 1
            $resultsCsvThere = @(Get-ChildItem -LiteralPath $outPath -Recurse -File -Filter 'results.csv').Count -eq 1
            $events.Add("warning: $Message | run.json: $runJsonThere | results.csv: $resultsCsvThere")
        }

        $rows = @(Get-SecEditExport -ComputerName $targetName -OutputPath $outPath)

        $rows.Count | Should -Be 1
        $rows[0].ComputerName | Should -Be 'remote1'
        Should -Invoke -ModuleName RemoteSecEdit -CommandName Write-Warning -Exactly -Times 1 -Scope It
        @($events) | Should -Be @('remote call returns', 'warning: Unattributed remote result, matched no requested computer name: stray-host | run.json: True | results.csv: True')
    }

    It 'still completes the requested computer when the caller runs with -WarningAction Stop and a stray result arrives first' {
        $targetName = 'remote1'
        $strayWorker = Get-FakeWorkerObject -ComputerName $script:FixtureNameTwo -PSComputerNameValue 'stray-host'
        $requestedWorker = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue 'remote1'
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $strayWorker
            & $OnResult $requestedWorker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        # The warning ends the call, as the caller asked, but only after the requested computer's folder was written.
        { Get-SecEditExport -ComputerName $targetName -OutputPath $outPath -WarningAction Stop } | Should -Throw
        $runFolder = @(Get-ChildItem -LiteralPath $outPath -Directory -Filter 'RemoteSecEdit-*')[0].FullName
        @(Get-ChildItem -LiteralPath $runFolder -Directory | Where-Object { $_.Name -like 'REMOTE1_*' }).Count | Should -Be 1
        # The warning comes last, so the run files are on disk too.
        (Test-Path -LiteralPath (Join-Path -Path $runFolder -ChildPath 'run.json')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path -Path $runFolder -ChildPath 'results.csv')) | Should -BeTrue
    }

    It 'sanitises the build number from the target in the folder name' {
        $targetName = 'remote1'
        $worker = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue $targetName
        $worker.CurrentBuild = '..\x 1'
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $worker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName $targetName -OutputPath $outPath)

        $runFolder = @(Get-ChildItem -LiteralPath $outPath -Directory -Filter 'RemoteSecEdit-*')[0].FullName
        (Split-Path -Path $rows[0].OutputFolder -Parent) | Should -Be $runFolder
        (Split-Path -Path $rows[0].OutputFolder -Leaf) | Should -Match '^REMOTE1____x_1_\d{8}-\d{6}Z$'
    }
}

Describe 'Get-SecEditExport - one line per message and per csv cell' {
    It 'writes a late remote error with a line break as one line in the row, run.json and results.csv' {
        $targetName = 'remote1'
        $goodWorker = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue $targetName
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new("Late WinRM error`r`nspread  over lines."),
            'LateError',
            [System.Management.Automation.ErrorCategory]::NotSpecified,
            $targetName
        )
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @($errorRecord) }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName $targetName -OutputPath $outPath -WarningAction SilentlyContinue)

        $rows[0].Error | Should -BeExactly 'Late WinRM error spread over lines.'
        $rows[0].Errors[0] | Should -BeExactly 'Late WinRM error spread over lines.'
        $rows[0].ErrorCount | Should -Be 1

        $runFolder = Split-Path -Path $rows[0].OutputFolder -Parent
        $runJson = Get-Content -LiteralPath (Join-Path -Path $runFolder -ChildPath 'run.json') -Raw | ConvertFrom-Json
        @($runJson.Results)[0].Error | Should -BeExactly 'Late WinRM error spread over lines.'
        $csv = @(Import-Csv -LiteralPath (Join-Path -Path $runFolder -ChildPath 'results.csv'))
        $csv[0].Error | Should -BeExactly 'Late WinRM error spread over lines.'
    }
}

Describe 'ConvertTo-SecEditResultRow - one line per message' {
    It 'collapses an Errors entry with an embedded line break to one line in both Error and Errors' {
        $row = InModuleScope RemoteSecEdit {
            ConvertTo-SecEditResultRow -ComputerName $env:COMPUTERNAME -Status 'Failed' -Transport 'WinRM' -Errors @("Connecting to remote server failed`r`n  with the following error`nmessage ", 'second')
        }

        $row.Error | Should -BeExactly 'Connecting to remote server failed with the following error message'
        $row.Errors[0] | Should -BeExactly 'Connecting to remote server failed with the following error message'
        $row.Errors[1] | Should -BeExactly 'second'
        $row.ErrorCount | Should -Be 2
    }

    It 'returns Errors as a string array on every path, empty or not' {
        $rows = InModuleScope RemoteSecEdit {
            @(
                (ConvertTo-SecEditResultRow -ComputerName $env:COMPUTERNAME -Status 'Failed' -Transport 'WinRM' -Errors @()),
                (ConvertTo-SecEditResultRow -ComputerName $env:COMPUTERNAME -Status 'Failed' -Transport 'WinRM' -Errors @('one'))
            )
        }

        ($rows[0].Errors -is [string[]]) | Should -BeTrue
        @($rows[0].Errors).Count | Should -Be 0
        ($rows[1].Errors -is [string[]]) | Should -BeTrue
    }
}

Describe 'Get-SecEditExport - json files carry no byte order mark' {
    It 'writes every .json file of a completed run folder without EF BB BF' {
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName 'localhost' -OutputPath $outPath)

        $runFolder = Split-Path -Path $rows[0].OutputFolder -Parent
        $jsonFiles = @(Get-ChildItem -LiteralPath $runFolder -Recurse -File -Filter '*.json')
        # run.json plus system.json, summary.json and accounts.json of the one computer.
        $jsonFiles.Count | Should -BeGreaterOrEqual 4
        foreach ($jsonFile in $jsonFiles) {
            $bytes = [System.IO.File]::ReadAllBytes($jsonFile.FullName)
            -not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeTrue -Because "$($jsonFile.Name) must not start with a byte order mark"
        }
    }
}

Describe 'Complete-SecEditComputer - SHA-256 recomputed over the written inf' {
    It 'gives the known lower case SHA-256 of a fixed byte array as InfSha256Disk and records no mismatch' {
        # The SHA-256 of the three ASCII bytes abc is a published test vector; Get-FileHash over a temp file with the same bytes must agree with it.
        $bytes = [System.Text.Encoding]::ASCII.GetBytes('abc')
        $knownHash = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
        $file = Join-Path -Path $TestDrive -ChildPath 'abc.bin'
        [System.IO.File]::WriteAllBytes($file, $bytes)
        (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() | Should -BeExactly $knownHash

        $workerObject = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue 'remote1'
        $workerObject.Exports[0].InfBase64 = [Convert]::ToBase64String($bytes)
        $workerObject.Exports[0].InfSha256 = $knownHash
        $runFolder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        New-Item -Path $runFolder -ItemType Directory -Force | Out-Null

        $row = InModuleScope RemoteSecEdit -Parameters @{ Worker = $workerObject; RunFolder = $runFolder } {
            param($Worker, $RunFolder)
            Complete-SecEditComputer -RequestedComputerName 'remote1' -Transport 'WinRM' -RunFolder $RunFolder -WorkerObject $Worker -ExtraErrors @()
        }

        $summary = Get-Content -LiteralPath (Join-Path -Path $row.OutputFolder -ChildPath 'summary.json') -Raw | ConvertFrom-Json
        @($summary.Exports)[0].InfSha256Disk | Should -BeExactly $knownHash
        ($row.Errors -join ' ; ') | Should -Not -Match 'sha256'
    }
}

Describe 'Complete-SecEditComputer - empty entries in the worker Errors' {
    It 'drops an empty entry from the worker Errors and returns a row whose Errors and ErrorCount count only the real one' {
        $workerObject = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue 'remote1' -WorkerErrors @('real error', '')
        $runFolder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        New-Item -Path $runFolder -ItemType Directory -Force | Out-Null

        # Complete-SecEditComputer is private, so it is reached inside the module by name.
        $row = InModuleScope RemoteSecEdit -Parameters @{ Worker = $workerObject; RunFolder = $runFolder } {
            param($Worker, $RunFolder)
            Complete-SecEditComputer -RequestedComputerName 'remote1' -Transport 'WinRM' -RunFolder $RunFolder -WorkerObject $Worker -ExtraErrors @()
        }

        $row | Should -Not -BeNullOrEmpty
        @($row.Errors) | Should -Be @('real error')
        $row.ErrorCount | Should -Be 1
        $row.Error | Should -Be 'real error'
    }

    It 'lets ConvertTo-SecEditResultRow take an empty string inside Errors without throwing' {
        {
            InModuleScope RemoteSecEdit {
                ConvertTo-SecEditResultRow -ComputerName $env:COMPUTERNAME -Status 'Failed' -Transport 'WinRM' -Errors @('a', '')
            }
        } | Should -Not -Throw
    }
}

Describe 'Complete-SecEditComputer - system.json from a fixed property list' {
    BeforeAll {
        $script:ExpectedSystemKeys = @('ComputerName', 'DnsHostName', 'Domain', 'OSCaption', 'OSVersion', 'CurrentBuild', 'UBR',
            'DisplayVersion', 'EditionID', 'InstallationType', 'Culture', 'TimeZoneId', 'PSVersion', 'CollectedBy',
            'PartOfDomain', 'IsElevated', 'DomainRole', 'CollectedUtc', 'ComputerId', 'MachineGuid',
            'Collector', 'CollectorVersion', 'RunId',
            'SecEditPath', 'SecEditVersion', 'AccountCount', 'AccountUnresolvedCount', 'AccountsDurationMs',
            'Errors', 'Transport', 'RequestedComputerName', 'Status')

        function Get-SecEditSystemKeyName {
            param($WorkerObject)
            $runFolder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
            New-Item -Path $runFolder -ItemType Directory -Force | Out-Null
            $row = InModuleScope RemoteSecEdit -Parameters @{ Worker = $WorkerObject; RunFolder = $runFolder } {
                param($Worker, $RunFolder)
                Complete-SecEditComputer -RequestedComputerName 'remote1' -Transport 'WinRM' -RunFolder $RunFolder -WorkerObject $Worker -ExtraErrors @()
            }
            $systemContent = Get-Content -LiteralPath (Join-Path -Path $row.OutputFolder -ChildPath 'system.json') -Raw | ConvertFrom-Json
            return @($systemContent.PSObject.Properties.Name)
        }
    }

    It 'writes the documented key order for a normal worker object, without the remoting properties' {
        $workerObject = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue 'remote1'
        $workerObject | Add-Member -MemberType NoteProperty -Name 'RunspaceId' -Value ([guid]::NewGuid())
        $workerObject | Add-Member -MemberType NoteProperty -Name 'PSShowComputerName' -Value $true

        Get-SecEditSystemKeyName -WorkerObject $workerObject | Should -Be $script:ExpectedSystemKeys
    }

    It 'writes the same key order when the worker object properties arrive in a different order' {
        $workerObject = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue 'remote1'
        $shuffled = [ordered]@{}
        foreach ($property in @($workerObject.PSObject.Properties | Sort-Object -Property Name -Descending)) { $shuffled[$property.Name] = $property.Value }

        Get-SecEditSystemKeyName -WorkerObject ([pscustomobject]$shuffled) | Should -Be $script:ExpectedSystemKeys
    }

    It 'still writes Collector, CollectorVersion and RunId when the worker object has no MachineGuid' {
        $workerObject = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue 'remote1' | Select-Object -Property * -ExcludeProperty MachineGuid

        $keys = Get-SecEditSystemKeyName -WorkerObject $workerObject
        $keys | Should -Contain 'Collector'
        $keys | Should -Contain 'CollectorVersion'
        $keys | Should -Contain 'RunId'
        $keys | Should -Be $script:ExpectedSystemKeys
    }

    It 'includes every worker object property except Exports and Accounts in system.json' {
        $workerObject = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue 'remote1'

        $keys = Get-SecEditSystemKeyName -WorkerObject $workerObject
        # Exports and Accounts go to their own files, PSComputerName is remoting bookkeeping added by Invoke-Command.
        $workerPropertyNames = @($workerObject.PSObject.Properties.Name | Where-Object { $_ -notin @('Exports', 'Accounts', 'PSComputerName') })

        foreach ($name in $workerPropertyNames) {
            $keys | Should -Contain $name -Because "a future worker property named '$name' must not silently drop out of the fixed system.json property list"
        }
    }
}

Describe 'Get-SecEditExport - accounts' {
    It 'writes accounts.json and accounts.csv, carries AccountCount and AccountUnresolvedCount on the row, and leaves Status computed from the exports alone' {
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName 'localhost' -OutputPath $outPath)

        $rows.Count | Should -Be 1
        # The fixture's second account (CONTOSO\nosuchuser) is NotFound, and that never changes Status.
        $rows[0].Status | Should -Be 'Success'
        $rows[0].AccountCount | Should -Be 2
        $rows[0].AccountUnresolvedCount | Should -Be 1

        $folder = $rows[0].OutputFolder
        (Test-Path -LiteralPath (Join-Path $folder 'accounts.json')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $folder 'accounts.csv')) | Should -BeTrue

        $accountsCsv = @(Import-Csv -LiteralPath (Join-Path $folder 'accounts.csv'))
        $expectedAccountColumns = @('Token', 'Kind', 'Sid', 'Name', 'Status', 'ReferenceCount', 'Error')
        @($accountsCsv[0].PSObject.Properties.Name) | Should -Be $expectedAccountColumns
        $accountsCsv.Count | Should -Be 2
        ($accountsCsv | Where-Object { $_.Token -eq 'CONTOSO\nosuchuser' }).Status | Should -Be 'NotFound'

        $accountsJsonRaw = Get-Content -LiteralPath (Join-Path $folder 'accounts.json') -Raw
        $accountsJsonRaw.TrimStart()[0] | Should -Be '['
        # Assigned first and wrapped after: Windows PowerShell 5.1 emits a json array from ConvertFrom-Json as one pipeline object, so @() around the pipeline would count 1.
        $accountsJsonObject = ConvertFrom-Json -InputObject $accountsJsonRaw
        $accountsJson = @($accountsJsonObject)
        $accountsJson.Count | Should -Be 2
        @($accountsJson[0].References).Count | Should -Be 2
        # The second fixture account has one reference, so this pins that a single-element References list is still written as a json array.
        ($accountsJson[1].References -is [array]) | Should -BeTrue

        $runFolder = Split-Path -Path $folder -Parent
        $resultsCsv = @(Import-Csv -LiteralPath (Join-Path $runFolder 'results.csv'))
        @($resultsCsv[0].PSObject.Properties.Name) | Should -Contain 'AccountCount'
        @($resultsCsv[0].PSObject.Properties.Name) | Should -Contain 'AccountUnresolvedCount'
        @($resultsCsv[0].PSObject.Properties.Name) | Should -Not -Contain 'Errors'

        foreach ($csvPath in @((Join-Path $runFolder 'results.csv'), (Join-Path $folder 'accounts.csv'))) {
            $bytes = [System.IO.File]::ReadAllBytes($csvPath)
            $bytes[0] | Should -Be 0xEF
            $bytes[1] | Should -Be 0xBB
            $bytes[2] | Should -Be 0xBF
        }
    }

    It 'gives AccountCount $null, a header-only accounts.csv and an empty accounts.json array for a worker object with no Accounts and no count properties' {
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME | Select-Object -Property * -ExcludeProperty Accounts, AccountCount, AccountUnresolvedCount, AccountsDurationMs
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName 'localhost' -OutputPath $outPath)

        $rows[0].AccountCount | Should -BeNull
        $rows[0].AccountUnresolvedCount | Should -BeNull
        $rows[0].Status | Should -Be 'Success'
        ($rows[0].Errors -join ' ; ') | Should -Not -Match 'accounts'

        $folder = $rows[0].OutputFolder
        $accountsCsvLines = @(Get-Content -LiteralPath (Join-Path $folder 'accounts.csv'))
        $accountsCsvLines.Count | Should -Be 1
        $accountsCsvLines[0] | Should -Be '"Token","Kind","Sid","Name","Status","ReferenceCount","Error"'

        (Get-Content -LiteralPath (Join-Path $folder 'accounts.json') -Raw) | Should -Match '^\s*\[\s*\]\s*$'

        $summaryJson = Get-Content -LiteralPath (Join-Path $folder 'summary.json') -Raw | ConvertFrom-Json
        $summaryJson.AccountCount | Should -BeNullOrEmpty
        $summaryJson.AccountUnresolvedCount | Should -BeNullOrEmpty
        @($summaryJson.AccountUnresolvedTokens).Count | Should -Be 0
        $summaryJson.AccountsDurationMs | Should -BeNullOrEmpty
        @($summaryJson.Exports).Count | Should -Be 2
    }
}

Describe 'CollectorVersion in run.json and system.json' {
    BeforeAll {
        $script:ManifestVersion = (Test-ModuleManifest -Path $script:ManifestPath).Version.ToString()
    }

    It 'writes the manifest ModuleVersion as CollectorVersion in run.json and system.json for a local target' {
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName 'localhost' -OutputPath $outPath)

        $runFolder = Split-Path -Path $rows[0].OutputFolder -Parent
        $runJson = Get-Content -LiteralPath (Join-Path -Path $runFolder -ChildPath 'run.json') -Raw | ConvertFrom-Json
        $systemJson = Get-Content -LiteralPath (Join-Path -Path $rows[0].OutputFolder -ChildPath 'system.json') -Raw | ConvertFrom-Json

        $runJson.CollectorVersion | Should -Be $script:ManifestVersion
        $systemJson.CollectorVersion | Should -Be $script:ManifestVersion
    }

    It 'writes the manifest ModuleVersion as CollectorVersion in run.json and system.json for a remote target completed inside the streaming callback' {
        $targetName = 'remote1'
        $remoteWorker = Get-FakeWorkerObject -ComputerName $script:FixtureNameOne -PSComputerNameValue $targetName
        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditRemote -MockWith {
            & $OnResult $remoteWorker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-SecEditExport -ComputerName $targetName -OutputPath $outPath)

        $runFolder = Split-Path -Path $rows[0].OutputFolder -Parent
        $runJson = Get-Content -LiteralPath (Join-Path -Path $runFolder -ChildPath 'run.json') -Raw | ConvertFrom-Json
        $systemJson = Get-Content -LiteralPath (Join-Path -Path $rows[0].OutputFolder -ChildPath 'system.json') -Raw | ConvertFrom-Json

        $runJson.CollectorVersion | Should -Be $script:ManifestVersion
        $systemJson.CollectorVersion | Should -Be $script:ManifestVersion
    }
}

Describe 'Get-SecEditHostComputerId' {
    It 'returns the upper-case UUID from a CIM read' {
        Mock -ModuleName RemoteSecEdit -CommandName Get-CimInstance -MockWith { [pscustomobject]@{ UUID = ' abcdef01-2345-6789-abcd-ef0123456789 ' } }

        $id = InModuleScope RemoteSecEdit { Get-SecEditHostComputerId }

        $id | Should -Be 'ABCDEF01-2345-6789-ABCD-EF0123456789'
    }

    It 'returns null without throwing and without calling Get-WmiObject when the CIM read throws' {
        Mock -ModuleName RemoteSecEdit -CommandName Get-CimInstance -MockWith { throw 'simulated CIM failure' }
        $wmiExists = [bool](Get-Command -Name Get-WmiObject -ErrorAction SilentlyContinue)
        if ($wmiExists) {
            Mock -ModuleName RemoteSecEdit -CommandName Get-WmiObject -MockWith { [pscustomobject]@{ UUID = 'from-wmi' } }
        }

        $id = InModuleScope RemoteSecEdit { Get-SecEditHostComputerId }

        $id | Should -BeNull
        if ($wmiExists) {
            Should -Invoke -ModuleName RemoteSecEdit -CommandName Get-WmiObject -Times 0 -Exactly -Scope It
        }
    }
}

Describe 'Write-SecEditCsvFile' {
    It 'writes a header-only file with the byte order mark when Row is empty and Column is supplied' {
        InModuleScope RemoteSecEdit {
            $path = Join-Path -Path $TestDrive -ChildPath 'header-only.csv'
            Write-SecEditCsvFile -Row @() -Path $path -Column @('Token', 'Kind', 'Sid')

            $lines = @(Get-Content -LiteralPath $path)
            $lines.Count | Should -Be 1
            $lines[0] | Should -Be '"Token","Kind","Sid"'

            $bytes = [System.IO.File]::ReadAllBytes($path)
            $bytes[0] | Should -Be 0xEF
            $bytes[1] | Should -Be 0xBB
            $bytes[2] | Should -Be 0xBF
        }
    }

    It 'writes the rows when Row is not empty' {
        InModuleScope RemoteSecEdit {
            $path = Join-Path -Path $TestDrive -ChildPath 'rows.csv'
            $rows = @(
                [pscustomobject]@{ Token = 'Guest'; Kind = 'Name' },
                [pscustomobject]@{ Token = '*S-1-5-32-544'; Kind = 'Sid' }
            )
            Write-SecEditCsvFile -Row $rows -Path $path -Column @('Token', 'Kind')

            $lines = @(Get-Content -LiteralPath $path)
            $lines.Count | Should -Be 3
            $lines[1] | Should -Be '"Guest","Name"'
            $lines[2] | Should -Be '"*S-1-5-32-544","Sid"'
        }
    }

    It 'writes the file literally under a folder whose name contains brackets' {
        InModuleScope RemoteSecEdit {
            $bracketFolder = Join-Path -Path $TestDrive -ChildPath 'a[1]'
            New-Item -Path $bracketFolder -ItemType Directory -Force | Out-Null
            $path = Join-Path -Path $bracketFolder -ChildPath 'rows.csv'

            Write-SecEditCsvFile -Row @([pscustomobject]@{ Token = 'Guest' }) -Path $path -Column @('Token')

            (Test-Path -LiteralPath $path) | Should -BeTrue
        }
    }

    It 'writes a string with a line break and repeated spaces as one line, leaves a null bare, an empty string as "" and an int unchanged' {
        InModuleScope RemoteSecEdit {
            $path = Join-Path -Path $TestDrive -ChildPath 'one-line.csv'
            $source = [pscustomobject]@{ Text = "a`r`nb  c"; Nothing = $null; Empty = ''; Count = 7 }
            Write-SecEditCsvFile -Row @($source) -Path $path -Column @('Text', 'Nothing', 'Empty', 'Count')

            $lines = @(Get-Content -LiteralPath $path)
            $lines.Count | Should -Be 2
            $lines[0] | Should -Be '"Text","Nothing","Empty","Count"'
            $lines[1] | Should -Be '"a b c",,"","7"'
            # The caller's object keeps the source form: the same rows go to run.json.
            $source.Text | Should -Be "a`r`nb  c"
        }
    }

    It 'writes a row that needs no change exactly as it is and leaves the caller''s objects untouched' {
        InModuleScope RemoteSecEdit {
            $path = Join-Path -Path $TestDrive -ChildPath 'pass-through.csv'
            $plain = [pscustomobject]@{ Text = 'plain text'; Nothing = $null; Empty = ''; Count = 7; Flag = $true }
            $changed = [pscustomobject]@{ Text = "a`r`nb"; Nothing = $null; Empty = ''; Count = 8; Flag = $false }
            Write-SecEditCsvFile -Row @($plain, $changed) -Path $path

            $lines = [System.IO.File]::ReadAllLines($path)
            $lines.Count | Should -Be 3
            $lines[0] | Should -BeExactly '"Text","Nothing","Empty","Count","Flag"'
            # The row with nothing to change comes out as its own values: null bare, empty string quoted, the int and the bool as they are.
            $lines[1] | Should -BeExactly '"plain text",,"","7","True"'
            $lines[2] | Should -BeExactly '"a b",,"","8","False"'
            # Neither the passed-through object nor the rebuilt one is modified: property order, values and types stay as the caller made them.
            ($plain.PSObject.Properties.Name -join ',') | Should -BeExactly 'Text,Nothing,Empty,Count,Flag'
            $plain.Text | Should -BeExactly 'plain text'
            $plain.Nothing | Should -BeNull
            $plain.Empty | Should -BeExactly ''
            $plain.Count | Should -BeOfType [int]
            $plain.Flag | Should -BeOfType [bool]
            $changed.Text | Should -BeExactly "a`r`nb"
        }
    }

    It 'skips a null row and writes the header and exactly one data row' {
        InModuleScope RemoteSecEdit {
            $path = Join-Path -Path $TestDrive -ChildPath 'null-row.csv'
            # -ErrorAction Stop matches the public function, whose callers run at Stop: ConvertTo-Csv reports a null pipeline element as an error, which only ends the call when the error action is Stop.
            Write-SecEditCsvFile -Row @([pscustomobject]@{ A = 1; B = 'x' }, $null) -Path $path -Column @('A', 'B') -ErrorAction Stop

            $lines = @(Get-Content -LiteralPath $path)
            $lines.Count | Should -Be 2
            $lines[0] | Should -Be '"A","B"'
            $lines[1] | Should -Be '"1","x"'
        }
    }

    It 'writes a UTF-8 byte order mark before the header' {
        InModuleScope RemoteSecEdit {
            $path = Join-Path -Path $TestDrive -ChildPath 'bom.csv'
            Write-SecEditCsvFile -Row @([pscustomobject]@{ A = 1 }) -Path $path -Column @('A')

            $bytes = [System.IO.File]::ReadAllBytes($path)
            $bytes[0] | Should -Be 0xEF
            $bytes[1] | Should -Be 0xBB
            $bytes[2] | Should -Be 0xBF
            # The first character after the mark is the opening quote of the header, not a second mark.
            $bytes[3] | Should -Be 0x22
        }
    }

    It 'writes a header-only file when the only row is null' {
        InModuleScope RemoteSecEdit {
            $path = Join-Path -Path $TestDrive -ChildPath 'null-only.csv'
            Write-SecEditCsvFile -Row @($null) -Path $path -Column @('A', 'B') -ErrorAction Stop

            $lines = @(Get-Content -LiteralPath $path)
            $lines.Count | Should -Be 1
            $lines[0] | Should -Be '"A","B"'
        }
    }

    It 'takes the header from the rows, not from -Column, when there are rows' {
        InModuleScope RemoteSecEdit {
            $path = Join-Path -Path $TestDrive -ChildPath 'rows-win.csv'
            Write-SecEditCsvFile -Row @([pscustomobject]@{ X = 1 }) -Path $path -Column @('A', 'B')

            $lines = @(Get-Content -LiteralPath $path)
            $lines.Count | Should -Be 2
            $lines[0] | Should -Be '"X"'
        }
    }
}

Describe 'Write-SecEditTextFile' {
    It 'writes UTF-8 without a byte order mark' {
        InModuleScope RemoteSecEdit {
            $path = Join-Path -Path $TestDrive -ChildPath 'text.json'
            Write-SecEditTextFile -Path $path -Content '{"a":1}'

            $bytes = [System.IO.File]::ReadAllBytes($path)
            $bytes.Count | Should -Be 7
            $bytes[0] | Should -Be 0x7B
        }
    }

    It 'encodes a non-ASCII character as UTF-8' {
        InModuleScope RemoteSecEdit {
            $path = Join-Path -Path $TestDrive -ChildPath 'utf8.json'
            # Built from a code point, so this file stays ASCII: U+00E6 is C3 A6 in UTF-8.
            Write-SecEditTextFile -Path $path -Content ([string][char]0x00E6)

            $bytes = [System.IO.File]::ReadAllBytes($path)
            $bytes.Count | Should -Be 2
            $bytes[0] | Should -Be 0xC3
            $bytes[1] | Should -Be 0xA6
        }
    }

    It 'writes an empty file for an empty string' {
        InModuleScope RemoteSecEdit {
            $path = Join-Path -Path $TestDrive -ChildPath 'empty.json'
            Write-SecEditTextFile -Path $path -Content ''

            (Test-Path -LiteralPath $path) | Should -BeTrue
            [System.IO.File]::ReadAllBytes($path).Count | Should -Be 0
        }
    }
}

Describe 'Resolve-SecEditComputerList' {
    It 'trims names, drops blanks and case-insensitive duplicates, and keeps the first-seen order and spelling' {
        $names = & $script:Module { param($list) Resolve-SecEditComputerList -ComputerName $list } @(' Alpha ', '', 'beta', 'ALPHA', '   ', 'Beta', 'gamma')

        ((@($names)) -join '|') | Should -BeExactly 'Alpha|beta|gamma'
    }

    It 'returns nothing for a list of blanks' {
        $names = & $script:Module { param($list) Resolve-SecEditComputerList -ComputerName $list } @('', '  ')

        @($names).Count | Should -Be 0
    }
}

Describe 'Initialize-SecEditRunFolder' {
    It 'creates a missing OutputPath and a RemoteSecEdit run folder named with a UTC stamp under it, and leaves nothing in it' {
        $root = Join-Path -Path $TestDrive -ChildPath 'newroot\deeper'
        $runFolder = & $script:Module { param($path) Initialize-SecEditRunFolder -OutputPath $path } $root

        (Test-Path -LiteralPath $runFolder) | Should -BeTrue
        (Split-Path -Path $runFolder -Parent) | Should -Be $root
        (Split-Path -Path $runFolder -Leaf) | Should -Match '^RemoteSecEdit-\d{8}-\d{6}Z(_\d+)?$'
        @(Get-ChildItem -LiteralPath $runFolder -Force).Count | Should -Be 0
    }

    It 'gives two calls in the same second two different folders' {
        $root = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $first = & $script:Module { param($path) Initialize-SecEditRunFolder -OutputPath $path } $root
        $second = & $script:Module { param($path) Initialize-SecEditRunFolder -OutputPath $path } $root

        $second | Should -Not -Be $first
        (Test-Path -LiteralPath $first) | Should -BeTrue
        (Test-Path -LiteralPath $second) | Should -BeTrue
    }

    It 'throws OutputPath is not writable when the run folder cannot be written to' {
        $missing = Join-Path -Path $TestDrive -ChildPath 'never-created\run'
        Mock -ModuleName RemoteSecEdit -CommandName Resolve-SecEditUniqueFolder -MockWith { $missing }
        $root = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))

        { & $script:Module { param($path) Initialize-SecEditRunFolder -OutputPath $path } $root } | Should -Throw -ExpectedMessage '*OutputPath is not writable*'
    }
}

Describe 'Get-SecEditSafeProperty' {
    It 'returns the default for a null object and for a property the object does not have, and the value otherwise, under strict mode' {
        $script:Probe = [pscustomobject]@{ Present = 0; Flag = $false; Nothing = $null }
        $results = & $script:Module {
            param($probe)
            Set-StrictMode -Version Latest
            [pscustomobject]@{
                NullObject = Get-SecEditSafeProperty -InputObject $null -Name 'Present' -Default 'fallback'
                Absent     = Get-SecEditSafeProperty -InputObject $probe -Name 'Missing' -Default 'fallback'
                Zero       = Get-SecEditSafeProperty -InputObject $probe -Name 'Present' -Default 'fallback'
                False      = Get-SecEditSafeProperty -InputObject $probe -Name 'Flag' -Default 'fallback'
                Null       = Get-SecEditSafeProperty -InputObject $probe -Name 'Nothing' -Default 'fallback'
                NoDefault  = Get-SecEditSafeProperty -InputObject $probe -Name 'Missing'
            }
        } $script:Probe

        $results.NullObject | Should -BeExactly 'fallback'
        $results.Absent | Should -BeExactly 'fallback'
        $results.Zero | Should -Be 0
        $results.Zero | Should -BeOfType [int]
        $results.False | Should -BeFalse
        ($null -eq $results.Null) | Should -BeTrue -Because 'a property that is present with a null value is not absent'
        ($null -eq $results.NoDefault) | Should -BeTrue
    }
}

Describe 'Resolve-SecEditRemoteErrorName' {
    BeforeAll {
        function Get-MatchedName {
            param($ErrorRecord, [string[]]$RemoteNames)
            & $script:Module { param($record, $names) Resolve-SecEditRemoteErrorName -ErrorRecord $record -RemoteNames $names } $ErrorRecord $RemoteNames
        }
    }

    It 'matches the TargetObject to a requested name ignoring letter case' {
        $record = [pscustomobject]@{ TargetObject = 'SRV01' }
        Get-MatchedName -ErrorRecord $record -RemoteNames @('srv02', 'srv01') | Should -BeExactly 'srv01'
    }

    It 'matches the host of a uri TargetObject' {
        $record = [pscustomobject]@{ TargetObject = [uri]'http://srv03.corp.example:5985/wsman' }
        Get-MatchedName -ErrorRecord $record -RemoteNames @('srv03.corp.example', 'srv04') | Should -BeExactly 'srv03.corp.example'
    }

    It 'falls back to the PSComputerName of the origin info when the TargetObject names nobody' {
        $record = [pscustomobject]@{ TargetObject = $null; OriginInfo = [pscustomobject]@{ PSComputerName = 'srv05' } }
        Get-MatchedName -ErrorRecord $record -RemoteNames @('srv05') | Should -BeExactly 'srv05'
    }

    It 'retries once with the domain suffix of the candidate stripped' {
        $record = [pscustomobject]@{ TargetObject = 'srv06.corp.example' }
        Get-MatchedName -ErrorRecord $record -RemoteNames @('srv06') | Should -BeExactly 'srv06'
    }

    It 'returns nothing when no requested name matches' {
        $record = [pscustomobject]@{ TargetObject = 'stranger' }
        Get-MatchedName -ErrorRecord $record -RemoteNames @('srv07') | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-SecEditRemote - credential forwarding and OnResult streaming' {
    It 'does not bind -Credential on Invoke-Command when none is supplied' {
        InModuleScope RemoteSecEdit {
            # A -ParameterFilter sees the bound parameters as $PesterBoundParameters ($PSBoundParameters is empty there in Pester 6.1.0), so this checks whether -Credential was bound at all.
            Mock Invoke-Command -MockWith { return @() } -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('Credential')
            }
            # An unfiltered catch-all, registered after the specific mock above, so any call that does not match the filter fails loudly here instead of silently reaching the real Invoke-Command.
            Mock Invoke-Command -MockWith { throw 'real Invoke-Command must never be reached in a test' }

            $null = Invoke-SecEditRemote -ComputerName @('remote1') -ThrottleLimit 4 -OnResult {}

            Should -Invoke Invoke-Command -Exactly -Times 1 -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('Credential')
            }
        }
    }

    It 'passes -Credential through to Invoke-Command when supplied' {
        InModuleScope RemoteSecEdit {
            # Built without ConvertTo-SecureString -AsPlainText: a synthetic, throwaway credential used only to prove Invoke-SecEditRemote forwards -Credential, never to authenticate anything.
            $securePassword = New-Object System.Security.SecureString
            foreach ($ch in 'x'.ToCharArray()) { $securePassword.AppendChar($ch) }
            $securePassword.MakeReadOnly()
            $credential = New-Object System.Management.Automation.PSCredential('someuser', $securePassword)

            Mock Invoke-Command -MockWith { return @() } -ParameterFilter {
                $null -ne $Credential -and $Credential.UserName -eq 'someuser'
            }

            $null = Invoke-SecEditRemote -ComputerName @('remote1') -Credential $credential -ThrottleLimit 4 -OnResult {}

            Should -Invoke Invoke-Command -Exactly -Times 1 -ParameterFilter {
                $null -ne $Credential -and $Credential.UserName -eq 'someuser'
            }
        }
    }

    It 'invokes -OnResult once per object the Invoke-Command mock emits' {
        InModuleScope RemoteSecEdit {
            $emitted = @(
                [pscustomobject]@{ PSComputerName = 'remoteA' },
                [pscustomobject]@{ PSComputerName = 'remoteB' },
                [pscustomobject]@{ PSComputerName = 'remoteC' }
            )

            Mock Invoke-Command -MockWith { return $emitted }

            $script:onResultCallCount = 0
            $onResult = { $script:onResultCallCount++ }

            $null = Invoke-SecEditRemote -ComputerName @('remoteA', 'remoteB', 'remoteC') -ThrottleLimit 4 -OnResult $onResult

            $script:onResultCallCount | Should -Be 3
        }
    }
}

Describe 'Invoke-SecEditRemote - UseSSL forwarding' {
    It 'does not bind -UseSSL on Invoke-Command when it is not supplied' {
        InModuleScope RemoteSecEdit {
            Mock Invoke-Command -MockWith { return @() } -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('UseSSL')
            }
            # An unfiltered catch-all, registered after the specific mock above, so any call that does not match the filter fails loudly here instead of silently reaching the real Invoke-Command.
            Mock Invoke-Command -MockWith { throw 'real Invoke-Command must never be reached in a test' }

            $null = Invoke-SecEditRemote -ComputerName @('remote1') -ThrottleLimit 4 -OnResult {}

            Should -Invoke Invoke-Command -Exactly -Times 1 -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('UseSSL')
            }
        }
    }

    It 'passes -UseSSL through to Invoke-Command when supplied' {
        InModuleScope RemoteSecEdit {
            Mock Invoke-Command -MockWith { return @() } -ParameterFilter {
                $UseSSL -eq $true
            }

            $null = Invoke-SecEditRemote -ComputerName @('remote1') -ThrottleLimit 4 -OnResult {} -UseSSL

            Should -Invoke Invoke-Command -Exactly -Times 1 -ParameterFilter {
                $UseSSL -eq $true
            }
        }
    }
}

Describe 'Get-SecEditExport - parameter validation' {
    It 'throws when ComputerName is empty after removing blanks and duplicates' {
        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        { Get-SecEditExport -ComputerName @('', '   ') -OutputPath $outPath } | Should -Throw
    }

    It 'throws when OutputPath cannot be created or written' {
        $blockerFile = Join-Path -Path $TestDrive -ChildPath 'blocker.txt'
        Set-Content -LiteralPath $blockerFile -Value 'x'
        $badOutputPath = Join-Path -Path $blockerFile -ChildPath 'child'

        Mock -ModuleName RemoteSecEdit -CommandName Invoke-SecEditLocal

        { Get-SecEditExport -ComputerName 'localhost' -OutputPath $badOutputPath } | Should -Throw
    }
}

Describe 'Manifest' {
    BeforeAll {
        $script:ManifestData = Test-ModuleManifest -Path $script:ManifestPath
    }

    It 'passes Test-ModuleManifest' {
        { Test-ModuleManifest -Path $script:ManifestPath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'exports exactly the public function set' {
        @($script:ManifestData.ExportedFunctions.Keys) | Should -Be @('Get-SecEditExport')
    }

    It 'has a FileList without a Get-SecEditCollectorVersion entry and no such function in the module' {
        @($script:ManifestData.FileList) | Should -Not -Contain (Join-Path -Path (Split-Path -Path $script:ManifestPath -Parent) -ChildPath 'src\ps1\Get-SecEditCollectorVersion.ps1')
        & (Get-Module RemoteSecEdit) { Get-Command -Name Get-SecEditCollectorVersion -ErrorAction SilentlyContinue } | Should -BeNull
    }

    It 'declares no RequiredModules' {
        $script:ManifestData.RequiredModules.Count | Should -Be 0
    }

    It 'has Author Tom Stryhn' {
        $script:ManifestData.Author | Should -Be 'Tom Stryhn'
    }

    It 'has a matching .VERSION in every src\ps1 file and every tests file that carries a PSScriptInfo header' {
        $moduleVersion = $script:ManifestData.Version.ToString()
        $srcPath = Join-Path -Path $script:RepoRoot -ChildPath 'RemoteSecEdit\src\ps1'
        $candidateFiles = @(Get-ChildItem -Path $srcPath -Filter '*.ps1') + @(Get-ChildItem -Path $PSScriptRoot -Recurse -Filter '*.ps1')

        $scriptInfoFiles = @($candidateFiles | Where-Object {
            (Get-Content -LiteralPath $_.FullName -Raw) -match '<#PSScriptInfo'
        })

        # Every src\ps1 file and every tests file (root plus stubs) carries a PSScriptInfo header, so this count also catches a header silently dropped from a new file.
        $scriptInfoFiles.Count | Should -Be $candidateFiles.Count

        foreach ($file in $scriptInfoFiles) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            $content | Should -Match ([regex]::Escape(".VERSION $moduleVersion"))
        }
    }

    It 'has a FileList that matches the module folder on disk in both directions' {
        # Test-ModuleManifest resolves FileList to full paths, so both sides are compared as full paths here.
        $moduleFolder = Split-Path -Path $script:ManifestPath -Parent
        $diskFiles = @(Get-ChildItem -Path $moduleFolder -File -Recurse | Select-Object -ExpandProperty FullName)
        $fileListPaths = @($script:ManifestData.FileList)

        foreach ($path in $diskFiles) {
            $fileListPaths | Should -Contain $path
        }
        foreach ($path in $fileListPaths) {
            $diskFiles | Should -Contain $path
        }
    }
}
