[CmdletBinding()]
param(
    [string]$Executable,
    [string]$OutputDirectory,
    [ValidateRange(30, 900)][int]$TimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$scriptDirectory = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptDirectory)) { $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path }
if ([string]::IsNullOrEmpty($Executable)) {
    $Executable = Join-Path $scriptDirectory '..\artifacts\test-host\ProxyBridge.TestHost.exe'
}
if ([string]::IsNullOrEmpty($OutputDirectory)) { $OutputDirectory = Join-Path $scriptDirectory '..\artifacts\automated-tests' }
$runId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$runDirectory = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) $runId
New-Item -ItemType Directory -Path $runDirectory | Out-Null
$summaryPath = Join-Path $runDirectory 'summary.json'
$summary = [ordered]@{
    schemaVersion = 1; runId = $runId; startedUtc = [DateTime]::UtcNow.ToString('o')
    finishedUtc = $null; status = 'FAIL'; executable = $null; sha256 = $null
    testHost = 'ProxyBridge.TestHost'; tests = @(); error = $null
    limitations = @('No live network or TUN startup', 'No task registration or actual Windows logon', 'No real throughput measurement', 'No crash, IPv6, DNS or UDP isolation proof')
}
$lock = $null
$lockOwned = $false
$exitCode = 1
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell. The runner does not request UAC automatically.'
    }
    $lock = New-Object Threading.Mutex($false, 'Global\ProxyBridge-AutomatedTests')
    try { $lockOwned = $lock.WaitOne(0) } catch [Threading.AbandonedMutexException] { $lockOwned = $true }
    if (-not $lockOwned) { throw 'Another ProxyBridge test runner is active.' }
    $appMutex = $null
    if ([Threading.Mutex]::TryOpenExisting('Global\ProxyBridge-8CBA1041', [ref]$appMutex)) {
        $appMutex.Dispose()
        throw 'ProxyBridge is already active. Close it yourself before running tests; the runner never stops another session.'
    }
    $source = (Resolve-Path -LiteralPath $Executable).Path
    if ([IO.Path]::GetFileName($source) -ine 'ProxyBridge.TestHost.exe') { throw 'Executable must be the separately published ProxyBridge.TestHost.exe; run build.ps1 -IncludeTests.' }
    $summary.executable = $source
    $summary.sha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $binaryDirectory = Join-Path $runDirectory 'bin'
    New-Item -ItemType Directory -Path $binaryDirectory | Out-Null
    $testExecutable = Join-Path $binaryDirectory 'ProxyBridge.TestHost.exe'
    Copy-Item -LiteralPath $source -Destination $testExecutable
    if ((Get-FileHash -LiteralPath $testExecutable -Algorithm SHA256).Hash -ne $summary.sha256) { throw 'Copied EXE checksum differs.' }
    $steps = @(
        @{ Name = 'bundle'; Arguments = '--bundle-test'; Report = 'bundle-test.txt'; MinimumPass = 1 },
        @{ Name = 'self'; Arguments = '--self-test'; Report = 'self-test.txt'; MinimumPass = 52 },
        @{ Name = 'ui'; Arguments = '--ui-test'; Report = 'ui-test.txt'; MinimumPass = 1 },
        @{ Name = 'startup-ui'; Arguments = '--ui-test --startup'; Report = 'ui-test.txt'; MinimumPass = 1 }
    )
    $abortRemaining = $false
    foreach ($step in $steps) {
        $entry = [ordered]@{ name = $step.Name; status = 'FAIL'; exitCode = $null; durationSeconds = 0; report = $null; checks = @(); error = $null }
        if ($abortRemaining) {
            $entry.status = 'SKIP'; $entry.error = 'Previous child timed out; remaining processes are not started.'
            $summary.tests += $entry
            continue
        }
        $caseDirectory = Join-Path $runDirectory $step.Name
        New-Item -ItemType Directory -Path $caseDirectory | Out-Null
        $reportPath = Join-Path $binaryDirectory $step.Report
        $child = $null
        $watch = [Diagnostics.Stopwatch]::StartNew()
        try {
            if (Test-Path -LiteralPath $reportPath) { throw 'Unexpected report before launch; stale reports are never accepted.' }
            $launchUtc = [DateTime]::UtcNow
            $info = New-Object Diagnostics.ProcessStartInfo
            $info.FileName = $testExecutable
            $info.Arguments = $step.Arguments
            $info.WorkingDirectory = $binaryDirectory
            $info.UseShellExecute = $false
            $info.CreateNoWindow = $true
            # WinForms UI checks intentionally display their own window briefly.
            # The explicit test host owns diagnostics; the shipping entry point is never used.
            $child = [Diagnostics.Process]::Start($info)
            if (-not $child.WaitForExit($TimeoutSeconds * 1000)) {
                $abortRemaining = $true
                # This captured Process handle belongs only to the child we started.
                if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit() }
                throw 'Owned test child exceeded its timeout and was stopped.'
            }
            $entry.exitCode = $child.ExitCode
            if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) { throw 'Test produced no report.' }
            $report = Get-Item -LiteralPath $reportPath
            if ($report.Length -eq 0 -or $report.LastWriteTimeUtc -lt $launchUtc.AddSeconds(-2)) { throw 'Empty or stale report rejected.' }
            $lines = @(Get-Content -LiteralPath $reportPath -Encoding UTF8 | Where-Object { $_.Trim().Length -gt 0 })
            foreach ($line in $lines) {
                if ($line -notmatch '^(PASS|FAIL|SKIP):\s*(.+)$') { throw 'Report contains an unrecognized result line.' }
                $entry.checks += [ordered]@{ status = $Matches[1]; name = $Matches[2] }
            }
            $destination = Join-Path $caseDirectory $step.Report
            Move-Item -LiteralPath $reportPath -Destination $destination
            $entry.report = $destination
            if ($step.Name -in @('ui', 'startup-ui')) {
                $manifestPath = Join-Path $binaryDirectory 'ui-captures.json'
                if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'UI capture manifest is missing.' }
                $manifestFile = Get-Item -LiteralPath $manifestPath
                if ($manifestFile.Length -eq 0 -or $manifestFile.LastWriteTimeUtc -lt $launchUtc.AddSeconds(-2)) { throw 'Empty or stale UI capture manifest rejected.' }
                $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($manifest.schemaVersion -ne 1 -or @($manifest.captures).Count -lt 20) { throw 'UI capture manifest has an unsupported schema or insufficient frames.' }
                $captureNames = @($manifest.captures | ForEach-Object {
                    if ($_.file -isnot [string] -or $_.file -cnotmatch '^ui-[A-Za-z0-9_-]+\.png$') { throw 'Invalid capture filename in UI manifest.' }
                    $_.file
                })
                if (@($captureNames | Sort-Object -Unique).Count -ne $captureNames.Count) { throw 'Duplicate UI capture filenames rejected.' }
                $requiredStages = @('ui-monitor-before.png', 'ui-monitor-during.png', 'ui-monitor-after.png',
                    'ui-command-before.png', 'ui-command-cancel-pending.png', 'ui-command-executing.png',
                    'ui-command-queued.png', 'ui-command-second-executing.png', 'ui-command-after.png',
                    'ui-failure-before.png', 'ui-failure-during.png', 'ui-failure-after.png', 'ui-followup-after.png')
                foreach ($requiredStage in $requiredStages) {
                    if ($captureNames -notcontains $requiredStage) { throw "Required UI capture stage is absent: $requiredStage" }
                }
                $actualCaptures = @(Get-ChildItem -LiteralPath $binaryDirectory -Filter 'ui-*.png' -File)
                if ($actualCaptures.Count -ne $captureNames.Count -or @($actualCaptures | Where-Object { $captureNames -notcontains $_.Name }).Count -ne 0) {
                    throw 'UI manifest and screenshot files disagree.'
                }
                foreach ($previewName in @('ui-preview.png', 'ui-overview.png', 'ui-proxy.png', 'ui-exclusions.png', 'ui-help.png', 'ui-minimum.png')) {
                    $previewPath = Join-Path $binaryDirectory $previewName
                    if (-not (Test-Path -LiteralPath $previewPath -PathType Leaf)) { throw "UI test produced no $previewName; rebuild the current suite." }
                    $preview = Get-Item -LiteralPath $previewPath
                    if ($preview.Length -eq 0 -or $preview.LastWriteTimeUtc -lt $launchUtc.AddSeconds(-2)) { throw "Empty or stale $previewName rejected." }
                }
                foreach ($preview in @(Get-ChildItem -LiteralPath $binaryDirectory -Filter 'ui-*.png' -File)) {
                    if ($preview.Length -eq 0 -or $preview.LastWriteTimeUtc -lt $launchUtc.AddSeconds(-2)) { throw "Empty or stale $($preview.Name) rejected." }
                    Move-Item -LiteralPath $preview.FullName -Destination (Join-Path $caseDirectory $preview.Name)
                }
                Move-Item -LiteralPath $manifestPath -Destination (Join-Path $caseDirectory 'ui-captures.json')
                foreach ($letter in @('D', 'P', 'S')) {
                    $iconPath = Join-Path $binaryDirectory ('icon-' + $letter + '.png')
                    if (-not (Test-Path -LiteralPath $iconPath -PathType Leaf)) { throw "UI test produced no $letter icon preview; rebuild the current suite." }
                    $icon = Get-Item -LiteralPath $iconPath
                    if ($icon.Length -eq 0 -or $icon.LastWriteTimeUtc -lt $launchUtc.AddSeconds(-2)) { throw "Empty or stale $letter icon preview rejected." }
                    Move-Item -LiteralPath $iconPath -Destination (Join-Path $caseDirectory $icon.Name)
                }
            }
            if ($entry.exitCode -ne 0) { throw "Test process exited with code $($entry.exitCode)." }
            if (@($entry.checks | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { throw 'Report contains failed checks.' }
            if (@($entry.checks | Where-Object { $_.status -eq 'PASS' }).Count -lt $step.MinimumPass) { throw 'Report has insufficient passing checks; rebuild the current test suite.' }
            $entry.status = 'PASS'
        } catch {
            $entry.error = $_.Exception.Message
        } finally {
            $watch.Stop(); $entry.durationSeconds = [Math]::Round($watch.Elapsed.TotalSeconds, 3)
            if ($null -ne $child) { $child.Dispose() }
        }
        $summary.tests += $entry
        Write-Host ($entry.status + ': ' + $entry.name + $(if ($entry.error) { ' - ' + $entry.error } else { '' }))
    }
    if (@($summary.tests | Where-Object { $_.status -ne 'PASS' }).Count -eq 0) { $summary.status = 'PASS'; $exitCode = 0 }
} catch {
    $summary.error = $_.Exception.Message
    Write-Host ('FAIL: ' + $summary.error)
} finally {
    $summary.finishedUtc = [DateTime]::UtcNow.ToString('o')
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
    if ($lockOwned) { $lock.ReleaseMutex() }
    if ($null -ne $lock) { $lock.Dispose() }
    Write-Host ('Report: ' + $summaryPath)
}
exit $exitCode
