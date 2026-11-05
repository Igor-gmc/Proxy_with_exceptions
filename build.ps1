param([switch]$BuildOnly)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Set-Location -LiteralPath $root
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -prerelease -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vs) { throw 'Install Visual Studio C++ build tools and Windows SDK.' }
New-Item -ItemType Directory -Force dist, artifacts | Out-Null
$bat = "@echo off`r`ncall `"$vs\VC\Auxiliary\Build\vcvars64.bat`"`r`ncl /nologo /LD /MT /EHsc /std:c++17 /W4 /O2 native\guard.cpp /Fo:artifacts\guard.obj /link /OUT:dist\ProxyGuard.dll /IMPLIB:artifacts\ProxyGuard.lib`r`n"
[IO.File]::WriteAllText((Join-Path $root 'artifacts\native-build.cmd'), $bat)
& cmd.exe /c artifacts\native-build.cmd
if ($LASTEXITCODE) { throw 'Native build failed' }
$payload = Join-Path $root ('artifacts\payload-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force (Join-Path $payload 'core') | Out-Null
Copy-Item dist\ProxyGuard.dll $payload
Copy-Item vendor\sing-box-1.14.4-windows-amd64\sing-box.exe (Join-Path $payload 'core')
Copy-Item vendor\wintun\bin\amd64\wintun.dll (Join-Path $payload 'core')
Copy-Item README.txt, HELP.txt, THIRD-PARTY.txt, CHANGELOG.md $payload
Copy-Item vendor\wintun\LICENSE.txt (Join-Path $payload 'core\WINTUN-LICENSE.txt')
Copy-Item vendor\SING-BOX-LICENSE.txt (Join-Path $payload 'core')
Copy-Item vendor\TRACEEVENT-LICENSE.txt, vendor\DOTNET-LICENSE.txt (Join-Path $payload 'core')
Compress-Archive -Path (Join-Path $payload '*') -DestinationPath artifacts\payload.zip -Force
dotnet publish ProxyBridge\ProxyBridge.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o release
if ($LASTEXITCODE) { throw 'Managed build failed' }
$publishedExe = Join-Path $root 'release\ProxyBridge.exe'
$publishedVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($publishedExe).ProductVersion
if ($publishedVersion -notmatch '^\d+\.\d+\.\d{2,}$') { throw 'Published EXE has an invalid product version' }
$versionedName = 'ProxyBridge-' + $publishedVersion + '.exe'
$releaseVersionedExe = Join-Path $root ('release\' + $versionedName)
Move-Item -LiteralPath $publishedExe -Destination $releaseVersionedExe -Force
$versionDirectory = Join-Path $root 'release\versions'
New-Item -ItemType Directory -Force -Path $versionDirectory | Out-Null
$versionedExe = Join-Path $versionDirectory $versionedName
Copy-Item -LiteralPath $releaseVersionedExe -Destination $versionedExe -Force
$releaseHash = (Get-FileHash -LiteralPath $versionedExe -Algorithm SHA256).Hash
[IO.File]::WriteAllText(($versionedExe + '.sha256'), ($releaseHash + '  ' + [IO.Path]::GetFileName($versionedExe) + "`r`n"), [Text.UTF8Encoding]::new($false))
Write-Host ('Built ProxyBridge ' + $publishedVersion + ' SHA256 ' + $releaseHash)
$releaseRecovery = Join-Path $root 'release\Recover-Internet.cmd'
$recoveryText = '@echo off' + "`r`n" + 'start "" "%~dp0' + $versionedName + '" --recover' + "`r`n"
[IO.File]::WriteAllText($releaseRecovery, $recoveryText, [Text.Encoding]::ASCII)
if (-not $BuildOnly) {
    Copy-Item -LiteralPath $releaseVersionedExe -Destination (Join-Path $root $versionedName) -Force
    Copy-Item -LiteralPath $releaseRecovery -Destination (Join-Path $root 'Recover-Internet.cmd') -Force
}
