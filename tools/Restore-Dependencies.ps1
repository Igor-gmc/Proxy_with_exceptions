[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$vendorDirectory = Join-Path $projectRoot 'vendor'
New-Item -ItemType Directory -Force -Path $vendorDirectory | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$packages = @(
    @{
        Name = 'sing-box'; File = 'sing-box.zip'
        Url = 'https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-windows-amd64.zip'
        Sha256 = '99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df'
    },
    @{
        Name = 'Wintun'; File = 'wintun.zip'
        Url = 'https://www.wintun.net/builds/wintun-0.14.1.zip'
        Sha256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
    }
)

foreach ($package in $packages) {
    $archivePath = Join-Path $vendorDirectory $package.File
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        $downloadPath = $archivePath + '.download'
        Invoke-WebRequest -Uri $package.Url -OutFile $downloadPath -UseBasicParsing
        if ((Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256).Hash -ine $package.Sha256) {
            throw ('Checksum mismatch: ' + $package.Name + '. Download was not extracted.')
        }
        Move-Item -LiteralPath $downloadPath -Destination $archivePath -Force
    }
    if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -ine $package.Sha256) {
        throw ('Checksum mismatch: ' + $package.Name + '. Archive was not extracted.')
    }
    Expand-Archive -LiteralPath $archivePath -DestinationPath $vendorDirectory -Force
    Write-Host ($package.Name + ': SHA256 verified and extracted.')
}

foreach ($licenseName in @('SING-BOX-LICENSE.txt', 'TRACEEVENT-LICENSE.txt', 'DOTNET-LICENSE.txt')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot ('licenses\' + $licenseName)) -Destination $vendorDirectory -Force
}
Write-Host 'Dependencies are ready. Run build.ps1 to build ProxyBridge.'
