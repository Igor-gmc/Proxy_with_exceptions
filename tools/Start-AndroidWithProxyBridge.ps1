[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9_.-]+$')]
    [string]$Avd = 'Pixel_7_API_36'
)

$ErrorActionPreference = 'Stop'

# DNS is selected by the emulator at process startup. LAN/loopback DNS can
# be blocked by strict_route even when the emulator EXEs are excluded.
# This helper changes no Windows routes, filters, DNS settings or Android
# proxy settings. Connect ProxyBridge before using it.
try {
    $sdkRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Android\Sdk'
    $emulatorPath = Join-Path $sdkRoot 'emulator\emulator.exe'
    if (-not (Test-Path -LiteralPath $emulatorPath -PathType Leaf)) {
        throw "Android Emulator was not found: $emulatorPath"
    }

    $tun = @(Get-NetIPInterface -InterfaceAlias 'ProxyBridge-TUN' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object ConnectionState -eq 'Connected')
    if ($tun.Count -ne 1) {
        throw 'Connect ProxyBridge first. Its IPv4 TUN is not ready.'
    }
    $dnsServers = @(Get-DnsClientServerAddress -InterfaceIndex $tun[0].InterfaceIndex -AddressFamily IPv4 |
        ForEach-Object { $_.ServerAddresses })
    if ($dnsServers -notcontains '172.29.231.2') {
        throw 'The expected ProxyBridge TUN DNS address is unavailable.'
    }

    $running = @(Get-Process -Name 'emulator', 'qemu-system-x86_64', 'qemu-system-aarch64' -ErrorAction SilentlyContinue)
    if ($running.Count -gt 0) {
        throw 'An Android emulator is already running. Close it normally, then run this launcher again.'
    }
    $availableAvds = @(& $emulatorPath -list-avds)
    if ($LASTEXITCODE -ne 0 -or $availableAvds -notcontains $Avd) {
        throw "AVD '$Avd' was not found. Available AVDs: $($availableAvds -join ', ')"
    }

    # A cold boot avoids restoring a snapshot with stale network state.
    # User data is preserved; -wipe-data is deliberately not used.
    Start-Process -FilePath $emulatorPath -ArgumentList @('-avd', $Avd, '-dns-server', '172.29.231.2', '-no-snapshot-load') | Out-Null
    Write-Host "Starting $Avd with ProxyBridge TUN DNS (172.29.231.2)."
} catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 1
}
