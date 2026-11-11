# ProxyBridge

[Русский](README.md) | **English**

A Windows application that routes connections through an HTTP CONNECT or SOCKS5
proxy, with exceptions for applications, IP addresses and subnets. It uses
sing-box, a Wintun virtual adapter, and its own Windows Filtering Platform
(WFP) module.

Version: **0.5.00**. Requires
Windows 10/11 x64 and administrator privileges to run.

## Features

- TCP routing through a proxy configured by the user.
- Application exceptions identified by their full EXE paths, allowing direct access.
- IP/CIDR exceptions with an optional port, such as `192.168.1.0/24` or
  `192.168.1.10:8080`. Direct TCP/UDP to these destinations is permitted for
  all applications except DNS port 53. Address exceptions do not enable stopped DNS.
- A kill switch with separate actions for stopping while blocking traffic and restoring internet access.
- Stop and disconnect remain available while connecting; queued commands run
  in order before the next automatic retry.
- Startup at Windows sign-in, a system tray icon, and a speed test.
- Local connection and activity logs, with TCP and WFP diagnostics.
- A dark interface with Overview, Proxy, Exceptions, and Help pages.

No proxy addresses, usernames, or passwords are bundled with the application.
The first launch opens the configuration page and does not connect until a
profile is configured. The proxy endpoint must be an IPv4 address, not a domain
name. SOCKS5 is used for TCP; unsupported UDP is intended to remain blocked.

## First launch

The application currently uses Russian interface labels. Their English meanings
are included below to help you find the controls.

1. Build the application as described below and run `ProxyBridge-0.5.00.exe`.
2. On «Прокси» (Proxy), enter the address, port, protocol, and credentials if required.
3. Click «Сохранить / применить» (Save / apply), then «Подключить» (Connect).
4. Wait for a successful connection check on «Обзор» (Overview).
5. If needed, add EXE files or addresses under «Исключения» (Exceptions) and apply the changes.

Once a valid profile has been saved, subsequent normal launches automatically
attempt to connect. Closing the window hides it in the system tray without a
popup. «Остановить и блокировать» (Stop and block) keeps protection enabled;
«Отключить и вернуть интернет» (Disconnect and restore internet) removes the
application's own blocking policy. Exiting with the kill switch preserved also
leaves blocking enabled. If the application is closed, `Recover-Internet.cmd`
requests explicit recovery through a UAC prompt.

“Stop and block” and “Disconnect and restore internet” remain available while
connecting. A clicked command waits for the current operation to finish and
runs before the next automatic retry. Commands follow click order, and a log
message confirms when a command is queued. Once stopping or disconnecting
has run, automatic reconnection stops.
The current attempt and its required cleanup finish before the command runs;
the network operation is not interrupted immediately. Tray commands use the
same queue. After a successful disconnect, a stale engine failure notification
cannot enable blocking again.

Exceptions intentionally allow direct access, including while the proxy is
stopped. When manually stopping with application exceptions configured, system
DNS access to the active adapters' resolvers may also be allowed. See
[HELP.txt](HELP.txt) for details (Russian).

## Address and subnet exceptions

Open «Исключения» (Exceptions) → «Добавить адрес…» (Add address), enter an
IP address or subnet and an optional port. Click «Добавить» (Add), then
«Сохранить / применить» (Save / apply). Specify the port either in the address
entry or in the separate port field.

| Entry | Direct access |
| --- | --- |
| `192.168.1.0/24` | Subnet `192.168.1.0–192.168.1.255`, all ports except 53 |
| `192.168.1.10` | One IP address, all ports except 53 |
| `192.168.1.10:8080` | One IP address, port 8080 only |
| `192.168.1.0/24:443` | Subnet, port 443 only |
| `[fd00::10]:8080` | IPv6 address, port 8080 only |
| `[fd00::/64]:443` | IPv6 subnet, port 443 only |

Address rules allow outbound TCP/UDP connections for all applications,
including while the proxy is stopped and the kill switch remains enabled.
Other destinations retain their existing policy. These rules do not permit
ICMP, such as ping. DNS port 53 is excluded from address exceptions; an explicit
`:53` is rejected. Domain names and URLs are not supported.

Up to 64 address rules can be saved separately from EXE exceptions. Subnets
are normalized: `192.168.1.42/24` becomes `192.168.1.0/24`; duplicate entries
are removed. New profiles have no address exceptions. Older profiles retain
their existing settings and load with an empty address list.

## Network protection status

The project is under development. Leak testing is not complete for crashes,
existing connections, IPv6, DNS/UDP, or combinations with third-party VPNs and
antivirus software. A successful build or HTTPS check does not verify all of
these scenarios. A connection failure must not automatically disable protection.

## Build from source

You need Windows x64, .NET SDK 10, Visual Studio Build Tools with Desktop
development with C++ and the Windows SDK, and PowerShell 5.1 or later. Git is
required for cloning; internet access is required to download dependencies and
NuGet packages.

```powershell
git clone git@github.com:Igor-gmc/Proxy_with_exceptions.git
cd Proxy_with_exceptions
powershell -NoProfile -ExecutionPolicy Bypass -File tools/Restore-Dependencies.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1
```

The dependency restoration script downloads pinned sing-box and Wintun archives
from their official sources and verifies SHA-256 checksums before extraction.
The build compiles the native module, packages an explicit list of components,
and produces a single EXE containing the .NET runtime. Proxy profiles and
environment files are not included in the package. `build.ps1 -BuildOnly`
keeps the release output in `release/` without copying it to the project root.

The main EXE and recovery script are placed in the project root; versioned copies
and SHA-256 checksums are stored in `release/versions/`. Binaries, dependencies,
and intermediate files are excluded from Git. The release version is defined
in [Version.props](Version.props).

## Tests

```powershell
dotnet run --project tests/Core.Tests -c Release
dotnet run --project tests/Settings.Tests -c Release
dotnet run --project tests/Logging.Tests -c Release
dotnet run --project tests/Diagnostics.Tests -c Release
```

Run these after building the application so that its resource package exists.
These checks use synthetic data and do not start a live tunnel. Other checks
and their limitations are documented in [tests/README.md](tests/README.md)
(Russian). Integration checks can change network state; they live in a
[separate test harness](integration/README.md) (Russian) and are not run by the build.

Test scenarios are not compiled into the user-facing EXE. For bundle, self, and
UI checks, build the separate host with
`powershell -File build.ps1 -BuildOnly -IncludeTests`. The `--self-test`,
`--ui-test`, and `--bundle-test` commands are accepted only by that host.
The application EXE rejects them before starting the application. Its user-facing
modes are a normal launch without arguments, `--startup`, or `--recover`;
unknown arguments and mixed modes are also rejected.

## Data and privacy

Settings are stored locally using Windows DPAPI; logs are kept in
`%LOCALAPPDATA%\ProxyBridge`. Components are extracted to the protected
`%ProgramFiles%\ProxyBridgeComponents` directory. Logs may contain network
addresses and application paths, so sanitize them before attaching them to
public issues.

No `.env` file is required. The repository excludes environment files, keys,
VPN profiles, saved settings, logs, and local investigation artifacts. Before
committing, run `python tools/check-publication.py --staged` and review the
changes. See [SECURITY.md](SECURITY.md) for details (Russian).

## Project structure

| Directory | Purpose |
| --- | --- |
| `ProxyBridge/` | WinForms interface, settings, engine management, and diagnostics |
| `native/` | Native WFP module |
| `tests/` | Automated checks and an isolated UI renderer |
| `integration/` | Manual network test harness |
| `tools/` | Dependency restoration and supporting tools |
| `licenses/` | Third-party notices and licenses |

Open `ProxyBridge.slnx` to work with all projects. Module boundaries, the order
of protection operations, and testing contracts are described in
[ARCHITECTURE.md](ARCHITECTURE.md) (Russian). C# formatting is defined by
`.editorconfig`.

See [CHANGELOG.md](CHANGELOG.md) for version history and
[THIRD-PARTY.txt](THIRD-PARTY.txt) for third-party components and their licenses
(both in Russian). This README does not replace dependency license terms or
grant a separate license to the project code.
