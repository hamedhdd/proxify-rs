# proxify-rs

`proxify-rs` is a lightweight, user-mode application proxy manager for Windows written in Rust. It functions similarly to Proxifier or Linux's `proxychains`, allowing you to route network traffic of specific Windows applications through SOCKS5 proxies based on granular target rules (IP addresses, subnets, ports, or domains)—**completely without administrator privileges, kernel drivers (WFP/Wintun), or PowerShell commands**.

---

## Key Features

- **Interactive Native GUI (`proxify-ui`)**: Clean desktop interface built in Rust (with egui) to visually manage proxied apps, configure IP/domain routing rules, inspect live running processes, and test proxy connectivity with 1 click.
- **Zero Administrator Privileges**: Intercepts applications in user-mode using standard Win32 process spawning and memory injection. No UAC prompts, no driver signing, and no kernel extensions required.
- **No PowerShell Dependency**: Runs as standalone native binaries (`proxify-ui.exe` and `proxify.exe`) interacting directly with the Windows API (`CreateProcessW`, `LoadLibraryW`, Winsock2).
- **Rule-Based Routing**:
  - Direct vs. Proxy rules based on target IPv4 addresses, wildcard prefixes (e.g., `198.51.100.*`), ports, and hostnames.
  - Automatic loopback bypass to avoid proxy self-loops.
- **SOCKS5 Protocol Tunneling**: Handshakes transparently with SOCKS5 proxies on intercepted Winsock `connect` and `WSAConnect` calls.
- **Two Operation Modes**:
  - `run`: Spawns a target process suspended, injects the hooking DLL, and resumes it cleanly.
  - `attach`: Attaches to an existing process owned by the current user session and injects the proxy hook.

---

## Architecture Overview

```
+------------------------------------------------------------------------+
|                               USER MODE                                |
|                                                                        |
|  +-----------------------+              +---------------------------+  |
|  |      proxify.exe      |              |     Target Application    |  |
|  |  (CLI Launcher/Mgr)   |              |   (e.g., app.exe, curl)   |  |
|  +-----------+-----------+              +-------------+-------------+  |
|              |                                        |                |
|       CreateProcessW                                  | calls connect  |
|       (SUSPENDED)                                     v                |
|       + Inject DLL                +----------------------------------+ |
|              +------------------->|         proxify_hook.dll         | |
|                                   |  (MinHook Winsock2 Interceptor)  | |
|                                   +-----------------+----------------+ |
|                                                     |                  |
|                                                     | matches rule?    |
|                                       +-------------+-------------+    |
|                                       |                           |    |
|                                   [Direct]                     [Proxy] |
|                                       |                           |    |
|                                       v                           v    |
|                                 Direct Socket             SOCKS5 Handshake  |
|                                 (Destination)             (Proxy Server)  |
+------------------------------------------------------------------------+
```

---

## Prerequisites

- Windows 10 / 11 / Server (x86_64)
- Rust toolchain (1.80+) for building from source

---

## Build Instructions

To build the workspace binaries:

```cmd
cargo build --release
```

The resulting binaries will be placed in `target/release/`:
- `proxify.exe` - CLI Manager & Launcher
- `proxify_hook.dll` - Winsock API interception hook library

---

## Configuration (`proxify.json`)

Generate a template configuration:
```cmd
proxify.exe config init --out proxify.json
```

Example `proxify.json`:
```json
{
  "proxy_host": "127.0.0.1",
  "proxy_port": 1080,
  "default_action": "direct",
  "rules": [
    {
      "name": "Proxy Specific Subnet",
      "action": "proxy",
      "target_ips": ["198.51.100.*", "203.0.113.10"],
      "target_ports": [80, 443, 8080],
      "target_hosts": ["*.corp.example.com"]
    },
    {
      "name": "Direct Localhost Bypass",
      "action": "direct",
      "target_ips": ["127.0.0.1", "::1"],
      "target_ports": [],
      "target_hosts": ["localhost"]
    }
  ]
}
```

### Rule Fields:
- `proxy_host` / `proxy_port`: The listening host and port of your SOCKS5 proxy server.
- `default_action`: `direct` (bypass proxy for unmatched targets) or `proxy` (route unmatched targets through proxy).
- `rules`: List of matching rules:
  - `action`: `proxy` or `direct`
  - `target_ips`: Exact IPs (`203.0.113.10`) or prefix wildcards (`198.51.100.*`).
  - `target_ports`: Target port filter (e.g. `[80, 443]`), or empty `[]` for any port.
  - `target_hosts`: Hostname/domain patterns.

---

## Usage Guide

### 1. Launching the Graphical User Interface (GUI)
Run either of the following commands:
```cmd
# Launch GUI directly:
target\release\proxify-ui.exe

# Or via the CLI:
target\release\proxify.exe ui
```

The GUI provides 4 tabs:
- **📦 Applications**: Add desktop apps, specify arguments, and click **🚀 Launch Proxified** to run them with proxy hooks.
- **🌐 Routing Rules**: Add target IP addresses, subnets (e.g. `198.51.100.*`), ports, and domains with Proxy vs. Direct actions.
- **⚡ Running Processes**: View all active user processes and attach proxy hooks with 1 click without restarting the app.
- **⚙ Settings**: Configure SOCKS5 proxy host/port and run live connectivity tests.

---

### 2. Test Proxy Connectivity (CLI)
Run any Windows application through the proxy filter:
```cmd
# Example: Launch curl with proxy hook
proxify.exe run curl.exe https://api.myip.com

# Example: Launch any executable with custom config and debug logs
proxify.exe run "C:\Path\To\App.exe" --debug --config proxify.json
```

### 3. Attach to a Running Process
Attach the hook to a process currently running under your user account:
```cmd
proxify.exe attach <PID>
```

### 4. Inspect Configuration
```cmd
proxify.exe config show --config proxify.json
```

---

## Security & Non-Admin Guarantee

1. **No Drivers**: Does not require WFP (Windows Filtering Platform) drivers or WinDivert / Wintun.
2. **Standard User Token**: Operates strictly within user-space permissions (`PROCESS_ALL_ACCESS` is natively permitted for processes within the same Windows user session).
3. **No Registry Elevation**: Does not alter system-wide `HKLM` registry entries or network adapter configurations.
