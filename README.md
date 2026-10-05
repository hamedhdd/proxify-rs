# proxify-rs

`proxify-rs` is a lightweight, user-mode application proxy manager for Windows written in Rust. It functions similarly to Proxifier or Linux's `proxychains`, allowing you to route network traffic of specific Windows applications through SOCKS5 proxies based on granular target rules (IP addresses, subnets, ports, or domains)—**completely without administrator privileges, kernel drivers (WFP/Wintun), or PowerShell commands**.

---

## Key Features

- **Interactive Native GUI (`proxify-ui`)**: Clean desktop interface built in Rust (with egui) to visually manage proxied apps, configure IP/domain routing rules, inspect live running processes, and test proxy connectivity with 1 click. Console window is automatically suppressed in release builds.
- **Native File Dialog**: Integrated `rfd` file picker to browse and select `.exe` applications without manual path entry.
- **Asynchronous & Non-Blocking**: Process launching, suspended DLL injection, and active process attaching run in background threads via `mpsc` channels with zero UI freeze.
- **SOCKS5 with RFC 1929 Authentication**: Supports both unauthenticated proxies and username/password credentials in configuration and in-flight handshakes.
- **Zero Administrator Privileges**: Intercepts applications in user-mode using standard Win32 process spawning and memory injection. No UAC prompts, no driver signing, and no kernel extensions required.
- **No PowerShell Dependency**: Runs as standalone native binaries (`proxify-ui.exe` and `proxify.exe`) interacting directly with the Windows API (`CreateProcessW`, `LoadLibraryW`, Winsock2).
- **Rule-Based Routing**:
  - Direct vs. Proxy rules based on target IPv4 addresses, wildcard prefixes (e.g., `198.51.100.*`), ports, and hostnames.
  - Automatic loopback bypass to avoid proxy self-loops.
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

### 3. Attach to Running Processes (Single PID or All PIDs by Name)
Attach the hook to active processes running under your user session:
```cmd
# Attach to ALL running instances of an application by executable name:
proxify.exe attach --name telegram.exe
proxify.exe attach -n chrome.exe
proxify.exe attach -n firefox

# Or attach to a specific PID:
proxify.exe attach --pid 16392
```

In the GUI (`proxify-ui`):
- **Applications Tab**: Each app card features an **"⚡ Attach All (N running)"** button to hook all active instances with one click.
- **Running Processes Tab**: Multi-process applications are automatically grouped with an **"⚡ Attach All (N PIDs)"** button and a top-level **"⚡ Attach All Filtered"** action.

### 4. Detach & Unhook Running Processes (Clean Exit & Ejection)
Safely eject the proxy hook and restore original Winsock2 API bytecode without restarting the application:
```cmd
# Detach and restore Winsock APIs across ALL running instances of an application:
proxify.exe detach --name telegram.exe
proxify.exe detach -n firefox.exe

# Or detach a specific PID:
proxify.exe detach --pid 16392
```

In the GUI (`proxify-ui`):
- **Automatic on App Exit**: Closing `proxify-ui` automatically invokes `FreeLibrary` on all attached PIDs, cleanly disabling hooks via MinHook and restoring original socket handlers.
- **Automatic on App Deletion**: Deleting or removing an application from the list automatically detects and cleanly unhooks all running instances of that app.
- **On-Demand Buttons**: App cards and process groups feature **"🔌 Detach All"** and **"🔌 Detach Proxy"** buttons alongside live status indicators (`● Hooked`).

### 5. Inspect Configuration
```cmd
proxify.exe config show --config proxify.json
```

---

## Security & Non-Admin Guarantee

1. **No Drivers**: Does not require WFP (Windows Filtering Platform) drivers or WinDivert / Wintun.
2. **Standard User Token**: Operates strictly within user-space permissions (`PROCESS_ALL_ACCESS` is natively permitted for processes within the same Windows user session).
3. **No Registry Elevation**: Does not alter system-wide `HKLM` registry entries or network adapter configurations.
