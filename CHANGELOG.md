# Changelog

All notable changes to `proxify-rs` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.2] - 2026-10-05

### Fixed
- **Automatic App Registration on Attachment**:
  - When attaching to running processes from the GUI (Live Process Monitor) or CLI (`proxify attach`), Proxify automatically registers the application in `config.apps` with `enabled = true` and persists it to `%LOCALAPPDATA%\proxify\config.json`.
  - Resolves issue where attached processes routed connections directly (`[DIRECT]`) instead of tunneling through the SOCKS5 proxy when `default_action` was set to `direct`.
- **Dynamic Configuration Hot-Reloading in Target Processes**:
  - Replaced one-time `OnceLock<ProxyConfig>` in `proxify_hook.dll` with an adaptive 1-second hot-reloader using `RwLock<CachedConfig>`.
  - Attached target processes now automatically pick up changes to routing rules, app toggles, and proxy settings in real time without needing re-injection.
- **Graceful Sandbox DACL & Memory Allocation Handling**:
  - Properly detects OS error 5 (`Access is denied`) during `VirtualAllocEx` and `CreateRemoteThread` on sandboxed child processes with restricted tokens.
  - Automatically classifies them as sandboxed child renderers and skips them gracefully with informational notices instead of alarming red error alerts.

### Added
- **IPv6 SOCKS5 Connect Frame Support**:
  - Added `socks5::build_connect_ipv6` to construct RFC 1928 IPv6 connection requests (`ATYP_IPV6`).
- **Unit Test Coverage for Routing & Registration**:
  - Added automated unit tests verifying `ensure_app_registered` deduplication, state re-enabling, and `should_proxy` evaluation.

## [0.5.1] - 2026-10-05

### Added
- **Intelligent Parent Process Prioritization**:
  - Automatically identifies the root/main process of multi-process applications (e.g. Firefox, Chrome, Edge, Telegram) by evaluating `ParentProcessId` hierarchy.
  - Prioritizes attaching to the main parent process first, establishing transparent proxy tunneling on the process that owns the socket stack.
- **Dedicated "Attach Main Process" Action**:
  - Live Process Monitor now labels the main process (e.g., `● Main PID: 17744`) and provides a 1-click **`⚡ Attach Main`** action alongside **`⚡ Attach All`**.
- **Graceful Sandboxed Renderer Handling**:
  - Recognizes Windows Process Mitigation Policies (such as `BlockLowLabelImageLoads` and `DisableWin32kSystemCalls` in tab content renderers like PID 25368).
  - Skips sandboxed tab renderers gracefully with informational notes (`ℹ Sandboxed child renderer skipped — network traffic is routed via hooked main process`) instead of confusing error messages.
  - Batch attach and detach operations report concise and accurate completion summaries.

## [0.5.0] - 2026-10-05

### Added
- **Automatic & Safe Unhooking on App Exit**:
  - Automatically unhooks all attached target processes when `proxify-ui` is closed (via `eframe::App::on_exit` and `Drop` handlers).
  - Cleanly disables hooks via `MinHook::disable_all_hooks()`, restores original Winsock2 bytecode, and unmaps the DLL memory space.
- **Automatic Detaching on App Deletion**:
  - Deleting or removing an application from the Applications list automatically locates any running instances and unhooks them immediately with clear activity logs.
- **On-Demand Detaching in GUI**:
  - **Applications Tab**: Added `🔌 Detach All` button to app cards with running instances and dynamic `● Hooked (N)` status indicators.
  - **Running Processes Tab**: Added `● Hooked` badges and individual `🔌 Detach Proxy` / group `🔌 Detach All (N PIDs)` action buttons.
  - Added `🔌 Detach All Filtered` button for fast search-based bulk detaching.
- **CLI `detach` Subcommand**:
  - `proxify detach --name <APP>`: Ejects the hook and restores original Winsock APIs across all running instances of the specified process name.
  - `proxify detach --pid <PID>`: Ejects the hook from a specific target process ID.
- **Multi-Instance DLL Ejection Engine (`eject_dll`)**:
  - Uses `EnumProcessModules` and `GetModuleBaseNameA` to locate the target `HMODULE` address in the remote process.
  - Invokes `FreeLibrary` via `CreateRemoteThread` in an adaptive loop, correctly handling Windows DLL loader reference counts until the module is 100% unmapped with zero crashes or residual code.
- **Hook Uninitialization (`DLL_PROCESS_DETACH`)**:
  - Added `uninitialize_hooks()` in `proxify-hook`, restoring original `connect` and `WSAConnect` entrypoints cleanly before unmapping.

## [0.4.0] - 2026-10-05

### Added
- **Multi-PID & Batch Process Attachment**:
  - **CLI `attach --name <NAME>`**: Injects the proxy hook across **all** running instances of a target application (e.g. `proxify attach --name telegram.exe` or `proxify attach -n chrome`).
  - **Grouped Process View in UI**: The Live Process Monitor now aggregates multi-process applications (e.g. `chrome.exe (18 instances)`, `Telegram.exe (2 instances)`), displaying grouped PID chips alongside an **"⚡ Attach All (N PIDs)"** action.
  - **"⚡ Attach All Filtered" in UI Search**: Filtering by process name or PID reveals a one-click button to attach to all matching process instances simultaneously.
  - **App Card Attachment in Applications Tab**: Applications configured in the user's app list display a live badge (e.g. `⚡ Attach All (2 running)`) to attach all running instances without switching tabs.
  - Asynchronous batch injector with per-PID status reporting and error recovery.

## [0.3.1] - 2026-10-05

### Fixed
- **Process Attachment & Transparent Proxy Routing**:
  - Eliminated race condition by running hook initialization synchronously in `DllMain(DLL_PROCESS_ATTACH)` instead of a delayed background thread.
  - Dynamically preloaded `ws2_32.dll` prior to hooking so MinHook never fails with `MH_ERROR_MODULE_NOT_FOUND` in newly spawned processes.
  - Implemented application process name matching (`ProxyConfig::should_proxy`), ensuring configured apps automatically route traffic through the proxy without needing manual destination IP wildcard rules.
  - Synchronized configuration globally to `%LOCALAPPDATA%\proxify\config.json`, allowing attached processes without inherited environment variables to load active routing rules.
  - Stripped verbatim UNC `\\?\` prefix from DLL path to prevent `LoadLibraryW` failure across external applications.
  - Added WOW64 32-bit architecture detection and `GetExitCodeThread` return checks to surface injection failures.
  - Added live persistent file logging to `%LOCALAPPDATA%\proxify\hook.log`.
  - Configured active default proxy port to `10808` (active v2rayN / Xray local SOCKS5 port).

## [0.3.0] - 2026-10-05

### Added
- **Native File Picker (`rfd`)**: "📁 Browse..." button to easily select target application `.exe` binaries with automatic path and name detection.
- **Asynchronous Non-blocking Operations**: Background worker threads with `mpsc` channel communication for application launching, suspended process injection, and live process attaching, eliminating UI thread freezes.
- **SOCKS5 Username/Password Authentication (RFC 1929)**: Subnegotiation support in `proxify-core` and in-flight hook `proxify-hook`, with credential fields in the Settings UI and live auth probe in Test Proxy.
- **Confirm-on-Delete Safety**: Two-step confirmation for removing applications and routing rules to prevent accidental deletions.
- **Appearance & Theme Switcher**: Dark / Light theme switcher persisted to `proxify.json`.
- **Keyboard Shortcuts**: `Ctrl+S` (Save), `Ctrl+R` / `F5` (Refresh processes), `Ctrl+T` (Test proxy).
- **Rule Search & Filtering**: Real-time filter box in the Routing Rules tab.

### Fixed
- **Terminal Console Window Suppression**: Added `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]` to silence the companion black console window in release GUI builds.

## [0.2.0] - 2026-10-05

### Added
- **Graphical User Interface (`proxify-ui`)**: Native desktop UI built with `eframe`/`egui`.
  - Applications management tab: Add apps and launch them in suspended mode with in-memory hook injection via a single click.
  - Granular routing rules editor: Add/delete IP address, subnet (`198.51.100.*`), port, and domain rules.
  - Live process monitor: Enumerate running user processes via ToolHelp API and attach proxy hooks without restarts.
  - SOCKS5 connectivity testing tool with real-time handshake validation and response status badge.
- Added `ui` subcommand to `proxify` CLI (`proxify ui`).
- Extended `ProxyConfig` with `AppConfig` list.

## [0.1.0] - 2026-10-05

### Added
- Core architecture (`proxify-core`): SOCKS5 handshake frame builder and parser, rule-based IP/port/domain matching engine.
- Winsock Hooking DLL (`proxify-hook`): Injected DLL hooking `ws2_32.dll!connect` and `ws2_32.dll!WSAConnect` via MinHook, performing transparent in-flight SOCKS5 tunneling.
- CLI Manager & Launcher (`proxify-cli`):
  - `run`: Spawns target processes in a suspended state, injects `proxify_hook.dll`, and resumes execution without administrator rights.
  - `attach`: Attaches to existing processes owned by the user session and injects hook DLL.
  - `config init` / `config show`: Initializes and inspects JSON routing configuration templates.
  - `test`: SOCKS5 probe tool to verify handshake and connectivity with target proxy servers.
- Complete documentation and architectural runbook.
