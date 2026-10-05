# Changelog

All notable changes to `proxify-rs` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
