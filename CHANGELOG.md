# Changelog

All notable changes to `proxify-rs` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
