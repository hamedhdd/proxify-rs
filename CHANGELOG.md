# Changelog

All notable changes to `proxify-rs` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
