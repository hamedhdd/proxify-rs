use clap::{Parser, Subcommand};
use proxify_core::{ProxyConfig, Rule, RuleAction, socks5};
use std::ffi::{c_void, OsStr};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, HMODULE, INVALID_HANDLE_VALUE, WAIT_FAILED};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleBaseNameA};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD,
    PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE, ResumeThread, STARTUPINFOW, WaitForSingleObject,
};

#[derive(Parser)]
#[command(name = "proxify")]
#[command(about = "User-mode application proxy manager without admin privileges or drivers", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch an application and proxy its connections based on rules
    Run {
        /// Target executable path (e.g. C:\Path\To\App.exe or curl.exe)
        app: String,

        /// Arguments passed to the target application
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,

        /// Path to custom proxy configuration file (JSON)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Path to custom proxify_hook.dll
        #[arg(long)]
        dll: Option<PathBuf>,

        /// Enable verbose hook debug logging
        #[arg(short, long)]
        debug: bool,
    },

    /// Attach and inject proxy hook into existing running processes by PID or Name (attaches to ALL matching PIDs)
    Attach {
        /// Process ID (PID)
        #[arg(short, long)]
        pid: Option<u32>,

        /// Process executable name (e.g. "telegram.exe", "firefox", "chrome") — injects into ALL matching PIDs!
        #[arg(short, long)]
        name: Option<String>,

        /// Path to custom proxify_hook.dll
        #[arg(long)]
        dll: Option<PathBuf>,
    },

    /// Detach and unhook proxy from running processes by PID or Name (restores original Winsock handlers)
    Detach {
        /// Process ID (PID)
        #[arg(short, long)]
        pid: Option<u32>,

        /// Process executable name (e.g. "telegram.exe", "firefox", "chrome") — detaches from ALL matching PIDs!
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Manage configuration rules
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },

    /// Test connectivity to the configured SOCKS5 proxy server
    Test {
        /// Path to proxy configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Launch the interactive graphical user interface (GUI)
    Ui,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Create a template configuration file
    Init {
        /// Destination file path (default: proxify.json)
        #[arg(short, long, default_value = "proxify.json")]
        out: PathBuf,
    },

    /// Display current active routing configuration
    Show {
        /// Configuration file path
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

fn find_hook_dll(explicit_path: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(p) = explicit_path {
        if p.exists() {
            return Ok(p.to_path_buf());
        }
        return Err(format!("Explicit DLL path not found: {}", p.display()));
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("proxify_hook.dll");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    // Check development target directories
    let dev_candidates = [
        PathBuf::from("target/debug/proxify_hook.dll"),
        PathBuf::from("target/release/proxify_hook.dll"),
        PathBuf::from("../target/debug/proxify_hook.dll"),
        PathBuf::from("../target/release/proxify_hook.dll"),
    ];

    for candidate in &dev_candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }

    Err("Could not locate proxify_hook.dll. Build with `cargo build` or specify with --dll.".to_string())
}

unsafe fn inject_dll(process_handle: HANDLE, dll_path: &Path) -> Result<(), String> {
    // Check if target is a 32-bit process running under WOW64 on 64-bit Windows
    let mut is_wow64: windows_sys::Win32::Foundation::BOOL = 0;
    windows_sys::Win32::System::Threading::IsWow64Process(process_handle, &mut is_wow64);
    if is_wow64 != 0 {
        return Err("Target process is 32-bit (x86). 64-bit Proxify cannot inject into 32-bit processes.".to_string());
    }

    let dll_abs_path = dll_path
        .canonicalize()
        .map_err(|e| format!("Failed to canonicalize DLL path: {}", e))?;

    // Strip verbatim UNC prefix "\\?\"
    let mut path_str = dll_abs_path.to_string_lossy().to_string();
    if path_str.starts_with(r"\\?\") {
        path_str = path_str[4..].to_string();
    }

    let wide_path: Vec<u16> = OsStr::new(&path_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let wide_path_bytes_len = wide_path.len() * 2;

    let remote_mem = VirtualAllocEx(
        process_handle,
        core::ptr::null_mut(),
        wide_path_bytes_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if remote_mem.is_null() {
        return Err(format!("VirtualAllocEx failed: {}", std::io::Error::last_os_error()));
    }

    let mut written: usize = 0;
    let write_res = WriteProcessMemory(
        process_handle,
        remote_mem,
        wide_path.as_ptr() as *const _,
        wide_path_bytes_len,
        &mut written,
    );
    if write_res == 0 || written != wide_path_bytes_len {
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        return Err(format!("WriteProcessMemory failed: {}", std::io::Error::last_os_error()));
    }

    let kernel32_name = b"kernel32.dll\0";
    let h_kernel32 = GetModuleHandleA(kernel32_name.as_ptr());
    if h_kernel32.is_null() {
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        return Err("Failed to obtain handle to kernel32.dll".to_string());
    }

    let load_library_name = b"LoadLibraryW\0";
    let load_library_addr = GetProcAddress(h_kernel32, load_library_name.as_ptr());
    if load_library_addr.is_none() {
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        return Err("Failed to find LoadLibraryW symbol in kernel32.dll".to_string());
    }

    let thread_start_routine = core::mem::transmute(load_library_addr);
    let h_thread = CreateRemoteThread(
        process_handle,
        core::ptr::null(),
        0,
        thread_start_routine,
        remote_mem,
        0,
        core::ptr::null_mut(),
    );
    if h_thread.is_null() {
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        return Err(format!("CreateRemoteThread failed: {}", std::io::Error::last_os_error()));
    }

    let wait_res = WaitForSingleObject(h_thread, 10000);
    if wait_res == WAIT_FAILED {
        CloseHandle(h_thread);
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        return Err("WaitForSingleObject failed on injection thread".to_string());
    }

    // Check thread exit code = return value of LoadLibraryW!
    let mut exit_code: u32 = 0;
    windows_sys::Win32::System::Threading::GetExitCodeThread(h_thread, &mut exit_code);
    CloseHandle(h_thread);
    VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);

    if exit_code == 0 {
        return Err(format!(
            "LoadLibraryW returned NULL in target process for '{}'. Injection rejected by target process (Process Mitigation Policy / Sandboxed child process).",
            path_str
        ));
    }

    Ok(())
}

unsafe fn eject_dll(process_handle: HANDLE, module_name: &str) -> Result<(), String> {
    let kernel32_name = b"kernel32.dll\0";
    let h_kernel32 = GetModuleHandleA(kernel32_name.as_ptr());
    if h_kernel32.is_null() {
        return Err("GetModuleHandleA kernel32.dll failed".to_string());
    }

    let free_library_name = b"FreeLibrary\0";
    let free_library_addr = GetProcAddress(h_kernel32, free_library_name.as_ptr());
    if free_library_addr.is_none() {
        return Err("GetProcAddress FreeLibrary failed".to_string());
    }
    let thread_start_routine = core::mem::transmute(free_library_addr);

    let target_name_lower = module_name.to_lowercase();
    let mut attempts = 0;

    // Call FreeLibrary repeatedly until the module is completely unmapped
    loop {
        let mut modules: [HMODULE; 1024] = [core::ptr::null_mut(); 1024];
        let mut cb_needed: u32 = 0;
        let ok = EnumProcessModules(
            process_handle,
            modules.as_mut_ptr(),
            (modules.len() * core::mem::size_of::<HMODULE>()) as u32,
            &mut cb_needed,
        );

        if ok == 0 {
            if attempts > 0 {
                return Ok(());
            }
            return Err(format!("EnumProcessModules failed: {}", std::io::Error::last_os_error()));
        }

        let count = (cb_needed as usize) / core::mem::size_of::<HMODULE>();
        let mut target_hmodule: Option<HMODULE> = None;

        for &h_mod in &modules[..count.min(modules.len())] {
            if h_mod.is_null() {
                continue;
            }
            let mut name_buf = [0u8; 260];
            let len = GetModuleBaseNameA(
                process_handle,
                h_mod,
                name_buf.as_mut_ptr(),
                name_buf.len() as u32,
            );
            if len > 0 {
                let name_str = String::from_utf8_lossy(&name_buf[..len as usize]).to_lowercase();
                if name_str == target_name_lower {
                    target_hmodule = Some(h_mod);
                    break;
                }
            }
        }

        let h_mod = match target_hmodule {
            Some(m) => m,
            None => {
                if attempts > 0 {
                    return Ok(());
                } else {
                    return Err(format!("Module '{}' is not loaded in target process.", module_name));
                }
            }
        };

        attempts += 1;
        if attempts > 25 {
            return Err(format!("Module '{}' could not be unloaded after 25 FreeLibrary attempts.", module_name));
        }

        let h_thread = CreateRemoteThread(
            process_handle,
            core::ptr::null(),
            0,
            thread_start_routine,
            h_mod as *const c_void,
            0,
            core::ptr::null_mut(),
        );

        if h_thread.is_null() {
            return Err(format!("CreateRemoteThread FreeLibrary failed: {}", std::io::Error::last_os_error()));
        }

        let wait_res = WaitForSingleObject(h_thread, 10000);
        if wait_res == WAIT_FAILED {
            CloseHandle(h_thread);
            return Err("WaitForSingleObject failed on FreeLibrary thread".to_string());
        }

        let mut exit_code: u32 = 0;
        windows_sys::Win32::System::Threading::GetExitCodeThread(h_thread, &mut exit_code);
        CloseHandle(h_thread);

        if exit_code == 0 {
            return Err("FreeLibrary returned FALSE in target process.".to_string());
        }
    }
}

fn resolve_config(cfg_path: Option<&Path>) -> (ProxyConfig, Option<PathBuf>) {
    if let Some(p) = cfg_path {
        if let Ok(content) = fs::read_to_string(p) {
            if let Ok(cfg) = serde_json::from_str::<ProxyConfig>(&content) {
                return (cfg, Some(p.to_path_buf()));
            }
        }
    }

    let default_local = PathBuf::from("proxify.json");
    if default_local.exists() {
        if let Ok(content) = fs::read_to_string(&default_local) {
            if let Ok(cfg) = serde_json::from_str::<ProxyConfig>(&content) {
                return (cfg, Some(default_local));
            }
        }
    }

    (ProxyConfig::default(), None)
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            app,
            args,
            config,
            dll,
            debug,
        } => {
            let dll_path = match find_hook_dll(dll.as_deref()) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("Error: {}", err);
                    std::process::exit(1);
                }
            };

            let (_, resolved_cfg_path) = resolve_config(config.as_deref());

            if debug {
                std::env::set_var("PROXIFY_DEBUG", "1");
            }

            if let Some(ref p) = resolved_cfg_path {
                if let Ok(canon) = p.canonicalize() {
                    std::env::set_var("PROXIFY_CONFIG", canon.to_str().unwrap_or(""));
                }
            }

            println!("==> Launching: {} with proxify hook", app);
            println!("==> Injected DLL: {}", dll_path.display());
            if let Some(ref p) = resolved_cfg_path {
                println!("==> Configuration: {}", p.display());
            }

            let mut cmd_line_str = format!("\"{}\"", app);
            for arg in &args {
                cmd_line_str.push(' ');
                cmd_line_str.push_str(arg);
            }

            let mut cmd_line_wide: Vec<u16> = OsStr::new(&cmd_line_str)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut startup_info: STARTUPINFOW = unsafe { core::mem::zeroed() };
            startup_info.cb = core::mem::size_of::<STARTUPINFOW>() as u32;

            let mut proc_info: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };

            let success = unsafe {
                CreateProcessW(
                    core::ptr::null(),
                    cmd_line_wide.as_mut_ptr(),
                    core::ptr::null(),
                    core::ptr::null(),
                    FALSE,
                    CREATE_SUSPENDED,
                    core::ptr::null(),
                    core::ptr::null(),
                    &mut startup_info,
                    &mut proc_info,
                )
            };

            if success == 0 {
                eprintln!(
                    "Failed to create process '{}': {}",
                    app,
                    std::io::Error::last_os_error()
                );
                std::process::exit(1);
            }

            println!("==> Target process created (PID: {}). Injecting hook...", proc_info.dwProcessId);

            unsafe {
                if let Err(e) = inject_dll(proc_info.hProcess, &dll_path) {
                    eprintln!("Warning: Failed to inject DLL: {}", e);
                } else {
                    println!("==> Hook successfully injected!");
                }

                ResumeThread(proc_info.hThread);
                CloseHandle(proc_info.hThread);

                // Wait for the target process to finish
                WaitForSingleObject(proc_info.hProcess, windows_sys::Win32::System::Threading::INFINITE);
                CloseHandle(proc_info.hProcess);
            }

            println!("==> Process {} exited.", proc_info.dwProcessId);
        }

        Commands::Attach { pid, name, dll } => {
            let dll_path = match find_hook_dll(dll.as_deref()) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("Error: {}", err);
                    std::process::exit(1);
                }
            };

            let targets: Vec<(u32, String)> = match (pid, name) {
                (Some(p), None) => vec![(p, format!("PID {}", p))],
                (None, Some(ref n)) => {
                    let found = find_pids_by_name(n);
                    if found.is_empty() {
                        eprintln!("No running processes found matching '{}'", n);
                        std::process::exit(1);
                    }
                    found
                }
                (Some(p), Some(n)) => {
                    println!("Attaching to explicit PID {} ({})", p, n);
                    vec![(p, n)]
                }
                (None, None) => {
                    eprintln!("Error: Please specify either --pid <PID> or --name <PROCESS_NAME> (e.g. proxify attach --name telegram.exe)");
                    std::process::exit(1);
                }
            };

            println!("==> Found {} target process(es) to attach:", targets.len());
            let desired_access = PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ;

            let mut success_count = 0;
            let mut sandboxed_count = 0;
            for (p, proc_name) in &targets {
                let h_proc = unsafe { OpenProcess(desired_access, FALSE, *p) };
                if h_proc.is_null() {
                    eprintln!("  ✗ PID {} ({}): Failed to open (Access Denied / not running): {}", p, proc_name, std::io::Error::last_os_error());
                    continue;
                }

                unsafe {
                    match inject_dll(h_proc, &dll_path) {
                        Ok(_) => {
                            println!("  ✓ PID {} ({}): Injected proxify hook successfully", p, proc_name);
                            success_count += 1;
                        }
                        Err(e) => {
                            if e.contains("Sandboxed child process") || e.contains("Injection rejected") {
                                sandboxed_count += 1;
                                if success_count > 0 {
                                    println!("  ℹ PID {} ({}): Sandboxed child renderer skipped (network traffic is routed via hooked main process)", p, proc_name);
                                } else {
                                    println!("  ℹ PID {} ({}): Sandboxed child process rejected injection. In multi-process browsers, attach the main process.", p, proc_name);
                                }
                            } else {
                                eprintln!("  ✗ PID {} ({}): Injection failed: {}", p, proc_name, e);
                            }
                        }
                    }
                    CloseHandle(h_proc);
                }
            }
            if success_count > 0 {
                if sandboxed_count > 0 {
                    println!("==> Finished: Successfully hooked application! ({} main/parent process(es) hooked; {} sandboxed renderers skipped).", success_count, sandboxed_count);
                } else {
                    println!("==> Finished: Successfully attached to {}/{} process(es).", success_count, targets.len());
                }
            } else {
                println!("==> Finished: Attached to 0/{} process(es).", targets.len());
            }
        }

        Commands::Detach { pid, name } => {
            let targets: Vec<(u32, String)> = match (pid, name) {
                (Some(p), None) => vec![(p, format!("PID {}", p))],
                (None, Some(ref n)) => {
                    let found = find_pids_by_name(n);
                    if found.is_empty() {
                        eprintln!("No running processes found matching '{}'", n);
                        std::process::exit(1);
                    }
                    found
                }
                (Some(p), Some(n)) => {
                    println!("Detaching from explicit PID {} ({})", p, n);
                    vec![(p, n)]
                }
                (None, None) => {
                    eprintln!("Error: Please specify either --pid <PID> or --name <PROCESS_NAME> (e.g. proxify detach --name telegram.exe)");
                    std::process::exit(1);
                }
            };

            println!("==> Found {} target process(es) to detach & unhook:", targets.len());
            let desired_access = PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ;

            let mut success_count = 0;
            for (p, proc_name) in &targets {
                let h_proc = unsafe { OpenProcess(desired_access, FALSE, *p) };
                if h_proc.is_null() {
                    eprintln!("  ✗ PID {} ({}): Failed to open (Access Denied / not running): {}", p, proc_name, std::io::Error::last_os_error());
                    continue;
                }

                unsafe {
                    match eject_dll(h_proc, "proxify_hook.dll") {
                        Ok(_) => {
                            println!("  ✓ PID {} ({}): Detached proxify hook and restored original Winsock APIs cleanly", p, proc_name);
                            success_count += 1;
                        }
                        Err(e) => {
                            if !e.contains("not loaded") {
                                eprintln!("  ✗ PID {} ({}): Detach failed: {}", p, proc_name, e);
                            }
                        }
                    }
                    CloseHandle(h_proc);
                }
            }
            println!("==> Finished: Successfully detached from {}/{} process(es).", success_count, targets.len());
        }

        Commands::Config { action } => match action {
            ConfigCommands::Init { out } => {
                let template = ProxyConfig {
                    proxy_host: "127.0.0.1".to_string(),
                    proxy_port: 1080,
                    proxy_username: None,
                    proxy_password: None,
                    theme: Some("dark".to_string()),
                    default_action: RuleAction::Direct,
                    rules: vec![
                        Rule {
                            name: "Proxy Specific Corporate Subnet".to_string(),
                            action: RuleAction::Proxy,
                            target_apps: vec![],
                            target_ips: vec!["198.51.100.*".to_string(), "203.0.113.10".to_string()],
                            target_ports: vec![80, 443, 8080],
                            target_hosts: vec!["*.corp.example.com".to_string()],
                        },
                        Rule {
                            name: "Direct Localhost Bypass".to_string(),
                            action: RuleAction::Direct,
                            target_apps: vec![],
                            target_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
                            target_ports: vec![],
                            target_hosts: vec!["localhost".to_string()],
                        },
                    ],
                    apps: vec![],
                };

                match serde_json::to_string_pretty(&template) {
                    Ok(json) => {
                        if let Err(e) = fs::write(&out, json) {
                            eprintln!("Failed to write configuration: {}", e);
                            std::process::exit(1);
                        }
                        println!("==> Created configuration template at: {}", out.display());
                    }
                    Err(e) => {
                        eprintln!("Failed to serialize template: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            ConfigCommands::Show { config } => {
                let (cfg, path) = resolve_config(config.as_deref());
                println!("==> Configuration Source: {:?}", path.unwrap_or_else(|| PathBuf::from("Default (in-memory)")));
                println!("    Proxy Server:   {}:{}", cfg.proxy_host, cfg.proxy_port);
                println!("    Default Action: {:?}", cfg.default_action);
                println!("    Rules count:    {}", cfg.rules.len());
                for (i, r) in cfg.rules.iter().enumerate() {
                    println!("    [{}] {} => {:?}", i + 1, r.name, r.action);
                    if !r.target_ips.is_empty() {
                        println!("         Target IPs: {:?}", r.target_ips);
                    }
                    if !r.target_ports.is_empty() {
                        println!("         Target Ports: {:?}", r.target_ports);
                    }
                    if !r.target_hosts.is_empty() {
                        println!("         Target Hosts: {:?}", r.target_hosts);
                    }
                }
            }
        },

        Commands::Test { config } => {
            let (cfg, _) = resolve_config(config.as_deref());
            let target_addr = format!("{}:{}", cfg.proxy_host, cfg.proxy_port);
            println!("==> Testing connection to SOCKS5 proxy at {}...", target_addr);

            match target_addr.to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                            Ok(mut stream) => {
                                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                                let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));

                                let greeting = socks5::build_greeting();
                                if let Err(e) = stream.write_all(&greeting) {
                                    eprintln!("Failed to send SOCKS5 greeting: {}", e);
                                    std::process::exit(1);
                                }

                                let mut resp = [0u8; 2];
                                if let Err(e) = stream.read_exact(&mut resp) {
                                    eprintln!("Failed to read SOCKS5 greeting response: {}", e);
                                    std::process::exit(1);
                                }

                                if socks5::verify_greeting_response(&resp) {
                                    println!("✓ SOCKS5 proxy is ONLINE and ready (Handshake successful: VER=0x05, NO_AUTH)!");
                                } else {
                                    eprintln!("✗ Proxy responded but rejected greeting: {:?}", resp);
                                }
                            }
                            Err(e) => {
                                eprintln!("✗ Could not connect to SOCKS5 proxy at {}: {}", target_addr, e);
                                std::process::exit(1);
                            }
                        }
                    } else {
                        eprintln!("Failed to resolve proxy address: {}", target_addr);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to resolve proxy socket address: {}", e);
                }
            }
        }

        Commands::Ui => {
            let mut ui_path = std::env::current_exe().unwrap_or_default();
            ui_path.set_file_name("proxify-ui.exe");
            if !ui_path.exists() {
                let cand1 = PathBuf::from("target/release/proxify-ui.exe");
                let cand2 = PathBuf::from("target/debug/proxify-ui.exe");
                if cand1.exists() {
                    ui_path = cand1;
                } else if cand2.exists() {
                    ui_path = cand2;
                }
            }
            println!("==> Launching Proxify GUI: {}", ui_path.display());
            match std::process::Command::new(&ui_path).spawn() {
                Ok(_) => println!("==> GUI launched successfully."),
                Err(e) => eprintln!("Failed to launch GUI binary at {}: {}", ui_path.display(), e),
            }
        }
    }
}

fn find_pids_by_name(name_query: &str) -> Vec<(u32, String)> {
    let mut raw_matches = Vec::new();
    let q = name_query.to_lowercase();
    let q_exe = if q.ends_with(".exe") { q.clone() } else { format!("{}.exe", q) };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Vec::new();
        }

        let mut entry: PROCESSENTRY32 = core::mem::zeroed();
        entry.dwSize = core::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) != 0 {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let bytes: Vec<u8> = entry.szExeFile[..len].iter().map(|&c| c as u8).collect();
                let name = String::from_utf8_lossy(&bytes).to_string();
                let name_lower = name.to_lowercase();

                if (name_lower == q || name_lower == q_exe || name_lower.contains(&q)) && entry.th32ProcessID > 4 {
                    raw_matches.push((entry.th32ProcessID, entry.th32ParentProcessID, name));
                }

                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }

    let pid_set: std::collections::HashSet<u32> = raw_matches.iter().map(|(pid, _, _)| *pid).collect();
    raw_matches.sort_by_key(|(_, parent_pid, _)| {
        if pid_set.contains(parent_pid) {
            1 // Child process (e.g. renderer)
        } else {
            0 // Main / Root process
        }
    });

    raw_matches.into_iter().map(|(pid, _, name)| (pid, name)).collect()
}
