use clap::{Parser, Subcommand};
use proxify_core::{ProxyConfig, Rule, RuleAction, socks5};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, WAIT_FAILED};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
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

    /// Attach and inject proxy hook into an existing running process by PID
    Attach {
        /// Process ID (PID)
        pid: u32,

        /// Path to custom proxify_hook.dll
        #[arg(long)]
        dll: Option<PathBuf>,
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
    let dll_abs_path = dll_path
        .canonicalize()
        .map_err(|e| format!("Failed to canonicalize DLL path: {}", e))?;

    let wide_path: Vec<u16> = dll_abs_path
        .as_os_str()
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
        return Err("VirtualAllocEx failed in target process memory".to_string());
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
        return Err("WriteProcessMemory failed to write DLL path".to_string());
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
        return Err("CreateRemoteThread failed in target process".to_string());
    }

    let wait_res = WaitForSingleObject(h_thread, 10000);
    CloseHandle(h_thread);
    VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);

    if wait_res == WAIT_FAILED {
        return Err("WaitForSingleObject failed on injection thread".to_string());
    }

    Ok(())
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

        Commands::Attach { pid, dll } => {
            let dll_path = match find_hook_dll(dll.as_deref()) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("Error: {}", err);
                    std::process::exit(1);
                }
            };

            println!("==> Attaching to PID: {}", pid);

            let desired_access = PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ;

            let h_proc = unsafe { OpenProcess(desired_access, FALSE, pid) };
            if h_proc.is_null() {
                eprintln!(
                    "Failed to open process PID {} (Ensure process runs as your user): {}",
                    pid,
                    std::io::Error::last_os_error()
                );
                std::process::exit(1);
            }

            unsafe {
                match inject_dll(h_proc, &dll_path) {
                    Ok(_) => println!("==> Successfully injected proxify hook into PID {}", pid),
                    Err(e) => eprintln!("Failed to inject into PID {}: {}", pid, e),
                }
                CloseHandle(h_proc);
            }
        }

        Commands::Config { action } => match action {
            ConfigCommands::Init { out } => {
                let template = ProxyConfig {
                    proxy_host: "127.0.0.1".to_string(),
                    proxy_port: 1080,
                    default_action: RuleAction::Direct,
                    rules: vec![
                        Rule {
                            name: "Proxy Specific Corporate Subnet".to_string(),
                            action: RuleAction::Proxy,
                            target_ips: vec!["198.51.100.*".to_string(), "203.0.113.10".to_string()],
                            target_ports: vec![80, 443, 8080],
                            target_hosts: vec!["*.corp.example.com".to_string()],
                        },
                        Rule {
                            name: "Direct Localhost Bypass".to_string(),
                            action: RuleAction::Direct,
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
