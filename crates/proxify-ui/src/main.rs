// Suppress the console window on Windows release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use proxify_core::{AppConfig, ProxyConfig, Rule, RuleAction, socks5};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD,
    PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE, ResumeThread, STARTUPINFOW, WaitForSingleObject,
};

#[derive(Clone, Debug)]
pub struct ProcessItem {
    pub pid: u32,
    pub name: String,
}

#[derive(PartialEq)]
enum ActiveTab {
    Applications,
    Rules,
    RunningProcesses,
    Settings,
}

struct ProxifyApp {
    config: ProxyConfig,
    config_path: PathBuf,
    active_tab: ActiveTab,

    // Proxy test state
    test_status: Option<String>,
    test_success: bool,

    // New app inputs
    new_app_name: String,
    new_app_path: String,
    new_app_args: String,

    // New rule inputs
    new_rule_name: String,
    new_rule_ips: String,
    new_rule_ports: String,
    new_rule_hosts: String,
    new_rule_action: RuleAction,

    // Search filters
    rule_search: String,
    proc_search: String,

    // Confirm-on-delete state
    confirm_delete_app: Option<usize>,
    confirm_delete_rule: Option<usize>,

    // Theme state
    is_dark_theme: bool,

    // Process monitor
    processes: Vec<ProcessItem>,

    // Async background task communication
    log_tx: Sender<String>,
    log_rx: Receiver<String>,

    // Activity log entries
    logs: Vec<String>,
}

impl ProxifyApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let config_path = PathBuf::from("proxify.json");
        let config = if config_path.exists() {
            fs::read_to_string(&config_path)
                .ok()
                .and_then(|c| serde_json::from_str(&c).ok())
                .unwrap_or_default()
        } else {
            ProxyConfig::default()
        };

        let is_dark_theme = config.theme.as_deref().unwrap_or("dark") != "light";
        if is_dark_theme {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
        } else {
            cc.egui_ctx.set_visuals(egui::Visuals::light());
        }

        let (log_tx, log_rx) = channel();

        let mut app = Self {
            config,
            config_path,
            active_tab: ActiveTab::Applications,
            test_status: None,
            test_success: false,
            new_app_name: String::new(),
            new_app_path: String::new(),
            new_app_args: String::new(),
            new_rule_name: String::new(),
            new_rule_ips: String::new(),
            new_rule_ports: String::new(),
            new_rule_hosts: String::new(),
            new_rule_action: RuleAction::Proxy,
            rule_search: String::new(),
            proc_search: String::new(),
            confirm_delete_app: None,
            confirm_delete_rule: None,
            is_dark_theme,
            processes: Vec::new(),
            log_tx,
            log_rx,
            logs: vec!["Proxify UI initialized. Ready to control apps and routes.".to_string()],
        };

        app.refresh_processes();
        app
    }

    fn log(&mut self, msg: &str) {
        let time_str = chrono_format_now();
        self.logs.push(format!("[{}] {}", time_str, msg));
        if self.logs.len() > 150 {
            self.logs.remove(0);
        }
    }

    fn save_config(&mut self) {
        self.config.theme = Some(if self.is_dark_theme {
            "dark".to_string()
        } else {
            "light".to_string()
        });

        if let Ok(json) = serde_json::to_string_pretty(&self.config) {
            let _ = fs::write(&self.config_path, &json);

            // Save to %LOCALAPPDATA%\proxify\config.json for target processes
            if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
                let dir = PathBuf::from(&local_appdata).join("proxify");
                let _ = fs::create_dir_all(&dir);
                let _ = fs::write(dir.join("config.json"), &json);
            }

            // Save to %APPDATA%\proxify\config.json
            if let Ok(appdata) = std::env::var("APPDATA") {
                let dir = PathBuf::from(&appdata).join("proxify");
                let _ = fs::create_dir_all(&dir);
                let _ = fs::write(dir.join("config.json"), &json);
            }

            self.log(&format!("Saved configuration to {} and global AppData.", self.config_path.display()));
        }
    }

    fn refresh_processes(&mut self) {
        self.processes = list_running_processes();
    }

    fn test_proxy_connection(&mut self) {
        let target = format!("{}:{}", self.config.proxy_host, self.config.proxy_port);
        let username = self.config.proxy_username.clone();
        let password = self.config.proxy_password.clone();
        let tx = self.log_tx.clone();

        self.log(&format!("Testing connection to SOCKS5 proxy at {}...", target));

        // Perform test asynchronously so UI never hangs
        std::thread::spawn(move || {
            match target.to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                            Ok(mut stream) => {
                                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                                let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));

                                let has_auth = username.is_some() && password.is_some();
                                let greeting = socks5::build_greeting_methods(has_auth);
                                if stream.write_all(&greeting).is_err() {
                                    let _ = tx.send("Error: Failed to send SOCKS5 greeting.".to_string());
                                    return;
                                }

                                let mut resp = [0u8; 2];
                                if stream.read_exact(&mut resp).is_err() || resp[0] != socks5::SOCKS_VERSION {
                                    let _ = tx.send("Error: Proxy rejected greeting or returned invalid version.".to_string());
                                    return;
                                }

                                if resp[1] == socks5::AUTH_USER_PASS {
                                    if let (Some(u), Some(p)) = (username, password) {
                                        let auth_req = socks5::build_auth_request(&u, &p);
                                        let _ = stream.write_all(&auth_req);
                                        let mut auth_resp = [0u8; 2];
                                        if stream.read_exact(&mut auth_resp).is_ok() && socks5::verify_auth_response(&auth_resp) {
                                            let _ = tx.send(format!("✓ Proxy at {} is ONLINE and AUTHENTICATED (User/Pass OK)!", target));
                                        } else {
                                            let _ = tx.send("✗ Proxy reached, but authentication was rejected by the server!".to_string());
                                        }
                                    } else {
                                        let _ = tx.send("✗ Proxy requires authentication, but no credentials configured.".to_string());
                                    }
                                } else if resp[1] == socks5::AUTH_NONE {
                                    let _ = tx.send(format!("✓ Proxy at {} is ONLINE (No Authentication required)!", target));
                                } else {
                                    let _ = tx.send(format!("✗ Proxy selected unsupported authentication method code: 0x{:02X}", resp[1]));
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(format!("✗ Could not connect to SOCKS5 proxy at {}: {}", target, e));
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(format!("✗ Failed to resolve proxy address: {}", e));
                }
            }
        });
    }

    fn launch_proxied_app_async(&mut self, app_path: String, app_args: String) {
        let dll_path = match find_hook_dll() {
            Ok(p) => p,
            Err(e) => {
                self.log(&format!("Error: {}", e));
                return;
            }
        };

        self.save_config();

        let canon_cfg = self.config_path.canonicalize().unwrap_or(self.config_path.clone());
        let cfg_str = canon_cfg.to_str().unwrap_or("").to_string();
        let tx = self.log_tx.clone();

        self.log(&format!("Launching application asynchronously: {} {}", app_path, app_args));

        // Spawn background thread so UI never freezes during suspended launch and injection
        std::thread::spawn(move || {
            std::env::set_var("PROXIFY_CONFIG", &cfg_str);

            let mut cmd_str = format!("\"{}\"", app_path);
            if !app_args.trim().is_empty() {
                cmd_str.push(' ');
                cmd_str.push_str(app_args.trim());
            }

            let mut cmd_wide: Vec<u16> = OsStr::new(&cmd_str)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            unsafe {
                let mut startup_info: STARTUPINFOW = core::mem::zeroed();
                startup_info.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
                let mut proc_info: PROCESS_INFORMATION = core::mem::zeroed();

                let ok = CreateProcessW(
                    core::ptr::null(),
                    cmd_wide.as_mut_ptr(),
                    core::ptr::null(),
                    core::ptr::null(),
                    FALSE,
                    CREATE_SUSPENDED,
                    core::ptr::null(),
                    core::ptr::null(),
                    &mut startup_info,
                    &mut proc_info,
                );

                if ok == 0 {
                    let err = std::io::Error::last_os_error();
                    let _ = tx.send(format!("✗ CreateProcessW failed for '{}': {}", app_path, err));
                    return;
                }

                let pid = proc_info.dwProcessId;
                let _ = tx.send(format!("==> Target process created suspended (PID: {}). Injecting hook...", pid));

                match inject_dll(proc_info.hProcess, &dll_path) {
                    Ok(_) => {
                        let _ = tx.send(format!("✓ Hook successfully injected into PID {}! Resuming execution...", pid));
                    }
                    Err(e) => {
                        let _ = tx.send(format!("✗ DLL injection failed for PID {}: {}", pid, e));
                    }
                }

                ResumeThread(proc_info.hThread);
                CloseHandle(proc_info.hThread);
                CloseHandle(proc_info.hProcess);
            }
        });
    }

fn find_matching_pids(processes: &[ProcessItem], app_name: &str, app_path: &str) -> Vec<(u32, String)> {
    let mut matches = Vec::new();
    let name_lower = app_name.to_lowercase();
    let path_file_lower = std::path::Path::new(app_path)
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_else(|| app_path.to_lowercase());

    for proc in processes {
            let p_lower = proc.name.to_lowercase();
            let matches_app = p_lower == name_lower
                || p_lower == path_file_lower
                || (p_lower.ends_with(".exe") && p_lower[..p_lower.len() - 4] == name_lower)
                || (name_lower.ends_with(".exe") && name_lower[..name_lower.len() - 4] == p_lower)
                || (p_lower.ends_with(".exe") && p_lower[..p_lower.len() - 4] == path_file_lower)
                || (path_file_lower.ends_with(".exe") && path_file_lower[..path_file_lower.len() - 4] == p_lower);

            if matches_app {
                matches.push((proc.pid, proc.name.clone()));
            }
        }
        matches
    }

    fn attach_to_pids_async(&mut self, targets: Vec<(u32, String)>) {
        if targets.is_empty() {
            self.log("No matching running processes found to attach.");
            return;
        }

        let dll_path = match find_hook_dll() {
            Ok(p) => p,
            Err(e) => {
                self.log(&format!("Error: {}", e));
                return;
            }
        };

        self.save_config();
        let canon_cfg = self.config_path.canonicalize().unwrap_or(self.config_path.clone());
        let cfg_str = canon_cfg.to_str().unwrap_or("").to_string();
        let tx = self.log_tx.clone();

        let total = targets.len();
        self.log(&format!("Starting batch attach to {} process instance(s)...", total));

        std::thread::spawn(move || {
            std::env::set_var("PROXIFY_CONFIG", &cfg_str);

            let desired_access = PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ;

            let mut success_count = 0;
            for (pid, proc_name) in &targets {
                unsafe {
                    let h_proc = OpenProcess(desired_access, FALSE, *pid);
                    if h_proc.is_null() {
                        let err = std::io::Error::last_os_error();
                        let _ = tx.send(format!("✗ Failed to open PID {} ({}): {}", pid, proc_name, err));
                        continue;
                    }

                    match inject_dll(h_proc, &dll_path) {
                        Ok(_) => {
                            let _ = tx.send(format!("✓ Successfully attached proxy hook to {} (PID {})!", proc_name, pid));
                            success_count += 1;
                        }
                        Err(e) => {
                            let _ = tx.send(format!("✗ Failed injecting into {} (PID {}): {}", proc_name, pid, e));
                        }
                    }
                    CloseHandle(h_proc);
                }
            }

            let _ = tx.send(format!("==> Batch attach completed: {}/{} processes successfully hooked!", success_count, total));
        });
    }

    #[allow(dead_code)]
    fn attach_to_pid_async(&mut self, pid: u32, proc_name: String) {
        self.attach_to_pids_async(vec![(pid, proc_name)]);
    }
}

fn chrono_format_now() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let secs = now % 60;
    let mins = (now / 60) % 60;
    let hours = (now / 3600) % 24;
    format!("{:02}:{:02}:{:02} UTC", hours, mins, secs)
}

fn find_hook_dll() -> Result<PathBuf, String> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("proxify_hook.dll");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    let dev_candidates = [
        PathBuf::from("target/release/proxify_hook.dll"),
        PathBuf::from("target/debug/proxify_hook.dll"),
        PathBuf::from("../target/release/proxify_hook.dll"),
        PathBuf::from("../target/debug/proxify_hook.dll"),
    ];

    for candidate in &dev_candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }

    Err("Could not find proxify_hook.dll. Ensure project is built with `cargo build`.".to_string())
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

    // Strip verbatim UNC prefix "\\?\" which can cause LoadLibraryW to fail in many apps
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
        return Err("GetModuleHandleA kernel32.dll failed".to_string());
    }

    let load_library_name = b"LoadLibraryW\0";
    let load_library_addr = GetProcAddress(h_kernel32, load_library_name.as_ptr());
    if load_library_addr.is_none() {
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        return Err("GetProcAddress LoadLibraryW failed".to_string());
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
        return Err("WaitForSingleObject failed on remote thread".to_string());
    }

    // Check thread exit code = return value of LoadLibraryW!
    let mut exit_code: u32 = 0;
    windows_sys::Win32::System::Threading::GetExitCodeThread(h_thread, &mut exit_code);
    CloseHandle(h_thread);
    VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);

    if exit_code == 0 {
        return Err(format!(
            "LoadLibraryW returned NULL in target process for '{}'. Injection rejected by target process.",
            path_str
        ));
    }

    Ok(())
}

fn list_running_processes() -> Vec<ProcessItem> {
    let mut procs = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return procs;
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

                if entry.th32ProcessID > 4 && !name.is_empty() {
                    procs.push(ProcessItem {
                        pid: entry.th32ProcessID,
                        name,
                    });
                }

                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
    procs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    procs
}

impl eframe::App for ProxifyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain asynchronous background task logs
        while let Ok(msg) = self.log_rx.try_recv() {
            self.log(&msg);
            if msg.starts_with('✓') {
                self.test_status = Some("Online".to_string());
                self.test_success = true;
            } else if msg.starts_with('✗') {
                self.test_status = Some("Failed".to_string());
                self.test_success = false;
            }
        }

        // Handle Global Keyboard Shortcuts
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::S)) {
            self.save_config();
        }
        if ctx.input(|i| (i.modifiers.ctrl && i.key_pressed(egui::Key::R)) || i.key_pressed(egui::Key::F5)) {
            self.refresh_processes();
            self.log("Refreshed running processes list.");
        }
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::T)) {
            self.test_proxy_connection();
        }

        // Top Menu / Header Panel
        egui::TopBottomPanel::top("header_panel").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("🛡 Proxify-RS");
                ui.label(egui::RichText::new("User-Mode App Proxy Manager").color(egui::Color32::GRAY));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("💾 Save (Ctrl+S)").clicked() {
                        self.save_config();
                    }

                    if let Some(ref status) = self.test_status {
                        let color = if self.test_success {
                            egui::Color32::from_rgb(46, 204, 113)
                        } else {
                            egui::Color32::from_rgb(231, 76, 60)
                        };
                        ui.colored_label(color, format!("● {}", status));
                    }

                    if ui.button("🔍 Test Proxy (Ctrl+T)").clicked() {
                        self.test_proxy_connection();
                    }

                    ui.label(format!("Proxy: {}:{}", self.config.proxy_host, self.config.proxy_port));
                });
            });
            ui.add_space(4.0);

            // Navigation Tab bar
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, ActiveTab::Applications, "📦 Applications");
                ui.selectable_value(&mut self.active_tab, ActiveTab::Rules, "🌐 Routing Rules");
                ui.selectable_value(&mut self.active_tab, ActiveTab::RunningProcesses, "⚡ Running Processes");
                ui.selectable_value(&mut self.active_tab, ActiveTab::Settings, "⚙ Settings");
            });
            ui.add_space(4.0);
        });

        // Bottom log panel
        egui::TopBottomPanel::bottom("log_panel")
            .resizable(true)
            .default_height(110.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Activity Log").strong());
                    if ui.button("Clear Log").clicked() {
                        self.logs.clear();
                    }
                });
                egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                    for entry in &self.logs {
                        let color = if entry.contains('✓') || entry.contains("successfully") {
                            egui::Color32::from_rgb(46, 204, 113)
                        } else if entry.contains('✗') || entry.contains("failed") || entry.contains("Error") {
                            egui::Color32::from_rgb(231, 76, 60)
                        } else {
                            ui.style().visuals.text_color()
                        };
                        ui.colored_label(color, egui::RichText::new(entry).monospace().size(11.0));
                    }
                });
            });

        // Main Central Content Area
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.active_tab {
                ActiveTab::Applications => self.render_applications_tab(ui),
                ActiveTab::Rules => self.render_rules_tab(ui),
                ActiveTab::RunningProcesses => self.render_processes_tab(ui),
                ActiveTab::Settings => self.render_settings_tab(ui, ctx),
            }
        });
    }
}

impl ProxifyApp {
    fn render_applications_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Control Proxified Applications");
        ui.label("Configure desktop applications to intercept and route through your proxy without admin rights.");
        ui.add_space(8.0);

        // Add application box with native file picker
        ui.group(|ui| {
            ui.label(egui::RichText::new("Add Application").strong());
            ui.horizontal(|ui| {
                ui.label("Name:");
                ui.add(egui::TextEdit::singleline(&mut self.new_app_name).hint_text("e.g. Telegram"));

                ui.label("Executable Path:");
                ui.add(egui::TextEdit::singleline(&mut self.new_app_path).hint_text("C:\\Path\\To\\App.exe"));

                // U1: Native File Picker using rfd
                if ui.button("📁 Browse...").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Select Application Executable")
                        .add_filter("Executable Files", &["exe", "bat", "cmd"])
                        .pick_file()
                    {
                        let path_str = path.to_string_lossy().to_string();
                        if self.new_app_name.trim().is_empty() {
                            if let Some(stem) = path.file_stem() {
                                self.new_app_name = stem.to_string_lossy().to_string();
                            }
                        }
                        self.new_app_path = path_str;
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.label("Arguments (optional):");
                ui.add(egui::TextEdit::singleline(&mut self.new_app_args).hint_text("e.g. --profile work"));

                if ui.button("➕ Add App to List").clicked() {
                    if !self.new_app_path.trim().is_empty() {
                        let name = if self.new_app_name.trim().is_empty() {
                            self.new_app_path.clone()
                        } else {
                            self.new_app_name.clone()
                        };
                        self.config.apps.push(AppConfig {
                            name,
                            path: self.new_app_path.trim().to_string(),
                            args: self.new_app_args.trim().to_string(),
                            enabled: true,
                        });
                        self.new_app_name.clear();
                        self.new_app_path.clear();
                        self.new_app_args.clear();
                        self.save_config();
                    }
                }
            });
        });

        ui.add_space(8.0);

        // Configured Apps Table
        let mut to_launch: Option<(String, String)> = None;
        let mut to_attach_batch: Option<Vec<(u32, String)>> = None;
        let mut to_remove: Option<usize> = None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            for (idx, app) in self.config.apps.iter_mut().enumerate() {
                let running_targets = Self::find_matching_pids(&self.processes, &app.name, &app.path);
                let run_count = running_targets.len();

                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut app.enabled, "");
                        ui.label(egui::RichText::new(&app.name).strong());
                        ui.label(format!("Path: {}", app.path));
                        if !app.args.is_empty() {
                            ui.label(format!("Args: {}", app.args));
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            // Confirm-on-delete check
                            if self.confirm_delete_app == Some(idx) {
                                if ui.button(egui::RichText::new("Yes, Delete").color(egui::Color32::RED)).clicked() {
                                    to_remove = Some(idx);
                                    self.confirm_delete_app = None;
                                }
                                if ui.button("Cancel").clicked() {
                                    self.confirm_delete_app = None;
                                }
                            } else {
                                if ui.button("🗑 Remove").clicked() {
                                    self.confirm_delete_app = Some(idx);
                                }
                            }

                            if ui.button(egui::RichText::new("🚀 Launch Proxified").color(egui::Color32::from_rgb(46, 204, 113))).clicked() {
                                to_launch = Some((app.path.clone(), app.args.clone()));
                            }

                            if run_count > 0 {
                                let btn_text = format!("⚡ Attach All ({} running)", run_count);
                                if ui.button(egui::RichText::new(btn_text).color(egui::Color32::from_rgb(52, 152, 219))).clicked() {
                                    to_attach_batch = Some(running_targets);
                                }
                            } else {
                                ui.add_enabled_ui(false, |ui| {
                                    let _ = ui.button("⚡ Not running");
                                });
                            }
                        });
                    });
                });
            }
        });

        if let Some(idx) = to_remove {
            self.config.apps.remove(idx);
            self.save_config();
        }

        if let Some((path, args)) = to_launch {
            self.launch_proxied_app_async(path, args);
        }

        if let Some(targets) = to_attach_batch {
            self.attach_to_pids_async(targets);
        }
    }

    fn render_rules_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Address & Port Routing Rules");
        ui.label("Define which target IP addresses, subnets, and ports route through proxy vs. connect direct.");
        ui.add_space(8.0);

        // Default Action selection
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Default Action (for unmatched traffic):").strong());
            ui.radio_value(&mut self.config.default_action, RuleAction::Direct, "Direct (Bypass Proxy)");
            ui.radio_value(&mut self.config.default_action, RuleAction::Proxy, "Proxy (Route through Proxy)");
        });

        ui.add_space(8.0);

        // Add Rule Form
        ui.group(|ui| {
            ui.label(egui::RichText::new("Add New Routing Rule").strong());
            ui.horizontal(|ui| {
                ui.label("Rule Name:");
                ui.add(egui::TextEdit::singleline(&mut self.new_rule_name).hint_text("e.g. Work Subnet"));

                ui.label("Target IPs / Subnets:");
                ui.add(egui::TextEdit::singleline(&mut self.new_rule_ips).hint_text("198.51.100.*, 203.0.113.10"));
            });

            ui.horizontal(|ui| {
                ui.label("Target Ports:");
                ui.add(egui::TextEdit::singleline(&mut self.new_rule_ports).hint_text("80, 443 (blank = any)"));

                ui.label("Target Hosts:");
                ui.add(egui::TextEdit::singleline(&mut self.new_rule_hosts).hint_text("*.corp.example.com"));

                ui.label("Action:");
                egui::ComboBox::from_id_salt("rule_action_combo")
                    .selected_text(match self.new_rule_action {
                        RuleAction::Proxy => "Proxy",
                        RuleAction::Direct => "Direct",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.new_rule_action, RuleAction::Proxy, "Proxy");
                        ui.selectable_value(&mut self.new_rule_action, RuleAction::Direct, "Direct");
                    });

                if ui.button("➕ Add Rule").clicked() {
                    if !self.new_rule_name.trim().is_empty() {
                        let ips: Vec<String> = self.new_rule_ips
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        let ports: Vec<u16> = self.new_rule_ports
                            .split(',')
                            .filter_map(|s| s.trim().parse::<u16>().ok())
                            .collect();
                        let hosts: Vec<String> = self.new_rule_hosts
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();

                        self.config.rules.push(Rule {
                            name: self.new_rule_name.trim().to_string(),
                            action: self.new_rule_action,
                            target_apps: vec![],
                            target_ips: ips,
                            target_ports: ports,
                            target_hosts: hosts,
                        });

                        self.new_rule_name.clear();
                        self.new_rule_ips.clear();
                        self.new_rule_ports.clear();
                        self.new_rule_hosts.clear();
                        self.save_config();
                    }
                }
            });
        });

        ui.add_space(8.0);

        // Search / Filter Rules box
        ui.horizontal(|ui| {
            ui.label("Filter Rules:");
            ui.add(egui::TextEdit::singleline(&mut self.rule_search).hint_text("Search by name, IP, port, host..."));
            if ui.button("Clear").clicked() {
                self.rule_search.clear();
            }
        });

        ui.add_space(4.0);

        // Rules List
        let mut remove_rule_idx: Option<usize> = None;
        let query = self.rule_search.to_lowercase();

        egui::ScrollArea::vertical().show(ui, |ui| {
            for (idx, rule) in self.config.rules.iter_mut().enumerate() {
                if !query.is_empty() {
                    let matches_name = rule.name.to_lowercase().contains(&query);
                    let matches_ips = rule.target_ips.iter().any(|ip| ip.to_lowercase().contains(&query));
                    let matches_hosts = rule.target_hosts.iter().any(|h| h.to_lowercase().contains(&query));
                    if !matches_name && !matches_ips && !matches_hosts {
                        continue;
                    }
                }

                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        let action_color = match rule.action {
                            RuleAction::Proxy => egui::Color32::from_rgb(46, 204, 113),
                            RuleAction::Direct => egui::Color32::from_rgb(52, 152, 219),
                        };
                        ui.colored_label(action_color, format!("[{:?}]", rule.action));
                        ui.label(egui::RichText::new(&rule.name).strong());

                        if !rule.target_ips.is_empty() {
                            ui.label(format!("IPs: {:?}", rule.target_ips));
                        }
                        if !rule.target_ports.is_empty() {
                            ui.label(format!("Ports: {:?}", rule.target_ports));
                        }
                        if !rule.target_hosts.is_empty() {
                            ui.label(format!("Hosts: {:?}", rule.target_hosts));
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if self.confirm_delete_rule == Some(idx) {
                                if ui.button(egui::RichText::new("Yes, Delete").color(egui::Color32::RED)).clicked() {
                                    remove_rule_idx = Some(idx);
                                    self.confirm_delete_rule = None;
                                }
                                if ui.button("Cancel").clicked() {
                                    self.confirm_delete_rule = None;
                                }
                            } else {
                                if ui.button("🗑 Delete").clicked() {
                                    self.confirm_delete_rule = Some(idx);
                                }
                            }
                        });
                    });
                });
            }
        });

        if let Some(idx) = remove_rule_idx {
            self.config.rules.remove(idx);
            self.save_config();
        }
    }

    fn render_processes_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Live Process Monitor");
        ui.label("Attach proxy hooks directly into running applications without restarting them.");
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("Search Process:");
            let search_changed = ui.add(egui::TextEdit::singleline(&mut self.proc_search).hint_text("Type name or PID...")).changed();
            if search_changed {
                // Keep UI snappy
            }

            if ui.button("🔄 Refresh (F5 / Ctrl+R)").clicked() {
                self.refresh_processes();
            }
            ui.label(format!("Found: {} running user processes", self.processes.len()));
        });

        ui.add_space(4.0);

        let search = self.proc_search.to_lowercase();
        let mut grouped: std::collections::BTreeMap<String, Vec<u32>> = std::collections::BTreeMap::new();

        for proc in &self.processes {
            let pid_str = proc.pid.to_string();
            if !search.is_empty() && !proc.name.to_lowercase().contains(&search) && !pid_str.contains(&search) {
                continue;
            }
            grouped.entry(proc.name.clone()).or_default().push(proc.pid);
        }

        let total_matched_pids: usize = grouped.values().map(|v| v.len()).sum();
        let mut attach_batch: Option<Vec<(u32, String)>> = None;

        if !search.is_empty() && total_matched_pids > 0 {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("Matches: {} processes across {} applications", total_matched_pids, grouped.len())).color(egui::Color32::from_rgb(241, 196, 15)));
                if ui.button(egui::RichText::new(format!("⚡ Attach All Filtered ({} PIDs)", total_matched_pids)).color(egui::Color32::from_rgb(52, 152, 219))).clicked() {
                    let mut targets = Vec::new();
                    for (name, pids) in &grouped {
                        for p in pids {
                            targets.push((*p, name.clone()));
                        }
                    }
                    attach_batch = Some(targets);
                }
            });
            ui.add_space(4.0);
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            for (name, pids) in &grouped {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(name).strong());
                        let count = pids.len();
                        if count > 1 {
                            ui.colored_label(egui::Color32::from_rgb(241, 196, 15), format!("({} instances)", count));
                        }

                        let pids_preview = if count <= 4 {
                            pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
                        } else {
                            format!("{}, ... ({} total)", pids[..3].iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "), count)
                        };
                        ui.label(egui::RichText::new(format!("PIDs: [{}]", pids_preview)).monospace().color(egui::Color32::GRAY));

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if count > 1 {
                                let btn_text = format!("⚡ Attach All ({} PIDs)", count);
                                if ui.button(egui::RichText::new(btn_text).color(egui::Color32::from_rgb(52, 152, 219))).clicked() {
                                    let targets = pids.iter().map(|p| (*p, name.clone())).collect();
                                    attach_batch = Some(targets);
                                }
                            } else if let Some(&single_pid) = pids.first() {
                                if ui.button("⚡ Attach Proxy").clicked() {
                                    attach_batch = Some(vec![(single_pid, name.clone())]);
                                }
                            }
                        });
                    });
                });
            }
        });

        if let Some(targets) = attach_batch {
            self.attach_to_pids_async(targets);
        }
    }

    fn render_settings_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.heading("Settings & Proxy Configuration");
        ui.add_space(8.0);

        // SOCKS5 Configuration Box
        ui.group(|ui| {
            ui.label(egui::RichText::new("SOCKS5 Proxy Server").strong());
            ui.horizontal(|ui| {
                ui.label("Host:");
                ui.text_edit_singleline(&mut self.config.proxy_host);

                ui.label("Port:");
                let mut port_str = self.config.proxy_port.to_string();
                if ui.text_edit_singleline(&mut port_str).changed() {
                    if let Ok(p) = port_str.parse::<u16>() {
                        self.config.proxy_port = p;
                    }
                }
            });

            ui.add_space(4.0);
            ui.label(egui::RichText::new("Optional Authentication (RFC 1929)").strong());
            ui.horizontal(|ui| {
                ui.label("Username:");
                let mut user = self.config.proxy_username.clone().unwrap_or_default();
                if ui.add(egui::TextEdit::singleline(&mut user).hint_text("Leave blank if none")).changed() {
                    self.config.proxy_username = if user.trim().is_empty() { None } else { Some(user.trim().to_string()) };
                }

                ui.label("Password:");
                let mut pass = self.config.proxy_password.clone().unwrap_or_default();
                if ui.add(egui::TextEdit::singleline(&mut pass).password(true).hint_text("Leave blank if none")).changed() {
                    self.config.proxy_password = if pass.trim().is_empty() { None } else { Some(pass.trim().to_string()) };
                }
            });

            ui.add_space(6.0);
            if ui.button("🔍 Test Proxy Connection").clicked() {
                self.test_proxy_connection();
            }
        });

        ui.add_space(8.0);

        // UI Appearance Box
        ui.group(|ui| {
            ui.label(egui::RichText::new("Appearance & Theme").strong());
            ui.horizontal(|ui| {
                if ui.radio(self.is_dark_theme, "🌙 Dark Theme").clicked() {
                    self.is_dark_theme = true;
                    ctx.set_visuals(egui::Visuals::dark());
                    self.save_config();
                }
                if ui.radio(!self.is_dark_theme, "☀️ Light Theme").clicked() {
                    self.is_dark_theme = false;
                    ctx.set_visuals(egui::Visuals::light());
                    self.save_config();
                }
            });
        });

        ui.add_space(8.0);

        // Shortcuts Summary Box
        ui.group(|ui| {
            ui.label(egui::RichText::new("Keyboard Shortcuts").strong());
            ui.label("• Ctrl+S: Save configuration to proxify.json");
            ui.label("• Ctrl+R / F5: Refresh active processes list");
            ui.label("• Ctrl+T: Test connection to SOCKS5 proxy server");
        });

        ui.add_space(8.0);
        if ui.button("💾 Save All Settings").clicked() {
            self.save_config();
        }
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 640.0])
            .with_min_inner_size([680.0, 480.0])
            .with_title("Proxify-RS — User-Mode App Proxy Manager"),
        ..Default::default()
    };

    eframe::run_native(
        "Proxify-RS",
        native_options,
        Box::new(|cc| Ok(Box::new(ProxifyApp::new(cc)))),
    )
}
