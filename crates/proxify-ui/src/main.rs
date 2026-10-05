use eframe::egui;
use proxify_core::{AppConfig, ProxyConfig, Rule, RuleAction, socks5};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
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

    // Process monitor
    processes: Vec<ProcessItem>,
    proc_search: String,

    // Log messages
    logs: Vec<String>,
}

impl ProxifyApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let config_path = PathBuf::from("proxify.json");
        let config = if config_path.exists() {
            fs::read_to_string(&config_path)
                .ok()
                .and_then(|c| serde_json::from_str(&c).ok())
                .unwrap_or_default()
        } else {
            ProxyConfig::default()
        };

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
            processes: Vec::new(),
            proc_search: String::new(),
            logs: vec!["Proxify UI initialized. Ready to control apps and routes.".to_string()],
        };

        app.refresh_processes();
        app
    }

    fn log(&mut self, msg: &str) {
        let time_str = chrono_format_now();
        self.logs.push(format!("[{}] {}", time_str, msg));
        if self.logs.len() > 100 {
            self.logs.remove(0);
        }
    }

    fn save_config(&mut self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.config) {
            if let Err(e) = fs::write(&self.config_path, json) {
                self.log(&format!("Failed to save config: {}", e));
            } else {
                self.log(&format!("Saved configuration to {}", self.config_path.display()));
            }
        }
    }

    fn refresh_processes(&mut self) {
        self.processes = list_running_processes();
    }

    fn test_proxy_connection(&mut self) {
        let target = format!("{}:{}", self.config.proxy_host, self.config.proxy_port);
        match target.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                        Ok(mut stream) => {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                            let greeting = socks5::build_greeting();
                            let _ = stream.write_all(&greeting);

                            let mut resp = [0u8; 2];
                            if stream.read_exact(&mut resp).is_ok()
                                && socks5::verify_greeting_response(&resp)
                            {
                                self.test_status = Some("Proxy Online & Ready (Handshake OK)".to_string());
                                self.test_success = true;
                                self.log(&format!("SOCKS5 proxy at {} is reachable and responsive.", target));
                            } else {
                                self.test_status = Some("Proxy reachable, handshake rejected".to_string());
                                self.test_success = false;
                                self.log("Proxy reachable but handshake failed.");
                            }
                        }
                        Err(e) => {
                            self.test_status = Some(format!("Connection Failed: {}", e));
                            self.test_success = false;
                            self.log(&format!("Could not connect to SOCKS5 proxy: {}", e));
                        }
                    }
                }
            }
            Err(e) => {
                self.test_status = Some(format!("Invalid Address: {}", e));
                self.test_success = false;
            }
        }
    }

    fn launch_proxied_app(&mut self, app_path: &str, app_args: &str) {
        let dll_path = match find_hook_dll() {
            Ok(p) => p,
            Err(e) => {
                self.log(&format!("Error: {}", e));
                return;
            }
        };

        // Ensure config is saved
        self.save_config();

        let canon_cfg = self.config_path.canonicalize().unwrap_or(self.config_path.clone());
        std::env::set_var("PROXIFY_CONFIG", canon_cfg.to_str().unwrap_or(""));

        let mut cmd_str = format!("\"{}\"", app_path);
        if !app_args.trim().is_empty() {
            cmd_str.push(' ');
            cmd_str.push_str(app_args.trim());
        }

        self.log(&format!("Spawning suspended process: {}", cmd_str));

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
                self.log(&format!("CreateProcessW failed for {}: {}", app_path, err));
                return;
            }

            let pid = proc_info.dwProcessId;
            self.log(&format!("Process created with PID {}. Injecting hook...", pid));

            if let Err(e) = inject_dll(proc_info.hProcess, &dll_path) {
                self.log(&format!("DLL injection error: {}", e));
            } else {
                self.log(&format!("Successfully hooked process PID {}! Resuming execution...", pid));
            }

            ResumeThread(proc_info.hThread);
            CloseHandle(proc_info.hThread);
            CloseHandle(proc_info.hProcess);
        }
    }

    fn attach_to_pid(&mut self, pid: u32, proc_name: &str) {
        let dll_path = match find_hook_dll() {
            Ok(p) => p,
            Err(e) => {
                self.log(&format!("Error: {}", e));
                return;
            }
        };

        self.save_config();
        let canon_cfg = self.config_path.canonicalize().unwrap_or(self.config_path.clone());
        std::env::set_var("PROXIFY_CONFIG", canon_cfg.to_str().unwrap_or(""));

        let desired_access = PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ;

        unsafe {
            let h_proc = OpenProcess(desired_access, FALSE, pid);
            if h_proc.is_null() {
                let err = std::io::Error::last_os_error();
                self.log(&format!("Failed to open PID {} ({}): {}", pid, proc_name, err));
                return;
            }

            match inject_dll(h_proc, &dll_path) {
                Ok(_) => {
                    self.log(&format!("Successfully attached proxy hook to {} (PID {})!", proc_name, pid));
                }
                Err(e) => {
                    self.log(&format!("Failed injecting into {} (PID {}): {}", proc_name, pid, e));
                }
            }
            CloseHandle(h_proc);
        }
    }
}

fn chrono_format_now() -> String {
    // Simple timestamp without external chrono dependency
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
        return Err("VirtualAllocEx failed in target process".to_string());
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
        return Err("WriteProcessMemory failed".to_string());
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
        return Err("CreateRemoteThread failed".to_string());
    }

    let wait_res = WaitForSingleObject(h_thread, 10000);
    CloseHandle(h_thread);
    VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);

    if wait_res == WAIT_FAILED {
        return Err("WaitForSingleObject failed".to_string());
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
        // Top Menu / Header
        egui::TopBottomPanel::top("header_panel").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("🛡 Proxify-RS");
                ui.label(egui::RichText::new("User-Mode Application Proxy Manager").color(egui::Color32::GRAY));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("💾 Save Config").clicked() {
                        self.save_config();
                    }

                    if let Some(ref status) = self.test_status {
                        let color = if self.test_success {
                            egui::Color32::from_rgb(46, 204, 113)
                        } else {
                            egui::Color32::from_rgb(231, 76, 60)
                        };
                        ui.colored_label(color, status);
                    }

                    if ui.button("🔍 Test Proxy").clicked() {
                        self.test_proxy_connection();
                    }

                    ui.label(format!("Proxy: {}:{}", self.config.proxy_host, self.config.proxy_port));
                });
            });
            ui.add_space(4.0);

            // Tab bar
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
            .default_height(100.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Activity Log").strong());
                    if ui.button("Clear").clicked() {
                        self.logs.clear();
                    }
                });
                egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                    for entry in &self.logs {
                        ui.label(egui::RichText::new(entry).monospace().size(11.0));
                    }
                });
            });

        // Main Central Content
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.active_tab {
                ActiveTab::Applications => self.render_applications_tab(ui),
                ActiveTab::Rules => self.render_rules_tab(ui),
                ActiveTab::RunningProcesses => self.render_processes_tab(ui),
                ActiveTab::Settings => self.render_settings_tab(ui),
            }
        });
    }
}

impl ProxifyApp {
    fn render_applications_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Control Proxified Applications");
        ui.label("Configure target desktop applications to intercept and route through your proxy.");
        ui.add_space(8.0);

        // Add application box
        ui.group(|ui| {
            ui.label(egui::RichText::new("Add Application").strong());
            ui.horizontal(|ui| {
                ui.label("Name:");
                ui.text_edit_singleline(&mut self.new_app_name);
                ui.label("Executable Path:");
                ui.text_edit_singleline(&mut self.new_app_path);
                ui.label("Args:");
                ui.text_edit_singleline(&mut self.new_app_args);

                if ui.button("➕ Add App").clicked() {
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

        // Apps List Table
        let mut to_launch: Option<(String, String)> = None;
        let mut to_remove: Option<usize> = None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            for (idx, app) in self.config.apps.iter_mut().enumerate() {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut app.enabled, "");
                        ui.label(egui::RichText::new(&app.name).strong());
                        ui.label(format!("Path: {}", app.path));
                        if !app.args.is_empty() {
                            ui.label(format!("Args: {}", app.args));
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("🗑 Remove").clicked() {
                                to_remove = Some(idx);
                            }

                            if ui.button(egui::RichText::new("🚀 Launch Proxified").color(egui::Color32::from_rgb(46, 204, 113))).clicked() {
                                to_launch = Some((app.path.clone(), app.args.clone()));
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
            self.launch_proxied_app(&path, &args);
        }
    }

    fn render_rules_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Address & Port Routing Rules");
        ui.label("Control which target IP addresses, subnets, and ports go through the proxy vs. direct.");
        ui.add_space(8.0);

        // Default Action Selection
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Default Action for unmatched traffic:").strong());
            ui.radio_value(&mut self.config.default_action, RuleAction::Direct, "Direct (Bypass Proxy)");
            ui.radio_value(&mut self.config.default_action, RuleAction::Proxy, "Proxy (Route through Proxy)");
        });

        ui.add_space(8.0);

        // Add Rule Section
        ui.group(|ui| {
            ui.label(egui::RichText::new("Add New Routing Rule").strong());
            ui.horizontal(|ui| {
                ui.label("Rule Name:");
                ui.text_edit_singleline(&mut self.new_rule_name);
                ui.label("Target IPs/Subnets (comma separated):");
                ui.text_edit_singleline(&mut self.new_rule_ips);
            });
            ui.horizontal(|ui| {
                ui.label("Target Ports (e.g. 80, 443):");
                ui.text_edit_singleline(&mut self.new_rule_ports);
                ui.label("Domains (e.g. *.example.com):");
                ui.text_edit_singleline(&mut self.new_rule_hosts);
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

        // Rules List
        let mut remove_idx: Option<usize> = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (idx, rule) in self.config.rules.iter_mut().enumerate() {
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
                            if ui.button("🗑 Delete").clicked() {
                                remove_idx = Some(idx);
                            }
                        });
                    });
                });
            }
        });

        if let Some(idx) = remove_idx {
            self.config.rules.remove(idx);
            self.save_config();
        }
    }

    fn render_processes_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Live Process Monitor");
        ui.label("Attach proxy hooks directly into running applications owned by your user session.");
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("Search Process:");
            ui.text_edit_singleline(&mut self.proc_search);
            if ui.button("🔄 Refresh Processes").clicked() {
                self.refresh_processes();
            }
            ui.label(format!("Found: {} processes", self.processes.len()));
        });

        ui.add_space(8.0);

        let search = self.proc_search.to_lowercase();
        let mut attach_target: Option<(u32, String)> = None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            for proc in &self.processes {
                if !search.is_empty() && !proc.name.to_lowercase().contains(&search) {
                    continue;
                }

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!("PID: {:<6}", proc.pid)).monospace());
                    ui.label(egui::RichText::new(&proc.name).strong());

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("⚡ Attach Proxy").clicked() {
                            attach_target = Some((proc.pid, proc.name.clone()));
                        }
                    });
                });
                ui.separator();
            }
        });

        if let Some((pid, name)) = attach_target {
            self.attach_to_pid(pid, &name);
        }
    }

    fn render_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Proxy Server Configuration");
        ui.add_space(8.0);

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
            if ui.button("Save Settings").clicked() {
                self.save_config();
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([880.0, 620.0])
            .with_min_inner_size([650.0, 450.0])
            .with_title("Proxify-RS — User-Mode App Proxy Manager"),
        ..Default::default()
    };

    eframe::run_native(
        "Proxify-RS",
        native_options,
        Box::new(|cc| Ok(Box::new(ProxifyApp::new(cc)))),
    )
}
