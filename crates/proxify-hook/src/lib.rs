use minhook::MinHook;
use proxify_core::{ProxyConfig, socks5};
use std::ffi::c_void;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{BOOL, HANDLE};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, FD_SET, SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR,
    SOL_SOCKET, SO_ERROR, TIMEVAL, WSAECONNREFUSED, WSAEWOULDBLOCK,
    WSAGetLastError, WSASetLastError, getsockopt, recv, select, send,
};
use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringA;
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

type ConnectFn = unsafe extern "system" fn(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32;
type WSAConnectFn = unsafe extern "system" fn(
    s: SOCKET,
    name: *const SOCKADDR,
    namelen: i32,
    lp_caller_data: *mut c_void,
    lp_callee_data: *mut c_void,
    lp_sqos: *mut c_void,
    lp_gqos: *mut c_void,
) -> i32;

static ORIGINAL_CONNECT: OnceLock<ConnectFn> = OnceLock::new();
static ORIGINAL_WSACONNECT: OnceLock<WSAConnectFn> = OnceLock::new();
static CONFIG: OnceLock<ProxyConfig> = OnceLock::new();
static HOOK_INITIALIZED: AtomicBool = AtomicBool::new(false);

fn log_msg(msg: &str) {
    if std::env::var("PROXIFY_DEBUG").is_ok() {
        eprintln!("[proxify-hook] {}", msg);
    }
    let formatted = format!("[proxify-hook] {}\n\0", msg);
    unsafe {
        OutputDebugStringA(formatted.as_ptr());
    }
}

fn load_config() -> ProxyConfig {
    if let Ok(path_str) = std::env::var("PROXIFY_CONFIG") {
        if let Ok(content) = fs::read_to_string(&path_str) {
            if let Ok(cfg) = serde_json::from_str::<ProxyConfig>(&content) {
                log_msg(&format!("Loaded configuration from PROXIFY_CONFIG: {}", path_str));
                return cfg;
            }
        }
    }

    if let Ok(content) = fs::read_to_string("proxify.json") {
        if let Ok(cfg) = serde_json::from_str::<ProxyConfig>(&content) {
            log_msg("Loaded configuration from ./proxify.json");
            return cfg;
        }
    }

    if let Ok(appdata) = std::env::var("APPDATA") {
        let p = PathBuf::from(appdata).join("proxify").join("config.json");
        if let Ok(content) = fs::read_to_string(&p) {
            if let Ok(cfg) = serde_json::from_str::<ProxyConfig>(&content) {
                log_msg(&format!("Loaded configuration from {}", p.display()));
                return cfg;
            }
        }
    }

    log_msg("Using default proxy configuration (127.0.0.1:1080)");
    ProxyConfig::default()
}

unsafe fn wait_socket_ready(s: SOCKET, for_read: bool, timeout_ms: u32) -> Result<(), i32> {
    let mut fds: FD_SET = core::mem::zeroed();
    fds.fd_count = 1;
    fds.fd_array[0] = s;

    let mut err_fds: FD_SET = core::mem::zeroed();
    err_fds.fd_count = 1;
    err_fds.fd_array[0] = s;

    let timeout = TIMEVAL {
        tv_sec: (timeout_ms / 1000) as i32,
        tv_usec: ((timeout_ms % 1000) * 1000) as i32,
    };

    let (read_ptr, write_ptr) = if for_read {
        (&mut fds as *mut _, core::ptr::null_mut())
    } else {
        (core::ptr::null_mut(), &mut fds as *mut _)
    };

    let res = select(0, read_ptr, write_ptr, &mut err_fds as *mut _, &timeout);
    if res <= 0 {
        return Err(WSAGetLastError());
    }

    if err_fds.fd_count > 0 {
        let mut err_code: i32 = 0;
        let mut len = core::mem::size_of::<i32>() as i32;
        getsockopt(
            s,
            SOL_SOCKET,
            SO_ERROR,
            &mut err_code as *mut _ as *mut _,
            &mut len,
        );
        return Err(if err_code != 0 { err_code } else { WSAECONNREFUSED as i32 });
    }

    Ok(())
}

unsafe fn send_all(s: SOCKET, mut buf: &[u8]) -> Result<(), i32> {
    while !buf.is_empty() {
        let sent = send(s, buf.as_ptr(), buf.len() as i32, 0);
        if sent == SOCKET_ERROR {
            let err = WSAGetLastError();
            if err == WSAEWOULDBLOCK as i32 {
                wait_socket_ready(s, false, 5000)?;
                continue;
            }
            return Err(err);
        }
        if sent <= 0 {
            return Err(WSAECONNREFUSED as i32);
        }
        buf = &buf[sent as usize..];
    }
    Ok(())
}

unsafe fn recv_exact(s: SOCKET, buf: &mut [u8]) -> Result<(), i32> {
    let mut offset = 0;
    while offset < buf.len() {
        let n = recv(
            s,
            buf.as_mut_ptr().add(offset),
            (buf.len() - offset) as i32,
            0,
        );
        if n == SOCKET_ERROR {
            let err = WSAGetLastError();
            if err == WSAEWOULDBLOCK as i32 {
                wait_socket_ready(s, true, 5000)?;
                continue;
            }
            return Err(err);
        }
        if n <= 0 {
            return Err(WSAECONNREFUSED as i32);
        }
        offset += n as usize;
    }
    Ok(())
}

unsafe fn perform_socks5_handshake(
    s: SOCKET,
    target_ip: [u8; 4],
    target_port: u16,
) -> Result<(), i32> {
    // 1. Send client greeting: SOCKS5, 1 auth method, NO AUTH (0x00)
    let greeting = socks5::build_greeting();
    send_all(s, &greeting)?;

    // 2. Expect server greeting response: [0x05, 0x00]
    let mut greet_resp = [0u8; 2];
    recv_exact(s, &mut greet_resp)?;
    if !socks5::verify_greeting_response(&greet_resp) {
        log_msg("SOCKS5 greeting response rejected or requires authentication");
        return Err(WSAECONNREFUSED as i32);
    }

    // 3. Send SOCKS5 CONNECT command for target IPv4
    let connect_req = socks5::build_connect_ipv4(target_ip, target_port);
    send_all(s, &connect_req)?;

    // 4. Read response header: [VER, REP, RSV, ATYP]
    let mut resp_header = [0u8; 4];
    recv_exact(s, &mut resp_header)?;
    if resp_header[0] != socks5::SOCKS_VERSION || resp_header[1] != socks5::REP_SUCCESS {
        log_msg(&format!("SOCKS5 connect rejected with status code: {}", resp_header[1]));
        return Err(WSAECONNREFUSED as i32);
    }

    // 5. Drain the bound address based on ATYP
    match resp_header[3] {
        socks5::ATYP_IPV4 => {
            let mut drain = [0u8; 6]; // 4 bytes IP + 2 bytes port
            recv_exact(s, &mut drain)?;
        }
        socks5::ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            recv_exact(s, &mut len)?;
            let mut drain = vec![0u8; len[0] as usize + 2];
            recv_exact(s, &mut drain)?;
        }
        socks5::ATYP_IPV6 => {
            let mut drain = [0u8; 18]; // 16 bytes IP + 2 bytes port
            recv_exact(s, &mut drain)?;
        }
        _ => return Err(WSAECONNREFUSED as i32),
    }

    Ok(())
}

unsafe fn handle_proxy_connect(
    s: SOCKET,
    name: *const SOCKADDR,
    namelen: i32,
    original_fn: ConnectFn,
) -> i32 {
    if name.is_null() || namelen < core::mem::size_of::<SOCKADDR_IN>() as i32 {
        return original_fn(s, name, namelen);
    }

    let sa_family = (*name).sa_family;
    if sa_family as u32 != AF_INET as u32 {
        return original_fn(s, name, namelen);
    }

    let name_in = name as *const SOCKADDR_IN;
    let s_addr = (*name_in).sin_addr.S_un.S_addr;
    let target_ip_bytes = s_addr.to_ne_bytes();
    let target_port = u16::from_be((*name_in).sin_port);
    let target_ip = Ipv4Addr::from(target_ip_bytes);
    let target_ip_str = target_ip.to_string();

    let cfg = CONFIG.get_or_init(load_config);

    if !cfg.should_proxy_ip(&target_ip_str, target_port) {
        log_msg(&format!("DIRECT connection to {}:{}", target_ip_str, target_port));
        return original_fn(s, name, namelen);
    }

    log_msg(&format!(
        "PROXYING connection to {}:{} via SOCKS5 proxy {}:{}",
        target_ip_str, target_port, cfg.proxy_host, cfg.proxy_port
    ));

    // Prepare proxy address
    let proxy_ip: Ipv4Addr = cfg.proxy_host.parse().unwrap_or(Ipv4Addr::new(127, 0, 0, 1));
    let mut proxy_sockaddr: SOCKADDR_IN = core::mem::zeroed();
    proxy_sockaddr.sin_family = AF_INET as u16;
    proxy_sockaddr.sin_port = cfg.proxy_port.to_be();
    proxy_sockaddr.sin_addr.S_un.S_addr = u32::from_ne_bytes(proxy_ip.octets());

    let res = original_fn(
        s,
        &proxy_sockaddr as *const _ as *const SOCKADDR,
        core::mem::size_of::<SOCKADDR_IN>() as i32,
    );

    if res != 0 {
        let err = WSAGetLastError();
        if err == WSAEWOULDBLOCK as i32 {
            if let Err(e) = wait_socket_ready(s, false, 5000) {
                log_msg(&format!("Proxy TCP connection timeout/failed: {}", e));
                WSASetLastError(e);
                return SOCKET_ERROR;
            }
        } else {
            log_msg(&format!("Failed to connect to SOCKS5 proxy: {}", err));
            return res;
        }
    }

    // Now complete SOCKS5 tunnel handshake
    match perform_socks5_handshake(s, target_ip_bytes, target_port) {
        Ok(_) => {
            log_msg(&format!("Successfully tunneled to {}:{}!", target_ip_str, target_port));
            0
        }
        Err(err) => {
            log_msg(&format!("SOCKS5 handshake failed: {}", err));
            WSASetLastError(err);
            SOCKET_ERROR
        }
    }
}

unsafe extern "system" fn detour_connect(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32 {
    if let Some(&original) = ORIGINAL_CONNECT.get() {
        handle_proxy_connect(s, name, namelen, original)
    } else {
        SOCKET_ERROR
    }
}

unsafe extern "system" fn detour_wsaconnect(
    s: SOCKET,
    name: *const SOCKADDR,
    namelen: i32,
    lp_caller_data: *mut c_void,
    lp_callee_data: *mut c_void,
    lp_sqos: *mut c_void,
    lp_gqos: *mut c_void,
) -> i32 {
    if lp_caller_data.is_null() && lp_callee_data.is_null() {
        if let Some(&original_connect) = ORIGINAL_CONNECT.get() {
            return handle_proxy_connect(s, name, namelen, original_connect);
        }
    }

    if let Some(&original) = ORIGINAL_WSACONNECT.get() {
        original(s, name, namelen, lp_caller_data, lp_callee_data, lp_sqos, lp_gqos)
    } else {
        SOCKET_ERROR
    }
}

fn initialize_hooks() {
    if HOOK_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    log_msg("Initializing Winsock API hooks...");
    let _ = CONFIG.get_or_init(load_config);

    unsafe {
        match MinHook::create_hook_api("ws2_32.dll", "connect", detour_connect as _) {
            Ok(orig) => {
                let orig_fn: ConnectFn = core::mem::transmute(orig);
                let _ = ORIGINAL_CONNECT.set(orig_fn);
                log_msg("Hooked ws2_32.dll!connect");
            }
            Err(e) => {
                log_msg(&format!("Failed to hook connect: {:?}", e));
            }
        }

        match MinHook::create_hook_api("ws2_32.dll", "WSAConnect", detour_wsaconnect as _) {
            Ok(orig) => {
                let orig_fn: WSAConnectFn = core::mem::transmute(orig);
                let _ = ORIGINAL_WSACONNECT.set(orig_fn);
                log_msg("Hooked ws2_32.dll!WSAConnect");
            }
            Err(e) => {
                log_msg(&format!("Failed to hook WSAConnect: {:?}", e));
            }
        }

        if let Err(e) = MinHook::enable_all_hooks() {
            log_msg(&format!("Failed to enable hooks: {:?}", e));
        } else {
            log_msg("All proxy hooks enabled successfully!");
        }
    }
}

#[no_mangle]
pub extern "system" fn DllMain(
    _hinst_dll: HANDLE,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> BOOL {
    if fdw_reason == DLL_PROCESS_ATTACH {
        std::thread::spawn(|| {
            initialize_hooks();
        });
    }
    1
}
