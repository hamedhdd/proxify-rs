use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Proxy,
    Direct,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub action: RuleAction,
    #[serde(default)]
    pub target_apps: Vec<String>,
    #[serde(default)]
    pub target_ips: Vec<String>,
    #[serde(default)]
    pub target_ports: Vec<u16>,
    #[serde(default)]
    pub target_hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub args: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub proxy_host: String,
    pub proxy_port: u16,
    #[serde(default)]
    pub proxy_username: Option<String>,
    #[serde(default)]
    pub proxy_password: Option<String>,
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default = "default_action_direct")]
    pub default_action: RuleAction,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub apps: Vec<AppConfig>,
}

fn default_action_direct() -> RuleAction {
    RuleAction::Direct
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 1080,
            proxy_username: None,
            proxy_password: None,
            theme: Some("dark".to_string()),
            default_action: RuleAction::Direct,
            rules: vec![
                Rule {
                    name: "Localhost bypass".to_string(),
                    action: RuleAction::Direct,
                    target_apps: vec![],
                    target_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
                    target_ports: vec![],
                    target_hosts: vec!["localhost".to_string()],
                },
            ],
            apps: vec![
                AppConfig {
                    name: "Command Prompt / Curl".to_string(),
                    path: "curl.exe".to_string(),
                    args: "https://api.myip.com".to_string(),
                    enabled: true,
                },
            ],
        }
    }
}

impl ProxyConfig {
    /// Comprehensive evaluation: Checks app name, IP, and port against configured apps, rules, and default action.
    pub fn should_proxy(&self, app_name: &str, ip_str: &str, port: u16) -> bool {
        // Never proxy loopback connections directly to the proxy itself to prevent loops!
        if (ip_str == "127.0.0.1" || ip_str == "localhost" || ip_str == "::1") && port == self.proxy_port {
            return false;
        }

        let app_lower = app_name.to_lowercase();

        // 1. Check explicit rules in order (first matching rule wins)
        for rule in &self.rules {
            if !rule.target_apps.is_empty() {
                let app_match = rule.target_apps.iter().any(|target_app| {
                    if target_app == "*" {
                        return true;
                    }
                    let t_lower = target_app.to_lowercase();
                    app_lower == t_lower
                        || (app_lower.ends_with(".exe") && app_lower[..app_lower.len() - 4] == t_lower)
                        || (t_lower.ends_with(".exe") && t_lower[..t_lower.len() - 4] == app_lower)
                });
                if !app_match {
                    continue;
                }
            }

            if !rule.target_ports.is_empty() && !rule.target_ports.contains(&port) {
                continue;
            }

            if !rule.target_ips.is_empty() {
                let ip_match = rule.target_ips.iter().any(|rule_ip| {
                    if rule_ip == "*" {
                        return true;
                    }
                    if rule_ip.ends_with('*') {
                        let prefix = &rule_ip[..rule_ip.len() - 1];
                        return ip_str.starts_with(prefix);
                    }
                    rule_ip == ip_str
                });
                if !ip_match {
                    continue;
                }
            }

            // Both app, port, and IP constraints match
            return rule.action == RuleAction::Proxy;
        }

        // 2. Check if the application is in the configured apps list
        if !app_name.is_empty() {
            let found_app = self.apps.iter().find(|app| {
                let name_lower = app.name.to_lowercase();
                let path_file_lower = std::path::Path::new(&app.path)
                    .file_name()
                    .map(|f| f.to_string_lossy().to_lowercase())
                    .unwrap_or_else(|| app.path.to_lowercase());

                app_lower == path_file_lower
                    || app_lower == name_lower
                    || (app_lower.ends_with(".exe") && app_lower[..app_lower.len() - 4] == path_file_lower)
                    || (path_file_lower.ends_with(".exe") && path_file_lower[..path_file_lower.len() - 4] == app_lower)
            });

            if let Some(app) = found_app {
                // If explicitly disabled in configured apps, bypass proxy
                if !app.enabled {
                    return false;
                }
                // If enabled, route through proxy
                return true;
            }
        }

        // 3. Fallback to default action
        self.default_action == RuleAction::Proxy
    }

    /// Ensures that an application is registered in the apps list and marked enabled.
    /// Returns true if newly added or enabled.
    pub fn ensure_app_registered(&mut self, app_name: &str) -> bool {
        let app_lower = app_name.to_lowercase();
        for app in &mut self.apps {
            let name_lower = app.name.to_lowercase();
            let path_file_lower = std::path::Path::new(&app.path)
                .file_name()
                .map(|f| f.to_string_lossy().to_lowercase())
                .unwrap_or_else(|| app.path.to_lowercase());

            if app_lower == path_file_lower
                || app_lower == name_lower
                || (app_lower.ends_with(".exe") && app_lower[..app_lower.len() - 4] == path_file_lower)
                || (path_file_lower.ends_with(".exe") && path_file_lower[..path_file_lower.len() - 4] == app_lower)
            {
                if !app.enabled {
                    app.enabled = true;
                    return true;
                }
                return false;
            }
        }

        self.apps.push(AppConfig {
            name: app_name.to_string(),
            path: app_name.to_string(),
            args: String::new(),
            enabled: true,
        });
        true
    }

    /// Determines whether the given IP and port should be proxied based on configured rules.
    pub fn should_proxy_ip(&self, ip_str: &str, port: u16) -> bool {
        self.should_proxy("", ip_str, port)
    }

    /// Determines whether a hostname/domain matches the proxy rules.
    pub fn should_proxy_host(&self, host: &str, port: u16) -> bool {
        if host == "localhost" || host == "127.0.0.1" {
            if port == self.proxy_port {
                return false;
            }
        }

        for rule in &self.rules {
            let port_matches = rule.target_ports.is_empty() || rule.target_ports.contains(&port);
            if !port_matches {
                continue;
            }

            let host_matches = rule.target_hosts.iter().any(|pattern| {
                if pattern == "*" {
                    return true;
                }
                if pattern.starts_with("*.") {
                    let suffix = &pattern[1..]; // e.g. .example.com
                    return host.ends_with(suffix) || host == &pattern[2..];
                }
                pattern.eq_ignore_ascii_case(host)
            });

            if host_matches {
                return rule.action == RuleAction::Proxy;
            }
        }

        self.default_action == RuleAction::Proxy
    }
}

pub mod socks5 {
    //! SOCKS5 protocol byte-level frame construction and validation.

    pub const SOCKS_VERSION: u8 = 0x05;
    pub const AUTH_NONE: u8 = 0x00;
    pub const AUTH_USER_PASS: u8 = 0x02;
    pub const CMD_CONNECT: u8 = 0x01;
    pub const ATYP_IPV4: u8 = 0x01;
    pub const ATYP_DOMAIN: u8 = 0x03;
    pub const ATYP_IPV6: u8 = 0x04;
    pub const REP_SUCCESS: u8 = 0x00;

    /// Build SOCKS5 greeting packet: [VER=0x05, NMETHODS=1, METHOD=0x00 (No Auth)]
    pub fn build_greeting() -> [u8; 3] {
        [SOCKS_VERSION, 0x01, AUTH_NONE]
    }

    /// Build SOCKS5 greeting packet with optional username/password support.
    pub fn build_greeting_methods(has_credentials: bool) -> Vec<u8> {
        if has_credentials {
            vec![SOCKS_VERSION, 0x02, AUTH_NONE, AUTH_USER_PASS]
        } else {
            vec![SOCKS_VERSION, 0x01, AUTH_NONE]
        }
    }

    /// Build RFC 1929 Username/Password auth request: [0x01, ulen, user..., plen, pass...]
    pub fn build_auth_request(user: &str, pass: &str) -> Vec<u8> {
        let u_bytes = user.as_bytes();
        let p_bytes = pass.as_bytes();
        let mut buf = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
        buf.push(0x01); // Auth subnegotiation version
        buf.push(u_bytes.len() as u8);
        buf.extend_from_slice(u_bytes);
        buf.push(p_bytes.len() as u8);
        buf.extend_from_slice(p_bytes);
        buf
    }

    /// Verify RFC 1929 Auth response: [0x01, 0x00]
    pub fn verify_auth_response(response: &[u8]) -> bool {
        response.len() >= 2 && response[1] == 0x00
    }

    /// Verify SOCKS5 greeting response: [VER=0x05, METHOD]
    pub fn verify_greeting_response(response: &[u8]) -> bool {
        response.len() >= 2 && response[0] == SOCKS_VERSION && response[1] == AUTH_NONE
    }

    /// Build SOCKS5 CONNECT request for IPv4.
    pub fn build_connect_ipv4(ip: [u8; 4], port: u16) -> [u8; 10] {
        [
            SOCKS_VERSION,
            CMD_CONNECT,
            0x00, // Reserved
            ATYP_IPV4,
            ip[0],
            ip[1],
            ip[2],
            ip[3],
            (port >> 8) as u8,
            (port & 0xFF) as u8,
        ]
    }

    /// Build SOCKS5 CONNECT request for IPv6.
    pub fn build_connect_ipv6(ip: [u8; 16], port: u16) -> [u8; 22] {
        let mut buf = [0u8; 22];
        buf[0] = SOCKS_VERSION;
        buf[1] = CMD_CONNECT;
        buf[2] = 0x00;
        buf[3] = ATYP_IPV6;
        buf[4..20].copy_from_slice(&ip);
        buf[20] = (port >> 8) as u8;
        buf[21] = (port & 0xFF) as u8;
        buf
    }

    /// Build SOCKS5 CONNECT request for domain name.
    pub fn build_connect_domain(domain: &str, port: u16) -> Vec<u8> {
        let domain_bytes = domain.as_bytes();
        let mut buf = Vec::with_capacity(7 + domain_bytes.len());
        buf.push(SOCKS_VERSION);
        buf.push(CMD_CONNECT);
        buf.push(0x00);
        buf.push(ATYP_DOMAIN);
        buf.push(domain_bytes.len() as u8);
        buf.extend_from_slice(domain_bytes);
        buf.push((port >> 8) as u8);
        buf.push((port & 0xFF) as u8);
        buf
    }

    /// Verify SOCKS5 CONNECT response.
    pub fn verify_connect_response(response: &[u8]) -> bool {
        response.len() >= 4 && response[0] == SOCKS_VERSION && response[1] == REP_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_app_registered() {
        let mut cfg = ProxyConfig::default();
        assert_eq!(cfg.apps.len(), 1);

        // Add firefox
        let added = cfg.ensure_app_registered("firefox.exe");
        assert!(added);
        assert_eq!(cfg.apps.len(), 2);
        assert!(cfg.apps.iter().any(|a| a.name == "firefox.exe" && a.enabled));

        // Adding again should not duplicate
        let added_again = cfg.ensure_app_registered("firefox.exe");
        assert!(!added_again);
        assert_eq!(cfg.apps.len(), 2);

        // Disabling it then calling ensure_app_registered should re-enable
        cfg.apps[1].enabled = false;
        let re_enabled = cfg.ensure_app_registered("firefox.exe");
        assert!(re_enabled);
        assert!(cfg.apps[1].enabled);
    }

    #[test]
    fn test_should_proxy_registered_app() {
        let mut cfg = ProxyConfig::default();
        cfg.default_action = RuleAction::Direct;

        // Untargeted app with default_action=Direct should not proxy
        assert!(!cfg.should_proxy("firefox.exe", "103.75.196.241", 5000));

        // Once registered, it should proxy!
        cfg.ensure_app_registered("firefox.exe");
        assert!(cfg.should_proxy("firefox.exe", "103.75.196.241", 5000));

        // Localhost bypass rule should still bypass even for registered app
        assert!(!cfg.should_proxy("firefox.exe", "127.0.0.1", 8080));
    }
}
