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
            default_action: RuleAction::Direct,
            rules: vec![
                Rule {
                    name: "Localhost bypass".to_string(),
                    action: RuleAction::Direct,
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
    /// Determines whether the given IP and port should be proxied based on configured rules.
    pub fn should_proxy_ip(&self, ip_str: &str, port: u16) -> bool {
        // Never proxy loopback connections directly to the proxy itself to prevent loops!
        if (ip_str == "127.0.0.1" || ip_str == "localhost") && port == self.proxy_port {
            return false;
        }

        for rule in &self.rules {
            let port_matches = rule.target_ports.is_empty() || rule.target_ports.contains(&port);
            if !port_matches {
                continue;
            }

            let ip_matches = rule.target_ips.iter().any(|rule_ip| {
                if rule_ip == "*" {
                    return true;
                }
                if rule_ip.ends_with('*') {
                    let prefix = &rule_ip[..rule_ip.len() - 1];
                    return ip_str.starts_with(prefix);
                }
                rule_ip == ip_str
            });

            if ip_matches {
                return rule.action == RuleAction::Proxy;
            }
        }

        self.default_action == RuleAction::Proxy
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
    pub const CMD_CONNECT: u8 = 0x01;
    pub const ATYP_IPV4: u8 = 0x01;
    pub const ATYP_DOMAIN: u8 = 0x03;
    pub const ATYP_IPV6: u8 = 0x04;
    pub const REP_SUCCESS: u8 = 0x00;

    /// Build SOCKS5 greeting packet: [VER=0x05, NMETHODS=1, METHOD=0x00 (No Auth)]
    pub fn build_greeting() -> [u8; 3] {
        [SOCKS_VERSION, 0x01, AUTH_NONE]
    }

    /// Verify SOCKS5 greeting response: [VER=0x05, METHOD=0x00]
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
