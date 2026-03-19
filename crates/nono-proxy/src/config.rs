//! Proxy configuration types.
//!
//! Defines the configuration for the proxy server, including allowed hosts,
//! credential routes, and external proxy settings.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Credential injection mode determining how credentials are inserted into requests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectMode {
    /// Inject credential into an HTTP header (default)
    #[default]
    Header,
    /// Replace a pattern in the URL path with the credential
    UrlPath,
    /// Add or replace a query parameter with the credential
    QueryParam,
    /// Use HTTP Basic Authentication (credential format: "username:password")
    BasicAuth,
}

/// Configuration for the proxy server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Bind address (default: 127.0.0.1)
    #[serde(default = "default_bind_addr")]
    pub bind_addr: IpAddr,

    /// Bind port (0 = OS-assigned ephemeral port)
    #[serde(default)]
    pub bind_port: u16,

    /// Allowed hosts for CONNECT mode (exact match + wildcards).
    /// Empty = allow all hosts (except deny list).
    #[serde(default)]
    pub allowed_hosts: Vec<String>,

    /// Reverse proxy credential routes.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    /// External (enterprise) proxy URL for passthrough mode.
    /// When set, CONNECT requests are chained to this proxy.
    #[serde(default)]
    pub external_proxy: Option<ExternalProxyConfig>,

    /// Maximum concurrent connections (0 = unlimited).
    #[serde(default)]
    pub max_connections: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            bind_port: 0,
            allowed_hosts: Vec::new(),
            routes: Vec::new(),
            external_proxy: None,
            max_connections: 256,
        }
    }
}

fn default_bind_addr() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
}

/// A single path-level access rule for L7 filtering.
///
/// When `allowed_paths` is non-empty on a route, only requests matching
/// at least one rule are forwarded. Empty = all paths allowed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathRule {
    /// HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
    /// Use "*" to match any method.
    pub method: String,
    /// URL path glob pattern.
    /// `*` matches a single path segment, `**` matches zero or more segments.
    pub path: String,
}

/// Configuration for a reverse proxy credential route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Path prefix for routing (e.g., "/openai")
    pub prefix: String,

    /// Upstream URL to forward to (e.g., "https://api.openai.com")
    pub upstream: String,

    /// Keystore account name to load the credential from.
    /// If `None`, no credential is injected.
    pub credential_key: Option<String>,

    /// Injection mode (default: "header")
    #[serde(default)]
    pub inject_mode: InjectMode,

    // --- Header mode fields ---
    /// HTTP header name for the credential (default: "Authorization")
    /// Only used when inject_mode is "header".
    #[serde(default = "default_inject_header")]
    pub inject_header: String,

    /// Format string for the credential value. `{}` is replaced with the secret.
    /// Default: "Bearer {}"
    /// Only used when inject_mode is "header".
    #[serde(default = "default_credential_format")]
    pub credential_format: String,

    // --- URL path mode fields ---
    /// Pattern to match in incoming URL path. Use {} as placeholder for phantom token.
    /// Example: "/bot{}/" matches "/bot<token>/getMe"
    /// Only used when inject_mode is "url_path".
    #[serde(default)]
    pub path_pattern: Option<String>,

    /// Pattern for outgoing URL path. Use {} as placeholder for real credential.
    /// Defaults to same as path_pattern if not specified.
    /// Only used when inject_mode is "url_path".
    #[serde(default)]
    pub path_replacement: Option<String>,

    // --- Query param mode fields ---
    /// Name of the query parameter to add/replace with the credential.
    /// Only used when inject_mode is "query_param".
    #[serde(default)]
    pub query_param_name: Option<String>,

    /// Explicit environment variable name for the phantom token (e.g., "OPENAI_API_KEY").
    ///
    /// When set, this is used as the SDK API key env var name instead of deriving
    /// it from `credential_key.to_uppercase()`. Required when `credential_key` is
    /// a URI manager reference (e.g., `op://`, `apple-password://`) which would
    /// otherwise produce a nonsensical env var name.
    #[serde(default)]
    pub env_var: Option<String>,

    /// L7 path filter rules. When non-empty, only matching method+path
    /// combinations are forwarded. Empty = all paths allowed (default).
    #[serde(default)]
    pub allowed_paths: Vec<PathRule>,

    /// Optional OAuth2 client_credentials configuration.
    /// When present, the proxy handles token exchange automatically instead
    /// of using a static credential from the keystore.
    /// Mutually exclusive with `credential_key` — use one or the other.
    #[serde(default)]
    pub oauth2: Option<OAuth2Config>,
}

fn default_inject_header() -> String {
    "Authorization".to_string()
}

fn default_credential_format() -> String {
    "Bearer {}".to_string()
}

/// Configuration for an external (enterprise) proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalProxyConfig {
    /// Proxy address (e.g., "squid.corp.internal:3128")
    pub address: String,

    /// Optional authentication for the external proxy.
    pub auth: Option<ExternalProxyAuth>,

    /// Hosts to bypass the external proxy and route directly.
    /// Supports exact hostnames and `*.` wildcard suffixes (case-insensitive).
    /// Empty = all traffic goes through the external proxy.
    #[serde(default)]
    pub bypass_hosts: Vec<String>,
}

/// Authentication for an external proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalProxyAuth {
    /// Keystore account name for proxy credentials.
    pub keyring_account: String,

    /// Authentication scheme (only "basic" supported).
    #[serde(default = "default_auth_scheme")]
    pub scheme: String,
}

fn default_auth_scheme() -> String {
    "basic".to_string()
}

/// OAuth2 client_credentials configuration for automatic token exchange.
///
/// When configured on a route, the proxy handles the token lifecycle:
/// 1. Exchanges client_id + client_secret for an access_token at startup
/// 2. Caches the token with TTL from the `expires_in` response
/// 3. Refreshes automatically before expiry (30s buffer)
/// 4. Injects the access_token as `Authorization: Bearer <token>`
///
/// The agent never sees client_id or client_secret — only a phantom token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuth2Config {
    /// Token endpoint URL (e.g., "https://auth.example.com/oauth/token")
    pub token_url: String,
    /// Client ID — plain value or credential reference (env://, file://, op://)
    pub client_id: String,
    /// Client secret — credential reference (env://, file://, op://)
    pub client_secret: String,
    /// OAuth2 scopes (space-separated). Empty = no scope parameter sent.
    #[serde(default)]
    pub scope: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ProxyConfig::default();
        assert_eq!(config.bind_addr, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(config.bind_port, 0);
        assert!(config.allowed_hosts.is_empty());
        assert!(config.routes.is_empty());
        assert!(config.external_proxy.is_none());
    }

    #[test]
    fn test_config_serialization() {
        let config = ProxyConfig {
            allowed_hosts: vec!["api.openai.com".to_string()],
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ProxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.allowed_hosts, vec!["api.openai.com"]);
    }

    #[test]
    fn test_external_proxy_config_with_bypass_hosts() {
        let config = ProxyConfig {
            external_proxy: Some(ExternalProxyConfig {
                address: "squid.corp:3128".to_string(),
                auth: None,
                bypass_hosts: vec!["internal.corp".to_string(), "*.private.net".to_string()],
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ProxyConfig = serde_json::from_str(&json).unwrap();
        let ext = deserialized.external_proxy.unwrap();
        assert_eq!(ext.address, "squid.corp:3128");
        assert_eq!(ext.bypass_hosts.len(), 2);
        assert_eq!(ext.bypass_hosts[0], "internal.corp");
        assert_eq!(ext.bypass_hosts[1], "*.private.net");
    }

    #[test]
    fn test_external_proxy_config_bypass_hosts_default_empty() {
        let json = r#"{"address": "proxy:3128", "auth": null}"#;
        let ext: ExternalProxyConfig = serde_json::from_str(json).unwrap();
        assert!(ext.bypass_hosts.is_empty());
    }

    #[test]
    fn test_path_rule_deserialization() {
        let json = r#"{"method": "GET", "path": "/api/v4/projects/*/merge_requests/**"}"#;
        let rule: PathRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.method, "GET");
        assert_eq!(rule.path, "/api/v4/projects/*/merge_requests/**");
    }

    #[test]
    fn test_route_config_with_allowed_paths() {
        let json = r#"{
            "prefix": "/gitlab",
            "upstream": "https://gitlab.example.com",
            "allowed_paths": [
                {"method": "GET", "path": "/api/v4/projects/*/merge_requests/**"},
                {"method": "POST", "path": "/api/v4/projects/*/merge_requests/*/notes"}
            ]
        }"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        assert_eq!(route.allowed_paths.len(), 2);
    }

    #[test]
    fn test_route_config_without_paths_allows_all() {
        let json = r#"{"prefix": "/openai", "upstream": "https://api.openai.com"}"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        assert!(route.allowed_paths.is_empty());
    }

    #[test]
    fn test_oauth2_config_deserialization() {
        let json = r#"{
            "token_url": "https://auth.example.com/oauth/token",
            "client_id": "my-client",
            "client_secret": "env://CLIENT_SECRET",
            "scope": "read write"
        }"#;
        let config: OAuth2Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.token_url, "https://auth.example.com/oauth/token");
        assert_eq!(config.client_id, "my-client");
        assert_eq!(config.client_secret, "env://CLIENT_SECRET");
        assert_eq!(config.scope, "read write");
    }

    #[test]
    fn test_oauth2_config_default_scope() {
        let json = r#"{
            "token_url": "https://auth.example.com/oauth/token",
            "client_id": "my-client",
            "client_secret": "env://SECRET"
        }"#;
        let config: OAuth2Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.scope, "");
    }

    #[test]
    fn test_route_config_with_oauth2() {
        let json = r#"{
            "prefix": "/my-api",
            "upstream": "https://api.example.com",
            "oauth2": {
                "token_url": "https://auth.example.com/oauth/token",
                "client_id": "agent-1",
                "client_secret": "env://CLIENT_SECRET",
                "scope": "api.read"
            }
        }"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        assert!(route.oauth2.is_some());
        assert!(route.credential_key.is_none());
        let oauth2 = route.oauth2.unwrap();
        assert_eq!(oauth2.token_url, "https://auth.example.com/oauth/token");
    }

    #[test]
    fn test_route_config_without_oauth2() {
        let json = r#"{
            "prefix": "/openai",
            "upstream": "https://api.openai.com",
            "credential_key": "openai"
        }"#;
        let route: RouteConfig = serde_json::from_str(json).unwrap();
        assert!(route.oauth2.is_none());
        assert!(route.credential_key.is_some());
    }
}
