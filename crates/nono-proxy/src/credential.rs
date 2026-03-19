//! Credential loading and management for reverse proxy mode.
//!
//! Loads API credentials from the system keystore or 1Password at proxy startup.
//! Credentials are stored in `Zeroizing<String>` and injected into
//! requests via headers, URL paths, query parameters, or Basic Auth.
//! The sandboxed agent never sees the real credentials.

use crate::config::{InjectMode, PathRule, RouteConfig};
use crate::error::{ProxyError, Result};
use crate::oauth2::{OAuth2ExchangeConfig, TokenCache};
use base64::Engine;
use std::collections::HashMap;
use tokio_rustls::TlsConnector;
use tracing::debug;
use zeroize::Zeroizing;

/// A loaded credential ready for injection.
pub struct LoadedCredential {
    /// Injection mode
    pub inject_mode: InjectMode,
    /// Upstream URL (e.g., "https://api.openai.com")
    pub upstream: String,
    /// Raw credential value from keystore (for modes that need it directly)
    pub raw_credential: Zeroizing<String>,

    // --- Header mode ---
    /// Header name to inject (e.g., "Authorization")
    pub header_name: String,
    /// Formatted header value (e.g., "Bearer sk-...")
    pub header_value: Zeroizing<String>,

    // --- URL path mode ---
    /// Pattern to match in incoming path (with {} placeholder)
    pub path_pattern: Option<String>,
    /// Pattern for outgoing path (with {} placeholder)
    pub path_replacement: Option<String>,

    // --- Query param mode ---
    /// Query parameter name
    pub query_param_name: Option<String>,

    // --- L7 path filtering ---
    /// Path filter rules for this route. Empty = all paths allowed.
    pub allowed_paths: Vec<PathRule>,
}

/// Custom Debug impl that redacts secret values to prevent accidental leakage
/// in logs, panic messages, or debug output.
impl std::fmt::Debug for LoadedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedCredential")
            .field("inject_mode", &self.inject_mode)
            .field("upstream", &self.upstream)
            .field("raw_credential", &"[REDACTED]")
            .field("header_name", &self.header_name)
            .field("header_value", &"[REDACTED]")
            .field("path_pattern", &self.path_pattern)
            .field("path_replacement", &self.path_replacement)
            .field("query_param_name", &self.query_param_name)
            .field("allowed_paths", &self.allowed_paths)
            .finish()
    }
}

/// An OAuth2 route entry: token cache + upstream URL.
#[derive(Debug)]
pub struct OAuth2Route {
    /// Token cache for automatic refresh
    pub cache: TokenCache,
    /// Upstream URL (e.g., "https://api.example.com")
    pub upstream: String,
}

/// Credential store for all configured routes.
#[derive(Debug)]
pub struct CredentialStore {
    /// Map from route prefix to loaded credential
    credentials: HashMap<String, LoadedCredential>,
    /// Map from route prefix to OAuth2 route (token cache + upstream)
    oauth2_routes: HashMap<String, OAuth2Route>,
}

impl CredentialStore {
    /// Load credentials for all configured routes from the system keystore.
    ///
    /// Routes without a `credential_key` or `oauth2` block are skipped (no
    /// credential injection). Routes whose credential is not found (e.g.
    /// unset env var) are skipped with a warning — this allows profiles to
    /// declare optional credentials without failing when they are unavailable.
    ///
    /// OAuth2 routes perform an initial token exchange at startup. If the
    /// exchange fails, the route is skipped (graceful degradation).
    ///
    /// The `tls_connector` is required for OAuth2 token exchange HTTPS calls.
    ///
    /// Returns an error only for hard failures (keystore access errors,
    /// config parse errors, non-UTF-8 values).
    pub fn load(routes: &[RouteConfig], tls_connector: &TlsConnector) -> Result<Self> {
        let mut credentials = HashMap::new();
        let mut oauth2_routes = HashMap::new();

        for route in routes {
            // Static credential path (existing behavior)
            if let Some(ref key) = route.credential_key {
                debug!(
                    "Loading credential for route prefix: {} (mode: {:?})",
                    route.prefix, route.inject_mode
                );

                let secret = match nono::keystore::load_secret_by_ref(KEYRING_SERVICE, key) {
                    Ok(s) => s,
                    Err(nono::NonoError::SecretNotFound(msg)) => {
                        debug!(
                            "Credential '{}' not available, skipping route: {}",
                            route.prefix, msg
                        );
                        continue;
                    }
                    Err(e) => return Err(ProxyError::Credential(e.to_string())),
                };

                // Format header value based on mode
                let header_value = match route.inject_mode {
                    InjectMode::Header => {
                        Zeroizing::new(route.credential_format.replace("{}", &secret))
                    }
                    InjectMode::BasicAuth => {
                        // Base64 encode the credential for Basic auth
                        let encoded =
                            base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
                        Zeroizing::new(format!("Basic {}", encoded))
                    }
                    // For url_path and query_param, header_value is not used
                    InjectMode::UrlPath | InjectMode::QueryParam => Zeroizing::new(String::new()),
                };

                credentials.insert(
                    route.prefix.clone(),
                    LoadedCredential {
                        inject_mode: route.inject_mode.clone(),
                        upstream: route.upstream.clone(),
                        raw_credential: secret,
                        header_name: route.inject_header.clone(),
                        header_value,
                        path_pattern: route.path_pattern.clone(),
                        path_replacement: route.path_replacement.clone(),
                        query_param_name: route.query_param_name.clone(),
                        allowed_paths: route.allowed_paths.clone(),
                    },
                );
                continue;
            }

            // OAuth2 client_credentials path
            if let Some(ref oauth2) = route.oauth2 {
                debug!(
                    "Loading OAuth2 credential for route prefix: {}",
                    route.prefix
                );

                let client_id =
                    match nono::keystore::load_secret_by_ref(KEYRING_SERVICE, &oauth2.client_id) {
                        Ok(s) => s,
                        Err(nono::NonoError::SecretNotFound(msg)) => {
                            debug!(
                                "OAuth2 client_id not available for route '{}': {}",
                                route.prefix, msg
                            );
                            continue;
                        }
                        Err(e) => return Err(ProxyError::Credential(e.to_string())),
                    };

                let client_secret = match nono::keystore::load_secret_by_ref(
                    KEYRING_SERVICE,
                    &oauth2.client_secret,
                ) {
                    Ok(s) => s,
                    Err(nono::NonoError::SecretNotFound(msg)) => {
                        debug!(
                            "OAuth2 client_secret not available for route '{}': {}",
                            route.prefix, msg
                        );
                        continue;
                    }
                    Err(e) => return Err(ProxyError::Credential(e.to_string())),
                };

                let config = OAuth2ExchangeConfig {
                    token_url: oauth2.token_url.clone(),
                    client_id,
                    client_secret,
                    scope: oauth2.scope.clone(),
                };

                match TokenCache::new(config, tls_connector.clone()) {
                    Ok(cache) => {
                        oauth2_routes.insert(
                            route.prefix.clone(),
                            OAuth2Route {
                                cache,
                                upstream: route.upstream.clone(),
                            },
                        );
                    }
                    Err(e) => {
                        debug!(
                            "OAuth2 token exchange failed for route '{}': {}, skipping",
                            route.prefix, e
                        );
                        continue;
                    }
                }
            }
        }

        Ok(Self {
            credentials,
            oauth2_routes,
        })
    }

    /// Create an empty credential store (no credential injection).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            credentials: HashMap::new(),
            oauth2_routes: HashMap::new(),
        }
    }

    /// Get a static credential for a route prefix, if configured.
    #[must_use]
    pub fn get(&self, prefix: &str) -> Option<&LoadedCredential> {
        self.credentials.get(prefix)
    }

    /// Get an OAuth2 route (token cache + upstream) for a route prefix, if configured.
    #[must_use]
    pub fn get_oauth2(&self, prefix: &str) -> Option<&OAuth2Route> {
        self.oauth2_routes.get(prefix)
    }

    /// Check if any credentials (static or OAuth2) are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty() && self.oauth2_routes.is_empty()
    }

    /// Number of loaded credentials (static + OAuth2).
    #[must_use]
    pub fn len(&self) -> usize {
        self.credentials.len() + self.oauth2_routes.len()
    }

    /// Returns the set of route prefixes that have loaded credentials
    /// (both static keystore and OAuth2 routes).
    #[must_use]
    pub fn loaded_prefixes(&self) -> std::collections::HashSet<String> {
        self.credentials
            .keys()
            .chain(self.oauth2_routes.keys())
            .cloned()
            .collect()
    }
}

/// The keyring service name used by nono for all credentials.
/// Uses the same constant as `nono::keystore::DEFAULT_SERVICE` to ensure consistency.
const KEYRING_SERVICE: &str = nono::keystore::DEFAULT_SERVICE;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Build a TLS connector for tests (never used for real connections).
    fn test_tls_connector() -> TlsConnector {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        TlsConnector::from(Arc::new(tls_config))
    }

    #[test]
    fn test_empty_credential_store() {
        let store = CredentialStore::empty();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.get("/openai").is_none());
        assert!(store.get_oauth2("/openai").is_none());
    }

    #[test]
    fn test_loaded_credential_debug_redacts_secrets() {
        // Security: Debug output must NEVER contain real secret values.
        // This prevents accidental leakage in logs, panic messages, or
        // tracing output at debug level.
        let cred = LoadedCredential {
            inject_mode: InjectMode::Header,
            upstream: "https://api.openai.com".to_string(),
            raw_credential: Zeroizing::new("sk-secret-12345".to_string()),
            header_name: "Authorization".to_string(),
            header_value: Zeroizing::new("Bearer sk-secret-12345".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            allowed_paths: Vec::new(),
        };

        let debug_output = format!("{:?}", cred);

        // Must contain REDACTED markers
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should contain [REDACTED], got: {}",
            debug_output
        );
        // Must NOT contain the actual secret
        assert!(
            !debug_output.contains("sk-secret-12345"),
            "Debug output must not contain the real secret"
        );
        assert!(
            !debug_output.contains("Bearer sk-secret"),
            "Debug output must not contain the formatted secret"
        );
        // Non-secret fields should still be visible
        assert!(debug_output.contains("api.openai.com"));
        assert!(debug_output.contains("Authorization"));
    }

    #[test]
    fn test_load_no_credential_routes() {
        let tls = test_tls_connector();
        let routes = vec![RouteConfig {
            prefix: "/test".to_string(),
            upstream: "https://example.com".to_string(),
            credential_key: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            env_var: None,
            allowed_paths: Vec::new(),
            oauth2: None,
        }];
        let store = CredentialStore::load(&routes, &tls);
        assert!(store.is_ok());
        let store = store.unwrap_or_else(|_| CredentialStore::empty());
        assert!(store.is_empty());
    }

    #[test]
    fn test_get_oauth2_returns_none_for_non_oauth2_routes() {
        let store = CredentialStore::empty();
        assert!(store.get_oauth2("openai").is_none());
        assert!(store.get_oauth2("my-api").is_none());
    }

    #[test]
    fn test_is_empty_false_with_only_oauth2_routes() {
        // Simulate a store with only OAuth2 routes by constructing directly.
        // We can't call load() with a real OAuth2 config (no token server),
        // so we build the struct manually to test the is_empty/len logic.
        use std::time::Duration;

        let cache = make_test_token_cache("test-token", Duration::from_secs(3600));
        let mut oauth2_routes = HashMap::new();
        oauth2_routes.insert(
            "my-api".to_string(),
            OAuth2Route {
                cache,
                upstream: "https://api.example.com".to_string(),
            },
        );

        let store = CredentialStore {
            credentials: HashMap::new(),
            oauth2_routes,
        };

        assert!(!store.is_empty(), "store with OAuth2 routes should not be empty");
        assert_eq!(store.len(), 1);
        assert!(store.get_oauth2("my-api").is_some());
        assert!(store.get("my-api").is_none());
    }

    #[test]
    fn test_loaded_prefixes_includes_oauth2() {
        use std::time::Duration;

        let cache = make_test_token_cache("test-token", Duration::from_secs(3600));
        let mut oauth2_routes = HashMap::new();
        oauth2_routes.insert(
            "my-api".to_string(),
            OAuth2Route {
                cache,
                upstream: "https://api.example.com".to_string(),
            },
        );

        let store = CredentialStore {
            credentials: HashMap::new(),
            oauth2_routes,
        };

        let prefixes = store.loaded_prefixes();
        assert!(prefixes.contains("my-api"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_load_oauth2_unreachable_endpoint_skips_route() {
        use crate::config::OAuth2Config;

        let tls = test_tls_connector();
        let routes = vec![RouteConfig {
            prefix: "my-api".to_string(),
            upstream: "https://api.example.com".to_string(),
            credential_key: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            env_var: Some("MY_API_KEY".to_string()),
            allowed_paths: Vec::new(),
            oauth2: Some(OAuth2Config {
                // Non-routable address: exchange will fail at TCP connect
                token_url: "https://127.0.0.1:1/oauth/token".to_string(),
                // Use env:// refs that point at test env vars
                client_id: "env://TEST_OAUTH2_CLIENT_ID".to_string(),
                client_secret: "env://TEST_OAUTH2_CLIENT_SECRET".to_string(),
                scope: String::new(),
            }),
        }];

        // Set env vars so credential loading succeeds (exchange will fail)
        std::env::set_var("TEST_OAUTH2_CLIENT_ID", "test-client");
        std::env::set_var("TEST_OAUTH2_CLIENT_SECRET", "test-secret");

        let store = CredentialStore::load(&routes, &tls);

        // Clean up env vars
        std::env::remove_var("TEST_OAUTH2_CLIENT_ID");
        std::env::remove_var("TEST_OAUTH2_CLIENT_SECRET");

        // load() should succeed (route skipped, not hard error)
        assert!(store.is_ok(), "load should not fail on unreachable OAuth2 endpoint");
        let store = store.unwrap();

        // The route should have been skipped (token exchange failed)
        assert!(store.is_empty(), "unreachable OAuth2 endpoint should result in skipped route");
        assert!(store.get_oauth2("my-api").is_none());
    }

    /// Build a test `TokenCache` with a pre-populated token.
    fn make_test_token_cache(token: &str, ttl: std::time::Duration) -> TokenCache {
        use crate::oauth2::OAuth2ExchangeConfig;

        let config = OAuth2ExchangeConfig {
            token_url: "https://127.0.0.1:1/oauth/token".to_string(),
            client_id: Zeroizing::new("test-client".to_string()),
            client_secret: Zeroizing::new("test-secret".to_string()),
            scope: String::new(),
        };

        TokenCache::new_from_parts(config, test_tls_connector(), token, ttl)
    }
}
