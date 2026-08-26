//! Network policies applied to every connection a sandboxed process attempts.

use std::collections::HashSet;
use std::future::Future;
use std::marker::PhantomData;

/// A network access request made by a sandboxed process.
///
/// Requests are always outbound: sandboxed processes reach the network through
/// the sandbox proxy, and inbound loopback connections are governed by the
/// platform backend rather than by a [`NetworkPolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRequest {
    host: String,
    port: u16,
}

impl DomainRequest {
    /// Create a request for `host:port`.
    ///
    /// The host is normalized for comparison: lowercased, with the root label's
    /// trailing dot removed.
    pub fn new(host: impl AsRef<str>, port: u16) -> Self {
        Self {
            host: normalize_host(host.as_ref()),
            port,
        }
    }

    /// The normalized domain or IP literal being accessed.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The destination port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Normalize a host for case-insensitive, trailing-dot-insensitive comparison.
///
/// DNS names are case-insensitive and `example.com.` denotes the same name as
/// `example.com`, so both must compare equal or an allow list is trivially
/// bypassed.
fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Decides whether a sandboxed process may open a given connection.
pub trait NetworkPolicy: Send + Sync + 'static {
    /// Whether this policy rejects every request without inspecting it.
    ///
    /// When `true` the sandbox skips starting a proxy altogether and the
    /// platform backend denies outbound traffic in the kernel, which is a
    /// stronger guarantee than a userspace rejection. Implementations must only
    /// set this when [`NetworkPolicy::check`] can never return `true`.
    const DENIES_ALL: bool = false;

    /// Check whether a request should be allowed.
    fn check(&self, request: &DomainRequest) -> impl Future<Output = bool> + Send;
}

/// Deny all network access (the default policy).
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAll;

impl NetworkPolicy for DenyAll {
    const DENIES_ALL: bool = true;

    async fn check(&self, _request: &DomainRequest) -> bool {
        false
    }
}

/// Allow all network access.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl NetworkPolicy for AllowAll {
    async fn check(&self, _request: &DomainRequest) -> bool {
        true
    }
}

/// Allow access to a fixed set of domains.
///
/// Entries are matched case-insensitively. An entry of the form `*.example.com`
/// matches any subdomain of `example.com` but not `example.com` itself.
#[derive(Debug, Clone)]
pub struct AllowList {
    exact: HashSet<String>,
    suffixes: Vec<String>,
}

impl AllowList {
    /// Build an allow list from domain patterns.
    pub fn new(domains: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        let mut exact = HashSet::new();
        let mut suffixes = Vec::new();

        for domain in domains {
            let domain = normalize_host(domain.as_ref());
            match domain.strip_prefix('*') {
                // "*.example.com" -> suffix ".example.com"
                Some(suffix) => suffixes.push(suffix.to_string()),
                None => {
                    exact.insert(domain);
                }
            }
        }

        Self { exact, suffixes }
    }

    /// Check whether a host matches the allow list.
    pub fn matches(&self, host: &str) -> bool {
        let host = normalize_host(host);
        self.exact.contains(&host)
            || self
                .suffixes
                .iter()
                .any(|suffix| host.ends_with(suffix.as_str()))
    }
}

impl NetworkPolicy for AllowList {
    async fn check(&self, request: &DomainRequest) -> bool {
        self.matches(request.host())
    }
}

/// A policy backed by a user-provided async handler.
pub struct CustomPolicy<F, Fut>
where
    F: Fn(&DomainRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + 'static,
{
    handler: F,
    _marker: PhantomData<fn() -> Fut>,
}

impl<F, Fut> CustomPolicy<F, Fut>
where
    F: Fn(&DomainRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + 'static,
{
    /// Wrap `handler` as a network policy.
    pub fn new(handler: F) -> Self {
        Self {
            handler,
            _marker: PhantomData,
        }
    }
}

impl<F, Fut> NetworkPolicy for CustomPolicy<F, Fut>
where
    F: Fn(&DomainRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + 'static,
{
    async fn check(&self, request: &DomainRequest) -> bool {
        (self.handler)(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Checked at compile time: the marker decides whether the sandbox starts a
    // proxy at all, so it must hold by construction rather than by test run.
    const _: () = assert!(DenyAll::DENIES_ALL);
    const _: () = assert!(!AllowAll::DENIES_ALL);
    const _: () = assert!(!AllowList::DENIES_ALL);

    #[test]
    fn deny_all_rejects_every_request() {
        smol::block_on(async {
            assert!(!DenyAll.check(&DomainRequest::new("example.com", 443)).await);
        });
    }

    #[test]
    fn allow_all_accepts_every_request() {
        smol::block_on(async {
            assert!(
                AllowAll
                    .check(&DomainRequest::new("example.com", 443))
                    .await
            );
        });
    }

    #[test]
    fn allow_list_matches_exact_domains() {
        let policy = AllowList::new(["example.com", "api.test.com"]);

        assert!(policy.matches("example.com"));
        assert!(policy.matches("api.test.com"));
        assert!(!policy.matches("other.com"));
        assert!(!policy.matches("sub.example.com"));
    }

    #[test]
    fn allow_list_matches_wildcards() {
        let policy = AllowList::new(["*.example.com"]);

        assert!(policy.matches("api.example.com"));
        assert!(policy.matches("sub.api.example.com"));
        assert!(!policy.matches("example.com"));
        assert!(!policy.matches("other.com"));
        assert!(!policy.matches("notexample.com"));
    }

    #[test]
    fn allow_list_ignores_case_and_trailing_dots() {
        let policy = AllowList::new(["Example.COM", "*.Test.com"]);

        assert!(policy.matches("EXAMPLE.com"));
        assert!(policy.matches("example.com."));
        assert!(policy.matches("API.Test.com"));
        assert!(!policy.matches("example.com.evil.net"));
    }

    #[test]
    fn domain_request_normalizes_host() {
        let request = DomainRequest::new("API.Example.COM.", 443);
        assert_eq!(request.host(), "api.example.com");
    }
}
