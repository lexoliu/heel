use heel::{AllowAll, AllowList, ConnectionDirection, DenyAll, DomainRequest, NetworkPolicy};
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Domain request information exposed to JavaScript
#[napi(object)]
#[derive(Clone)]
pub struct DomainRequestJs {
    pub target: String,
    pub port: u16,
    pub direction: String,
    pub pid: u32,
}

impl From<&DomainRequest> for DomainRequestJs {
    fn from(req: &DomainRequest) -> Self {
        Self {
            target: req.target().to_string(),
            port: req.port(),
            direction: match req.direction() {
                ConnectionDirection::Inbound => "inbound".to_string(),
                ConnectionDirection::Outbound => "outbound".to_string(),
            },
            pid: req.pid(),
        }
    }
}

/// Network policy configuration from JavaScript
#[napi(object)]
pub struct NetworkPolicyConfig {
    /// Policy type: "deny-all", "allow-all", or "allow-list"
    pub policy_type: String,
    /// Domains for allow-list policy (supports wildcards like "*.example.com")
    pub domains: Option<Vec<String>>,
    // Note: Custom handler is not yet supported due to NAPI async complexity
}

/// Unified network policy wrapper for runtime dispatch
pub enum NetworkPolicyWrapper {
    DenyAll(DenyAll),
    AllowAll(AllowAll),
    AllowList(AllowList),
}

impl NetworkPolicyWrapper {
    /// Create a NetworkPolicyWrapper from JavaScript configuration
    pub fn from_config(config: NetworkPolicyConfig) -> Result<Self> {
        match config.policy_type.as_str() {
            "deny-all" => Ok(Self::DenyAll(DenyAll)),
            "allow-all" => Ok(Self::AllowAll(AllowAll)),
            "allow-list" => {
                let domains = config.domains.unwrap_or_default();
                Ok(Self::AllowList(AllowList::new(domains)))
            }
            other => Err(Error::from_reason(format!(
                "unknown policy type: {}. Supported: deny-all, allow-all, allow-list",
                other
            ))),
        }
    }

    /// Create a default deny-all policy
    pub fn deny_all() -> Self {
        Self::DenyAll(DenyAll)
    }
}

impl NetworkPolicy for NetworkPolicyWrapper {
    async fn check(&self, request: &DomainRequest) -> bool {
        match self {
            Self::DenyAll(p) => p.check(request).await,
            Self::AllowAll(p) => p.check(request).await,
            Self::AllowList(p) => p.check(request).await,
        }
    }
}

// NetworkPolicyWrapper is Send + Sync because all variants are Send + Sync
unsafe impl Send for NetworkPolicyWrapper {}
unsafe impl Sync for NetworkPolicyWrapper {}
