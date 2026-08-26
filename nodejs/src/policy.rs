//! Network policy selection from JavaScript.

use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Network policy configuration.
#[napi(object)]
pub struct NetworkPolicyConfig {
    /// Policy type: `deny-all`, `allow-all`, or `allow-list`.
    pub policy_type: String,
    /// Domains for the allow-list policy; supports `*.example.com`.
    pub domains: Option<Vec<String>>,
}

/// A policy chosen at runtime.
///
/// The Rust API is generic over the policy so that policies compose at compile
/// time. JavaScript picks one from a string, so the binding resolves it to a
/// concrete type here rather than erasing it: a deny-all sandbox must still get
/// the kernel-level denial that its type selects.
pub enum PolicySelection {
    DenyAll,
    AllowAll,
    AllowList(Vec<String>),
}

impl PolicySelection {
    /// Resolve a JavaScript policy configuration.
    pub fn from_config(config: Option<NetworkPolicyConfig>) -> Result<Self> {
        let Some(config) = config else {
            return Ok(Self::DenyAll);
        };

        match config.policy_type.as_str() {
            "deny-all" => Ok(Self::DenyAll),
            "allow-all" => Ok(Self::AllowAll),
            "allow-list" => {
                let domains = config.domains.unwrap_or_default();
                if domains.is_empty() {
                    return Err(Error::from_reason(
                        "the allow-list policy requires at least one domain",
                    ));
                }
                Ok(Self::AllowList(domains))
            }
            other => Err(Error::from_reason(format!(
                "unknown policy type: {other}. Supported: deny-all, allow-all, allow-list"
            ))),
        }
    }
}
