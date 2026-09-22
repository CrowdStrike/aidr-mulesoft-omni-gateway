// Auto-generated from definition/gcl.yaml — do not edit by hand.
// Regenerate with: make build-asset-files
//
// This file is committed so that `cargo build` works without cargo-anypoint installed.
// CI enforces that it stays in sync with gcl.yaml via the generated-files-drift check.

use pdk::flex_abi::api::FlexAbi;
use pdk::hl::Service;
use pdk::serde::deserialize_service;
use serde::Deserialize;

/// Flex ABI initializer — runs before the async entrypoint.
///
/// Registers the AIDR API service cluster with Flex Gateway so the WASM's
/// outbound dispatch_http_call resolves to the correct Envoy cluster.
///
/// Note: abi.setup() (enable_stop_iteration) is intentionally omitted — it is
/// not supported in Flex Gateway 1.9.x (requires 1.12+). Body access uses the
/// two-step headers → body_state transition available in 1.9.x instead.
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration()).map_err(|e| {
        anyhow::anyhow!("Failed to parse configuration. Cause: {}", e)
    })?;
    abi.service_create(config.aidr_service)?;
    abi.setup()?;
    Ok(())
}

#[derive(Deserialize, Debug)]
pub struct Config {
    /// AIDR API service — defined as `format: service` in gcl.yaml.
    /// Deserialized into a Service so the cluster name matches what Flex Gateway
    /// registers (in connected mode via format:service; in local mode via a
    /// Service resource whose name is derived by the same formula).
    #[serde(alias = "aidr_api_base_url", deserialize_with = "deserialize_service")]
    pub aidr_service: Service,

    /// CrowdStrike AIDR Bearer token (sensitive)
    #[serde(alias = "aidr_api_key")]
    pub aidr_api_key: String,

    /// LLM provider identifier: "openai", "anthropic", "azureai", "gemini", "cohere", "bedrock"
    #[serde(alias = "llm_provider")]
    pub llm_provider: Option<String>,

    #[serde(alias = "app_id")]
    pub app_id: Option<String>,

    #[serde(alias = "user_id")]
    pub user_id: Option<String>,

    #[serde(alias = "model")]
    pub model: Option<String>,

    #[serde(alias = "model_version")]
    pub model_version: Option<String>,

    #[serde(alias = "source_location")]
    pub source_location: Option<String>,

    #[serde(alias = "tenant_id")]
    pub tenant_id: Option<String>,

    #[serde(alias = "collector_instance_id")]
    pub collector_instance_id: Option<String>,

    /// When true, pass traffic through if the AIDR service is unreachable instead of returning 500.
    /// Defaults to false (fail-closed). Override only for non-critical traffic.
    #[serde(alias = "fail_open", default)]
    pub fail_open: bool,
}
