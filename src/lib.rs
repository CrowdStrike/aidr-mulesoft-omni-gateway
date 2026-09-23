// Copyright 2024 CrowdStrike, Inc. All rights reserved.
//
// CrowdStrike AIDR policy for Anypoint Flex Gateway (PDK).
//
// Intercepts LLM requests/responses (OpenAI, Anthropic, Azure, etc.) and
// MCP JSON-RPC 2.0 traffic, calling the CrowdStrike AIDR API to block prompt
// injection, PII leakage, and malicious tool calls.
//
// NOTE: src/generated/ is auto-generated from definition/gcl.yaml.
// Run `make build-asset-files` once before building to populate it.
mod generated;

use anyhow::{anyhow, Result};
use pdk::hl::*;
use pdk::logger;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

/// Timeout for outbound AIDR API calls.
const AIDR_TIMEOUT: Duration = Duration::from_secs(10);

use crate::generated::config::Config;

// ---------------------------------------------------------------------------
// Shared state passed from on_request → on_response
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
enum TrafficContext {
    /// Standard LLM request/response pair
    LlmRequest,
    /// MCP JSON-RPC 2.0 — stores method name and request id for response phase
    Mcp {
        method: String,
        id: Value,
    },
    /// Could not determine traffic type; skip response inspection
    Unknown,
}

// ---------------------------------------------------------------------------
// AIDR API types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AidrResponse {
    result: Option<AidrResult>,
    summary: Option<String>,
}

#[derive(Deserialize)]
struct AidrResult {
    blocked: Option<bool>,
    transformed: Option<bool>,
    guard_output: Option<GuardOutput>,
}

#[derive(Deserialize)]
struct GuardOutput {
    messages: Option<Vec<AidrMessage>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AidrMessage {
    role: String,
    content: Value,
}

// ---------------------------------------------------------------------------
// Provider message extraction (translators)
//
// Returns (messages_for_aidr, redaction_pointers_into_body).
// redaction_pointers is a Vec of JSON Pointer strings (RFC 6901) that point
// to the content fields in the original body.  When AIDR returns transformed
// messages the redacted content is written back via pointer_mut.
// ---------------------------------------------------------------------------

/// Extract messages from an LLM *request* body.
fn extract_request_messages(
    provider: &str,
    body: &Value,
) -> (Vec<AidrMessage>, Vec<String>) {
    match provider {
        "anthropic" => extract_anthropic_request(body),
        "openai" | "azureai" | "kong" => extract_openai_request(body),
        "gemini" => extract_gemini_request(body),
        "cohere" => extract_cohere_request(body),
        "bedrock" => extract_bedrock_request(body),
        _ => extract_openai_request(body),
    }
}

fn extract_openai_request(body: &Value) -> (Vec<AidrMessage>, Vec<String>) {
    let mut messages = Vec::new();
    let mut pointers = Vec::new();

    if let Some(arr) = body.get("messages").and_then(|v| v.as_array()) {
        for (i, msg) in arr.iter().enumerate() {
            let role = msg
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("user")
                .to_string();
            let content = msg.get("content").cloned().unwrap_or(Value::Null);
            if content.is_null() {
                continue;
            }
            // Flatten content arrays to a single string for AIDR text detectors.
            // None means the content array contained an unrecognised block type —
            // serialize the raw content so AIDR still makes an explicit decision
            // rather than silently passing uninspected traffic.
            let flat = match flatten_content(&content) {
                Some(s) => s,
                None => {
                    logger::debug!("AIDR: unrecognised content block type; submitting raw JSON for inspection");
                    content.to_string()
                }
            };
            if flat.is_empty() {
                continue;
            }
            messages.push(AidrMessage {
                role,
                content: Value::String(flat),
            });
            pointers.push(format!("/messages/{}/content", i));
        }
    }
    (messages, pointers)
}

fn extract_anthropic_request(body: &Value) -> (Vec<AidrMessage>, Vec<String>) {
    let mut messages = Vec::new();
    let mut pointers = Vec::new();

    // Anthropic includes an optional top-level "system" field, which may be
    // either a plain string or an array of text blocks.
    if let Some(system) = body.get("system") {
        let flat = match system {
            Value::String(s) => Some(s.clone()),
            Value::Array(_) => flatten_content(system),
            _ => None,
        };
        if let Some(text) = flat {
            if !text.is_empty() {
                messages.push(AidrMessage {
                    role: "system".to_string(),
                    content: Value::String(text),
                });
                pointers.push("/system".to_string());
            }
        }
    }

    if let Some(arr) = body.get("messages").and_then(|v| v.as_array()) {
        for (i, msg) in arr.iter().enumerate() {
            let role = msg
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("user")
                .to_string();
            let content = msg.get("content").cloned().unwrap_or(Value::Null);
            if content.is_null() {
                continue;
            }
            let flat = match flatten_content(&content) {
                Some(s) => s,
                None => {
                    logger::debug!("AIDR: unrecognised content block type; submitting raw JSON for inspection");
                    content.to_string()
                }
            };
            if flat.is_empty() {
                continue;
            }
            messages.push(AidrMessage {
                role,
                content: Value::String(flat),
            });
            pointers.push(format!("/messages/{}/content", i));
        }
    }
    (messages, pointers)
}

/// Extract messages from an LLM *response* body.
fn extract_response_messages(
    provider: &str,
    body: &Value,
) -> (Vec<AidrMessage>, Vec<String>) {
    match provider {
        "anthropic" => extract_anthropic_response(body),
        "gemini" => extract_gemini_response(body),
        "cohere" => extract_cohere_response(body),
        "bedrock" => extract_bedrock_response(body),
        _ => extract_openai_response(body),
    }
}

fn extract_openai_response(body: &Value) -> (Vec<AidrMessage>, Vec<String>) {
    let mut messages = Vec::new();
    let mut pointers = Vec::new();

    if let Some(choices) = body.get("choices").and_then(|v| v.as_array()) {
        for (i, choice) in choices.iter().enumerate() {
            if let Some(msg) = choice.get("message") {
                let role = msg
                    .get("role")
                    .and_then(|v| v.as_str())
                    .unwrap_or("assistant")
                    .to_string();
                let content = msg.get("content").cloned().unwrap_or(Value::Null);
                if content.is_null() {
                    continue;
                }
                let flat = match flatten_content(&content) {
                    Some(s) => s,
                    None => {
                        logger::debug!("AIDR: unrecognised content block type; submitting raw JSON for inspection");
                        content.to_string()
                    }
                };
                messages.push(AidrMessage {
                    role,
                    content: Value::String(flat),
                });
                pointers.push(format!("/choices/{}/message/content", i));
            }
        }
    }
    (messages, pointers)
}

fn extract_anthropic_response(body: &Value) -> (Vec<AidrMessage>, Vec<String>) {
    let mut messages = Vec::new();
    let mut pointers = Vec::new();

    if let Some(content_arr) = body.get("content").and_then(|v| v.as_array()) {
        for (i, block) in content_arr.iter().enumerate() {
            if block.get("type").and_then(|v| v.as_str()) == Some("text") {
                if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                    messages.push(AidrMessage {
                        role: "assistant".to_string(),
                        content: Value::String(text.to_string()),
                    });
                    pointers.push(format!("/content/{}/text", i));
                }
            }
        }
    }
    (messages, pointers)
}

// ---------------------------------------------------------------------------
// Gemini extractors
// ---------------------------------------------------------------------------

fn extract_gemini_request(body: &Value) -> (Vec<AidrMessage>, Vec<String>) {
    let mut messages = Vec::new();
    let mut pointers = Vec::new();

    // Optional system instruction: {parts: [{text: "..."}]}
    // One AidrMessage per text part so each part has its own redaction pointer.
    if let Some(sys) = body.get("systemInstruction") {
        if let Some(parts) = sys.get("parts").and_then(|p| p.as_array()) {
            for (j, part) in parts.iter().enumerate() {
                if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                    if !text.is_empty() {
                        messages.push(AidrMessage {
                            role: "system".to_string(),
                            content: Value::String(text.to_string()),
                        });
                        pointers.push(format!("/systemInstruction/parts/{}/text", j));
                    }
                }
            }
        }
    }

    if let Some(contents) = body.get("contents").and_then(|v| v.as_array()) {
        for (i, msg) in contents.iter().enumerate() {
            // Gemini uses "model" for assistant turns; normalise for AIDR
            let role = match msg.get("role").and_then(|v| v.as_str()).unwrap_or("user") {
                "model" => "assistant",
                r => r,
            }
            .to_string();
            // One AidrMessage per text part so each part has its own redaction pointer.
            if let Some(parts) = msg.get("parts").and_then(|p| p.as_array()) {
                for (j, part) in parts.iter().enumerate() {
                    if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                        messages.push(AidrMessage {
                            role: role.clone(),
                            content: Value::String(text.to_string()),
                        });
                        pointers.push(format!("/contents/{}/parts/{}/text", i, j));
                    }
                }
            }
        }
    }
    (messages, pointers)
}

fn extract_gemini_response(body: &Value) -> (Vec<AidrMessage>, Vec<String>) {
    let mut messages = Vec::new();
    let mut pointers = Vec::new();

    if let Some(candidates) = body.get("candidates").and_then(|v| v.as_array()) {
        for (i, candidate) in candidates.iter().enumerate() {
            if let Some(content) = candidate.get("content") {
                // One AidrMessage per text part so each part has its own redaction pointer.
                if let Some(parts) = content.get("parts").and_then(|p| p.as_array()) {
                    for (j, part) in parts.iter().enumerate() {
                        if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                            messages.push(AidrMessage {
                                role: "assistant".to_string(),
                                content: Value::String(text.to_string()),
                            });
                            pointers.push(format!("/candidates/{}/content/parts/{}/text", i, j));
                        }
                    }
                }
            }
        }
    }
    (messages, pointers)
}

// ---------------------------------------------------------------------------
// Cohere extractors
// ---------------------------------------------------------------------------

fn extract_cohere_request(body: &Value) -> (Vec<AidrMessage>, Vec<String>) {
    // Cohere Chat v2 uses the same messages[] shape as OpenAI
    if body.get("messages").is_some() {
        return extract_openai_request(body);
    }

    // Cohere Chat v1: top-level "message" + optional "chat_history"
    let mut messages = Vec::new();
    let mut pointers = Vec::new();

    if let Some(history) = body.get("chat_history").and_then(|v| v.as_array()) {
        for (i, msg) in history.iter().enumerate() {
            // Cohere uses uppercase "USER" / "CHATBOT"; normalise before matching
            let role = match msg
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("USER")
                .to_uppercase()
                .as_str()
            {
                "CHATBOT" => "assistant".to_string(),
                other => other.to_lowercase(),
            };
            if let Some(text) = msg.get("message").and_then(|v| v.as_str()) {
                messages.push(AidrMessage {
                    role,
                    content: Value::String(text.to_string()),
                });
                pointers.push(format!("/chat_history/{}/message", i));
            }
        }
    }

    if let Some(text) = body.get("message").and_then(|v| v.as_str()) {
        messages.push(AidrMessage {
            role: "user".to_string(),
            content: Value::String(text.to_string()),
        });
        pointers.push("/message".to_string());
    }

    (messages, pointers)
}

fn extract_cohere_response(body: &Value) -> (Vec<AidrMessage>, Vec<String>) {
    // Cohere Chat v2 response matches OpenAI choices[] shape
    if body.get("choices").is_some() {
        return extract_openai_response(body);
    }

    // Cohere Chat v1 response: top-level "text"
    let mut messages = Vec::new();
    let mut pointers = Vec::new();

    if let Some(text) = body.get("text").and_then(|v| v.as_str()) {
        messages.push(AidrMessage {
            role: "assistant".to_string(),
            content: Value::String(text.to_string()),
        });
        pointers.push("/text".to_string());
    }
    (messages, pointers)
}

// ---------------------------------------------------------------------------
// Bedrock extractors
// ---------------------------------------------------------------------------

fn extract_bedrock_request(body: &Value) -> (Vec<AidrMessage>, Vec<String>) {
    // Try Converse API first (system[] + messages[]), then fall through to
    // InvokeModel formats (Titan: inputText, Llama/other: prompt).
    let mut messages = Vec::new();
    let mut pointers = Vec::new();

    // Bedrock Converse API: system[] — one AidrMessage per block for independent redaction
    if let Some(system_arr) = body.get("system").and_then(|v| v.as_array()) {
        for (j, block) in system_arr.iter().enumerate() {
            if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                if !text.is_empty() {
                    messages.push(AidrMessage {
                        role: "system".to_string(),
                        content: Value::String(text.to_string()),
                    });
                    pointers.push(format!("/system/{}/text", j));
                }
            }
        }
    }

    if let Some(arr) = body.get("messages").and_then(|v| v.as_array()) {
        for (i, msg) in arr.iter().enumerate() {
            let role = msg
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("user")
                .to_string();
            let content = msg.get("content").cloned().unwrap_or(Value::Null);
            if content.is_null() {
                continue;
            }
            let flat = match flatten_content(&content) {
                Some(s) => s,
                None => {
                    logger::debug!("AIDR: unrecognised content block type; submitting raw JSON for inspection");
                    content.to_string()
                }
            };
            if !flat.is_empty() {
                messages.push(AidrMessage {
                    role,
                    content: Value::String(flat),
                });
                pointers.push(format!("/messages/{}/content", i));
            }
        }
        // If we extracted any Converse messages, don't fall through to InvokeModel paths
        if !messages.is_empty() {
            return (messages, pointers);
        }
    }

    // Bedrock InvokeModel — Titan: {"inputText": "..."}
    if let Some(text) = body.get("inputText").and_then(|v| v.as_str()) {
        messages.push(AidrMessage {
            role: "user".to_string(),
            content: Value::String(text.to_string()),
        });
        pointers.push("/inputText".to_string());
        return (messages, pointers);
    }

    // Bedrock InvokeModel — Llama / other: {"prompt": "..."}
    if let Some(text) = body.get("prompt").and_then(|v| v.as_str()) {
        messages.push(AidrMessage {
            role: "user".to_string(),
            content: Value::String(text.to_string()),
        });
        pointers.push("/prompt".to_string());
    }

    (messages, pointers)
}

fn extract_bedrock_response(body: &Value) -> (Vec<AidrMessage>, Vec<String>) {
    let mut messages = Vec::new();
    let mut pointers = Vec::new();

    // Bedrock Converse API response: output.message.content[]{text}
    // One AidrMessage per text block so each block has its own redaction pointer.
    if let Some(output) = body.get("output") {
        if let Some(msg) = output.get("message") {
            if let Some(content) = msg.get("content").and_then(|v| v.as_array()) {
                for (k, block) in content.iter().enumerate() {
                    if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                        messages.push(AidrMessage {
                            role: "assistant".to_string(),
                            content: Value::String(text.to_string()),
                        });
                        pointers.push(format!("/output/message/content/{}/text", k));
                    }
                }
                if !messages.is_empty() {
                    return (messages, pointers);
                }
            }
        }
    }

    // Bedrock InvokeModel — Titan response: results[]{outputText}
    if let Some(results) = body.get("results").and_then(|v| v.as_array()) {
        for (i, result) in results.iter().enumerate() {
            if let Some(text) = result.get("outputText").and_then(|v| v.as_str()) {
                messages.push(AidrMessage {
                    role: "assistant".to_string(),
                    content: Value::String(text.to_string()),
                });
                pointers.push(format!("/results/{}/outputText", i));
            }
        }
        if !messages.is_empty() {
            return (messages, pointers);
        }
    }

    // Bedrock InvokeModel — Llama / other: {"generation": "..."}
    if let Some(text) = body.get("generation").and_then(|v| v.as_str()) {
        messages.push(AidrMessage {
            role: "assistant".to_string(),
            content: Value::String(text.to_string()),
        });
        pointers.push("/generation".to_string());
    }

    (messages, pointers)
}

/// Flatten complex content (array of blocks) to a plain string for AIDR.
///
/// Handles the block types that carry inspectable text across the supported providers:
///   - `{type: "text", text: "..."}` — OpenAI / Anthropic standard text block
///   - `{type: "tool_result", content: [...]}` — Anthropic tool result (nested blocks)
///   - `{type: "document", source: {type: "text", data: "..."}}` — Anthropic document
///   - `{type: "input_text", text: "..."}` — Bedrock Converse untyped variant
///   - `{text: "..."}` (no `type` field) — bare Bedrock Converse text block
///
/// Returns `None` when the input is a non-empty array/object but nothing could be
/// extracted — the caller should treat this as a failure rather than an allow.
fn flatten_content(content: &Value) -> Option<String> {
    match content {
        Value::String(s) => Some(s.clone()),
        Value::Array(blocks) if blocks.is_empty() => Some(String::new()),
        Value::Array(blocks) => {
            let mut parts: Vec<String> = Vec::new();
            for b in blocks {
                match b.get("type").and_then(|t| t.as_str()) {
                    Some("text") | Some("input_text") => {
                        if let Some(text) = b.get("text").and_then(|t| t.as_str()) {
                            parts.push(text.to_string());
                        }
                    }
                    Some("tool_result") => {
                        // Nested content array inside a tool_result block
                        if let Some(inner) = b.get("content") {
                            if let Some(flat) = flatten_content(inner) {
                                if !flat.is_empty() {
                                    parts.push(flat);
                                }
                            }
                        }
                    }
                    Some("document") => {
                        // Anthropic document block: source.type == "text", source.data
                        if let Some(src) = b.get("source") {
                            if src.get("type").and_then(|t| t.as_str()) == Some("text") {
                                if let Some(data) = src.get("data").and_then(|d| d.as_str()) {
                                    parts.push(data.to_string());
                                }
                            }
                        }
                    }
                    None => {
                        // Bare {text: "..."} block with no type field (Bedrock Converse)
                        if let Some(text) = b.get("text").and_then(|t| t.as_str()) {
                            parts.push(text.to_string());
                        }
                    }
                    _ => {
                        // Unknown block type — content is present but not extractable.
                        // Signal this to the caller so it can fail closed.
                        return None;
                    }
                }
            }
            Some(parts.join("\n"))
        }
        _ => Some(content.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Redaction: write AIDR-returned messages back into original body
// ---------------------------------------------------------------------------

fn apply_redactions(
    body: &mut Value,
    pointers: &[String],
    new_messages: &[AidrMessage],
) -> bool {
    if new_messages.len() != pointers.len() {
        logger::error!(
            "AIDR: redaction count mismatch — sent {} messages, received {}; skipping redaction to avoid misapplication",
            pointers.len(),
            new_messages.len(),
        );
        return false;
    }
    let mut updated = false;
    for (ptr_str, new_msg) in pointers.iter().zip(new_messages.iter()) {
        if let Some(target) = body.pointer_mut(ptr_str) {
            *target = new_msg.content.clone();
            updated = true;
        }
    }
    updated
}

// ---------------------------------------------------------------------------
// MCP helpers
// ---------------------------------------------------------------------------

/// Convert a single MCP tool definition to AIDR/OpenAI format.
fn mcp_tool_to_aidr(tool: &Value) -> Option<Value> {
    let name = tool.get("name")?.as_str()?;
    Some(json!({
        "type": "function",
        "function": {
            "name": name,
            "description": tool.get("description").cloned().unwrap_or(Value::Null),
            "parameters": tool.get("inputSchema").cloned().unwrap_or(Value::Null),
        }
    }))
}

/// Build a JSON-RPC 2.0 error response body.
fn jsonrpc_error(id: &Value, message: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "error": {
            "code": -32603,
            "message": message,
        },
        "id": id,
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// AIDR HTTP call
// ---------------------------------------------------------------------------

/// Distinguishes an AIDR service failure (unreachable/timeout) from a hard error.
/// Used to implement fail-open vs fail-closed behavior.
enum AidrError {
    /// AIDR service was unreachable, timed out, or returned a non-200 status.
    ServiceFailure(u16, String),
    /// AIDR was reached but returned an unprocessable response (encode/decode error).
    InternalError(u16, String),
}

impl AidrError {
    fn into_parts(self) -> (u16, String) {
        match self {
            AidrError::ServiceFailure(s, b) | AidrError::InternalError(s, b) => (s, b),
        }
    }
    fn is_service_failure(&self) -> bool {
        matches!(self, AidrError::ServiceFailure(_, _))
    }
}

async fn call_aidr(
    client: &HttpClient,
    config: &Config,
    event_type: &str,
    guard_input: Value,
    source_ip: Option<&str>,
) -> Result<AidrResponse, AidrError> {
    let mut req_body = json!({
        "event_type": event_type,
        "guard_input": guard_input,
    });

    if let Some(ip) = source_ip {
        req_body["source_ip"] = json!(ip);
    }

    if let Some(app_id) = &config.app_id {
        req_body["app_id"] = json!(app_id);
    }
    if let Some(user_id) = &config.user_id {
        req_body["user_id"] = json!(user_id);
    }
    if let Some(provider) = &config.llm_provider {
        let display = match provider.as_str() {
            "openai"    => "OpenAI",
            "anthropic" => "Anthropic",
            "azureai"   => "Azure OpenAI",
            "bedrock"   => "AWS Bedrock",
            "cohere"    => "Cohere",
            "gemini"    => "Google Gemini",
            "kong"      => "Kong AI Gateway",
            other       => other,
        };
        req_body["llm_provider"] = json!(display);
    }
    if let Some(model) = &config.model {
        req_body["model"] = json!(model);
    }
    if let Some(model_version) = &config.model_version {
        req_body["model_version"] = json!(model_version);
    }
    if let Some(source_location) = &config.source_location {
        req_body["source_location"] = json!(source_location);
    }
    if let Some(tenant_id) = &config.tenant_id {
        req_body["tenant_id"] = json!(tenant_id);
    }
    if let Some(collector_instance_id) = &config.collector_instance_id {
        req_body["collector_instance_id"] = json!(collector_instance_id);
    }

    let body_str = serde_json::to_string(&req_body).map_err(|e| {
        logger::error!("AIDR: failed to encode request body: {e}");
        AidrError::InternalError(500, r#"{"status":"Internal error","reason":"AIDR request encode failed"}"#.to_string())
    })?;

    let service = config.aidr_service.clone();

    let auth_header = format!("Bearer {}", config.aidr_api_key);
    let res = client
        .request(&service)
        .path("/aidr/aiguard/v1/guard_chat_completions")
        .headers(vec![
            ("Authorization", auth_header.as_str()),
            ("Content-Type", "application/json"),
        ])
        .body(body_str.as_bytes())
        .timeout(AIDR_TIMEOUT)
        .post()
        .await
        .map_err(|e| {
            logger::error!("AIDR: HTTP call failed: {e}");
            AidrError::ServiceFailure(500, r#"{"status":"Internal error","reason":"AIDR unreachable"}"#.to_string())
        })?;

    if res.status_code() != 200 {
        logger::error!("AIDR: unexpected status {}", res.status_code());
        return Err(AidrError::ServiceFailure(500, r#"{"status":"Internal error","reason":"AIDR error response"}"#.to_string()));
    }

    let parsed: AidrResponse = serde_json::from_slice(res.body()).map_err(|e| {
        logger::error!("AIDR: failed to decode response: {e}");
        AidrError::InternalError(500, r#"{"status":"Internal error","reason":"AIDR response decode failed"}"#.to_string())
    })?;

    Ok(parsed)
}

/// Handle an AIDR call error, respecting the fail_open config flag.
///
/// Returns `Some((status, body))` if the request should be rejected, or `None` to pass through
/// (only possible when fail_open=true and the error is a service failure).
fn handle_aidr_error(err: AidrError, fail_open: bool) -> Option<(u16, String)> {
    if fail_open && err.is_service_failure() {
        logger::warn!("AIDR: service unreachable, passing through (fail_open=true)");
        None
    } else {
        Some(err.into_parts())
    }
}

// ---------------------------------------------------------------------------
// Request filter
// ---------------------------------------------------------------------------

async fn request_filter(
    state: RequestState,
    config: &Config,
    client: &HttpClient,
) -> Flow<TrafficContext> {
    // ---- Headers phase: read method and content-type ----
    let headers_state = state.into_headers_state().await;
    let handler = headers_state.handler();

    let method = headers_state.method();
    if method != "POST" && method != "PUT" && method != "PATCH" {
        return Flow::Continue(TrafficContext::Unknown);
    }

    // Remove content-length before we potentially modify the body
    handler.remove_header("content-length");

    // ---- Transition to headers+body state (requires enable_stop_iteration / Flex 1.12+) ----
    let hb_state = headers_state.into_headers_body_state().await;
    let hb_handler = hb_state.handler();

    if !hb_state.contains_body() {
        return Flow::Continue(TrafficContext::Unknown);
    }

    let raw_body = hb_handler.body();
    let body: Value = match serde_json::from_slice(&raw_body) {
        Ok(v) => v,
        Err(e) => {
            logger::debug!("AIDR: request body is not JSON, skipping: {e}");
            return Flow::Continue(TrafficContext::Unknown);
        }
    };

    // ---- Detect traffic type ----
    if body.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0") {
        // MCP JSON-RPC 2.0
        let mcp_method = match body.get("method").and_then(|v| v.as_str()) {
            Some(m) => m.to_string(),
            None => return Flow::Continue(TrafficContext::Unknown),
        };
        let mcp_id = body.get("id").cloned().unwrap_or(Value::Null);

        if mcp_method == "tools/call" {
            let params = match body.get("params").and_then(|v| v.as_object()) {
                Some(p) => p,
                None => {
                    return Flow::Continue(TrafficContext::Mcp {
                        method: mcp_method,
                        id: mcp_id,
                    })
                }
            };

            let tool_name = params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let args_str = params
                .get("arguments")
                .map(|a| {
                    if a.is_object() || a.is_array() {
                        a.to_string()
                    } else {
                        a.as_str().unwrap_or("").to_string()
                    }
                })
                .unwrap_or_default();

            let content = if args_str.is_empty() {
                tool_name.to_string()
            } else {
                format!("{}: {}", tool_name, args_str)
            };

            let guard_input = json!({
                "messages": [{ "role": "user", "content": content }]
            });

            match call_aidr(client, config, "tool_input", guard_input, None).await {
                Err(err) => {
                    if let Some((status, body)) = handle_aidr_error(err, config.fail_open) {
                        return Flow::Break(
                            Response::new(status.into())
                                .with_headers(vec![(
                                    "Content-Type".to_string(),
                                    "application/json".to_string(),
                                )])
                                .with_body(body),
                        );
                    }
                }
                Ok(aidr_res) => {
                    if let Some(result) = &aidr_res.result {
                        if result.blocked.unwrap_or(false) {
                            let msg = aidr_res
                                .summary
                                .as_deref()
                                .unwrap_or("Tool call blocked by CrowdStrike AIDR policy");
                            logger::info!("AIDR: decision=BLOCKED event_type=tool_input tool={}", tool_name);
                            return Flow::Break(
                                Response::new(400)
                                    .with_headers(vec![(
                                        "Content-Type".to_string(),
                                        "application/json".to_string(),
                                    )])
                                    .with_body(jsonrpc_error(&mcp_id, msg)),
                            );
                        }
                        logger::info!("AIDR: decision=ALLOWED event_type=tool_input tool={}", tool_name);
                    }
                }
            }
        }

        return Flow::Continue(TrafficContext::Mcp {
            method: mcp_method,
            id: mcp_id,
        });
    }

    // ---- LLM request ----
    let provider = config
        .llm_provider
        .as_deref()
        .unwrap_or("openai");

    let (messages, pointers) = extract_request_messages(provider, &body);

    if messages.is_empty() {
        logger::debug!("AIDR: no messages found in LLM request, skipping");
        return Flow::Continue(TrafficContext::LlmRequest);
    }

    let aidr_messages: Vec<Value> = messages
        .iter()
        .map(|m| json!({"role": m.role, "content": m.content}))
        .collect();

    let guard_input = json!({ "messages": aidr_messages });

    match call_aidr(client, config, "input", guard_input, None).await {
        Err(err) => {
            if let Some((status, body)) = handle_aidr_error(err, config.fail_open) {
                return Flow::Break(
                    Response::new(status.into())
                        .with_headers(vec![(
                            "Content-Type".to_string(),
                            "application/json".to_string(),
                        )])
                        .with_body(body),
                );
            }
        }
        Ok(aidr_res) => {
            if let Some(result) = &aidr_res.result {
                if result.blocked.unwrap_or(false) {
                    let reason = aidr_res
                        .summary
                        .as_deref()
                        .unwrap_or("Content blocked by CrowdStrike AIDR policy");
                    logger::info!("AIDR: decision=BLOCKED event_type=input");
                    return Flow::Break(
                        Response::new(400)
                            .with_headers(vec![(
                                "Content-Type".to_string(),
                                "application/json".to_string(),
                            )])
                            .with_body(
                                json!({"status": "Prompt rejected by CrowdStrike AIDR", "reason": reason})
                                    .to_string(),
                            ),
                    );
                }

                if result.transformed.unwrap_or(false) {
                    if let Some(guard_output) = &result.guard_output {
                        if let Some(new_msgs) = &guard_output.messages {
                            if !new_msgs.is_empty() {
                                let mut new_body = body.clone();
                                if apply_redactions(&mut new_body, &pointers, new_msgs) {
                                    logger::info!("AIDR: decision=TRANSFORMED event_type=input");
                                    match serde_json::to_vec(&new_body) {
                                        Ok(encoded) => {
                                            let encoded_len = encoded.len();
                                            if let Err(e) = hb_handler.set_body(&encoded) {
                                                logger::error!("AIDR: failed to set redacted body: {e:?}");
                                            } else {
                                                hb_handler.set_header("content-length", &encoded_len.to_string());
                                            }
                                        }
                                        Err(e) => {
                                            logger::error!("AIDR: serialization of redacted body failed: {e:?}; blocking request to prevent unredacted content from reaching upstream");
                                            return Flow::Break(
                                                Response::new(500)
                                                    .with_headers(vec![(
                                                        "Content-Type".to_string(),
                                                        "application/json".to_string(),
                                                    )])
                                                    .with_body(
                                                        json!({"status": "Internal error during content inspection"}).to_string(),
                                                    ),
                                            );
                                        }
                                    }
                                } else {
                                    logger::error!("AIDR: apply_redactions failed (count mismatch or pointer error); blocking request to prevent unredacted content from reaching upstream");
                                    return Flow::Break(
                                        Response::new(500)
                                            .with_headers(vec![(
                                                "Content-Type".to_string(),
                                                "application/json".to_string(),
                                            )])
                                            .with_body(
                                                json!({"status": "Internal error during content inspection"}).to_string(),
                                            ),
                                    );
                                }
                            }
                        }
                    }
                } else {
                    logger::info!("AIDR: decision=ALLOWED event_type=input");
                }
            }
        }
    }

    Flow::Continue(TrafficContext::LlmRequest)
}

// ---------------------------------------------------------------------------
// Response filter
// ---------------------------------------------------------------------------

async fn response_filter(
    state: ResponseState,
    ctx: RequestData<TrafficContext>,
    config: &Config,
    client: &HttpClient,
) {
    let RequestData::Continue(traffic_ctx) = ctx else {
        return;
    };

    // ---- Headers phase: read status and content-type ----
    let headers_state = state.into_headers_state().await;
    let handler = headers_state.handler();

    let status = headers_state.status_code();
    if status != 200 {
        return;
    }

    let content_type = handler
        .header("content-type")
        .unwrap_or_default()
        .to_lowercase();
    let media_type = content_type.split(';').next().unwrap_or("").trim();
    if media_type == "text/event-stream"
        || media_type == "application/vnd.amazon.eventstream"
    {
        logger::debug!("AIDR: streaming response, skipping");
        return;
    }

    handler.remove_header("content-length");

    // ---- Transition to headers+body state (requires enable_stop_iteration / Flex 1.12+) ----
    let hb_state = headers_state.into_headers_body_state().await;

    if !hb_state.contains_body() {
        return;
    }

    // Read body bytes in a scoped block so the borrow on hb_state ends before
    // we call set_body() on it later.
    let (_raw_body, mut body) = {
        let h = hb_state.handler();
        let raw = h.body();
        let parsed: Value = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(e) => {
                logger::debug!("AIDR: response body is not JSON, skipping: {e}");
                return;
            }
        };
        (raw, parsed)
    };

    // We return a sentinel Option<(u16, String)> from the match block and apply
    // it after, setting ":status" + body via the headers-body handler.
    let early_response: Option<(u16, String)> = match &traffic_ctx {
        TrafficContext::Unknown => {
            // Not something we inspected on the way in; skip
            None
        }

        TrafficContext::Mcp { method, id } => {
            // JSON-RPC errors from upstream: nothing to inspect.
            // Check for a non-null error object; "error": null is not an error.
            if body.get("error").and_then(|e| e.as_object()).is_some() {
                return;
            }
            let result = match body.get("result").and_then(|v| v.as_object()) {
                Some(r) => r,
                None => return,
            };

            match method.as_str() {
                "tools/list" => {
                    let tools = match result.get("tools").and_then(|v| v.as_array()) {
                        Some(t) if !t.is_empty() => t,
                        _ => return,
                    };

                    let aidr_tools: Vec<Value> = tools
                        .iter()
                        .filter_map(mcp_tool_to_aidr)
                        .collect();

                    if aidr_tools.is_empty() {
                        return;
                    }

                    let guard_input = json!({ "tools": aidr_tools });

                    match call_aidr(client, config, "tool_listing", guard_input, None).await {
                        // Body is replaced with JSON-RPC 2.0 error format; raw AIDR body discarded.
                        Err(err) => handle_aidr_error(err, config.fail_open)
                            .map(|(s, _)| (s, jsonrpc_error(&id, "AIDR inspection failed"))),
                        Ok(aidr_res) => {
                            if let Some(result_obj) = &aidr_res.result {
                                if result_obj.blocked.unwrap_or(false) {
                                    let msg = aidr_res
                                        .summary
                                        .as_deref()
                                        .unwrap_or("Tool listing blocked by CrowdStrike AIDR policy");
                                    logger::info!("AIDR: decision=BLOCKED event_type=tool_listing");
                                    Some((400, jsonrpc_error(&id, msg)))
                                } else {
                                    logger::info!("AIDR: decision=ALLOWED event_type=tool_listing");
                                    None
                                }
                            } else {
                                None
                            }
                        }
                    }
                }

                "tools/call" => {
                    let content_arr = match result.get("content").and_then(|v| v.as_array()) {
                        Some(c) if !c.is_empty() => c,
                        _ => return,
                    };

                    let messages: Vec<Value> = content_arr
                        .iter()
                        .filter_map(|block| {
                            if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                                let text = block.get("text")?.as_str()?;
                                Some(json!({"role": "tool", "content": text}))
                            } else {
                                None
                            }
                        })
                        .collect();

                    if messages.is_empty() {
                        return;
                    }

                    let guard_input = json!({ "messages": messages });

                    match call_aidr(client, config, "tool_output", guard_input, None).await {
                        Err(err) => handle_aidr_error(err, config.fail_open)
                            .map(|(s, _)| (s, jsonrpc_error(&id, "AIDR inspection failed"))),
                        Ok(aidr_res) => {
                            if let Some(result_obj) = &aidr_res.result {
                                if result_obj.blocked.unwrap_or(false) {
                                    let msg = aidr_res
                                        .summary
                                        .as_deref()
                                        .unwrap_or("Tool output blocked by CrowdStrike AIDR policy");
                                    logger::info!("AIDR: decision=BLOCKED event_type=tool_output");
                                    Some((400, jsonrpc_error(&id, msg)))
                                } else {
                                    logger::info!("AIDR: decision=ALLOWED event_type=tool_output");
                                    None
                                }
                            } else {
                                None
                            }
                        }
                    }
                }

                _ => None,
            }
        }

        TrafficContext::LlmRequest => {
            let provider = config
                .llm_provider
                .as_deref()
                .unwrap_or("openai");

            let (messages, pointers) = extract_response_messages(provider, &body);

            if messages.is_empty() {
                logger::debug!("AIDR: no messages in LLM response, skipping");
                return;
            }

            let aidr_messages: Vec<Value> = messages
                .iter()
                .map(|m| json!({"role": m.role, "content": m.content}))
                .collect();

            let guard_input = json!({ "messages": aidr_messages });

            match call_aidr(client, config, "output", guard_input, None).await {
                Err(err) => handle_aidr_error(err, config.fail_open).map(|(s, b)| (s, b)),
                Ok(aidr_res) => {
                    if let Some(result_obj) = &aidr_res.result {
                        if result_obj.blocked.unwrap_or(false) {
                            let reason = aidr_res
                                .summary
                                .as_deref()
                                .unwrap_or("Response blocked by CrowdStrike AIDR policy");
                            logger::info!("AIDR: decision=BLOCKED event_type=output");
                            Some((
                                400,
                                json!({"status": "Response rejected by CrowdStrike AIDR", "reason": reason})
                                    .to_string(),
                            ))
                        } else {
                            if result_obj.transformed.unwrap_or(false) {
                                if let Some(guard_output) = &result_obj.guard_output {
                                    if let Some(new_msgs) = &guard_output.messages {
                                        if !new_msgs.is_empty() {
                                            if apply_redactions(&mut body, &pointers, new_msgs) {
                                                logger::info!("AIDR: decision=TRANSFORMED event_type=output");
                                                match serde_json::to_vec(&body) {
                                                    Ok(encoded) => {
                                                        let encoded_len = encoded.len();
                                                        if let Err(e) = hb_state.handler().set_body(&encoded) {
                                                            logger::error!(
                                                                "AIDR: failed to set redacted response body: {e:?}"
                                                            );
                                                        } else {
                                                            hb_state.handler().set_header("content-length", &encoded_len.to_string());
                                                        }
                                                    }
                                                    Err(e) => {
                                                        logger::error!("AIDR: serialization of redacted response failed: {e:?}; blocking response to prevent unredacted content reaching client");
                                                        // Fail closed: overwrite the response with a 500 so the
                                                        // original unredacted body never reaches the client.
                                                        hb_state.handler().set_header(":status", "500");
                                                        hb_state.handler().set_header("content-type", "application/json");
                                                        hb_state.handler().remove_header("content-length");
                                                        let _ = hb_state.handler().set_body(
                                                            json!({"status": "Internal error during content inspection"})
                                                                .to_string()
                                                                .as_bytes(),
                                                        );
                                                    }
                                                }
                                            } else {
                                                logger::error!("AIDR: apply_redactions failed (count mismatch or pointer error); blocking response to prevent unredacted content reaching client");
                                                hb_state.handler().set_header(":status", "500");
                                                hb_state.handler().set_header("content-type", "application/json");
                                                hb_state.handler().remove_header("content-length");
                                                let _ = hb_state.handler().set_body(
                                                    json!({"status": "Internal error during content inspection"})
                                                        .to_string()
                                                        .as_bytes(),
                                                );
                                            }
                                        }
                                    }
                                }
                            } else {
                                logger::info!("AIDR: decision=ALLOWED event_type=output");
                            }
                            None
                        }
                    } else {
                        None
                    }
                }
            }
        }
    };

    // Apply early response: set status code and body via headers-body handler.
    if let Some((status_code, body_str)) = early_response {
        hb_state.handler().set_header(":status", &status_code.to_string());
        hb_state.handler().set_header("content-type", "application/json");
        hb_state.handler().remove_header("content-length");
        let _ = hb_state.handler().set_body(body_str.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

#[entrypoint]
pub async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    client: HttpClient,
) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!("Failed to parse policy configuration. Cause: {}", err)
    })?;

    if config.aidr_api_key.trim().is_empty() {
        return Err(anyhow!("Policy configuration error: 'aidr_api_key' must not be empty"));
    }

    let filter = on_request(|request_state| {
        request_filter(request_state, &config, &client)
    })
    .on_response(|response_state, request_data| {
        response_filter(response_state, request_data, &config, &client)
    });

    launcher.launch(filter).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests — pure-logic functions that parse untrusted input
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- flatten_content ---------------------------------------------------

    #[test]
    fn flatten_string_content() {
        let v = json!("hello world");
        assert_eq!(flatten_content(&v), Some("hello world".to_string()));
    }

    #[test]
    fn flatten_empty_array() {
        let v = json!([]);
        assert_eq!(flatten_content(&v), Some(String::new()));
    }

    #[test]
    fn flatten_text_block() {
        let v = json!([{"type": "text", "text": "attack payload"}]);
        assert_eq!(flatten_content(&v), Some("attack payload".to_string()));
    }

    #[test]
    fn flatten_multiple_text_blocks() {
        let v = json!([
            {"type": "text", "text": "first"},
            {"type": "text", "text": "second"}
        ]);
        assert_eq!(flatten_content(&v), Some("first\nsecond".to_string()));
    }

    #[test]
    fn flatten_document_block() {
        let v = json!([{
            "type": "document",
            "source": {"type": "text", "data": "document body"}
        }]);
        assert_eq!(flatten_content(&v), Some("document body".to_string()));
    }

    #[test]
    fn flatten_tool_result_block_with_nested_text() {
        let v = json!([{
            "type": "tool_result",
            "content": [{"type": "text", "text": "tool output"}]
        }]);
        assert_eq!(flatten_content(&v), Some("tool output".to_string()));
    }

    #[test]
    fn flatten_bare_text_block_no_type_field() {
        // Bedrock Converse untyped: {"text": "..."} with no "type"
        let v = json!([{"text": "bedrock content"}]);
        assert_eq!(flatten_content(&v), Some("bedrock content".to_string()));
    }

    #[test]
    fn flatten_unknown_block_type_returns_none() {
        // An unrecognised block type must return None so callers can fail closed
        // rather than silently submitting an empty string to AIDR.
        let v = json!([{"type": "image_url", "image_url": {"url": "https://example.com/img.png"}}]);
        assert_eq!(flatten_content(&v), None);
    }

    #[test]
    fn flatten_mixed_known_and_unknown_returns_none() {
        // Even one unrecognised block should bubble up as None.
        let v = json!([
            {"type": "text", "text": "visible"},
            {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}}
        ]);
        assert_eq!(flatten_content(&v), None);
    }

    // ---- extract_openai_request --------------------------------------------

    #[test]
    fn openai_request_string_content() {
        let body = json!({"messages": [{"role": "user", "content": "hello"}]});
        let (msgs, ptrs) = extract_openai_request(&body);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, json!("hello"));
        assert_eq!(ptrs[0], "/messages/0/content");
    }

    #[test]
    fn openai_request_array_text_content() {
        let body = json!({
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]
        });
        let (msgs, _) = extract_openai_request(&body);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, json!("hi"));
    }

    #[test]
    fn openai_request_unknown_block_type_submits_raw_json() {
        // A message with an unrecognised block type (e.g. image_url) must still
        // produce an AidrMessage — the raw JSON is serialised so AIDR makes an
        // explicit decision rather than silently passing uninspected content.
        let body = json!({
            "messages": [
                {"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}}
                ]}
            ]
        });
        let (msgs, _) = extract_openai_request(&body);
        assert_eq!(msgs.len(), 1, "unknown block type must still produce an AidrMessage");
        // Content should be the raw JSON of the content array
        assert!(msgs[0].content.as_str().unwrap_or("").contains("image_url"));
    }

    #[test]
    fn openai_request_null_content_skipped() {
        let body = json!({"messages": [{"role": "assistant", "content": null}]});
        let (msgs, _) = extract_openai_request(&body);
        assert!(msgs.is_empty());
    }

    // ---- extract_anthropic_request -----------------------------------------

    #[test]
    fn anthropic_request_string_system() {
        let body = json!({
            "system": "you are helpful",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let (msgs, ptrs) = extract_anthropic_request(&body);
        assert_eq!(msgs[0].role, "system");
        assert_eq!(msgs[0].content, json!("you are helpful"));
        assert_eq!(ptrs[0], "/system");
    }

    #[test]
    fn anthropic_request_array_system() {
        // Array-form system was previously silently dropped (Vuln 1).
        let body = json!({
            "system": [{"type": "text", "text": "injected system prompt"}],
            "messages": [{"role": "user", "content": "hi"}]
        });
        let (msgs, ptrs) = extract_anthropic_request(&body);
        let system_msg = msgs.iter().find(|m| m.role == "system");
        assert!(system_msg.is_some(), "array-form system must be extracted");
        assert_eq!(system_msg.unwrap().content, json!("injected system prompt"));
        assert!(ptrs.contains(&"/system".to_string()));
    }

    #[test]
    fn anthropic_request_empty_array_system_not_included() {
        let body = json!({
            "system": [],
            "messages": [{"role": "user", "content": "hi"}]
        });
        let (msgs, _) = extract_anthropic_request(&body);
        assert!(
            msgs.iter().all(|m| m.role != "system"),
            "empty system array should not produce a system message"
        );
    }

    #[test]
    fn anthropic_request_messages_included() {
        let body = json!({
            "messages": [
                {"role": "user", "content": "first"},
                {"role": "assistant", "content": "second"}
            ]
        });
        let (msgs, _) = extract_anthropic_request(&body);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "user");
        assert_eq!(msgs[1].role, "assistant");
    }

    // ---- extract_anthropic_response ----------------------------------------

    #[test]
    fn anthropic_response_extracts_text_blocks() {
        let body = json!({
            "content": [
                {"type": "text", "text": "response text"}
            ]
        });
        let (msgs, ptrs) = extract_anthropic_response(&body);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, json!("response text"));
        assert_eq!(ptrs[0], "/content/0/text");
    }

    #[test]
    fn anthropic_response_skips_non_text_blocks() {
        let body = json!({
            "content": [
                {"type": "tool_use", "id": "tu_1", "name": "get_weather", "input": {"location": "NY"}},
                {"type": "text", "text": "the weather is sunny"}
            ]
        });
        let (msgs, ptrs) = extract_anthropic_response(&body);
        assert_eq!(msgs.len(), 1, "only text blocks should be extracted");
        assert_eq!(msgs[0].content, json!("the weather is sunny"));
        assert_eq!(ptrs[0], "/content/1/text");
    }

    // ---- extract_gemini_request / response ---------------------------------

    #[test]
    fn gemini_request_contents_extracted() {
        let body = json!({
            "contents": [
                {"role": "user", "parts": [{"text": "hello"}]}
            ]
        });
        let (msgs, ptrs) = extract_gemini_request(&body);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].role, "user");
        assert_eq!(msgs[0].content, json!("hello"));
        assert_eq!(ptrs[0], "/contents/0/parts/0/text");
    }

    #[test]
    fn gemini_request_model_role_normalised_to_assistant() {
        let body = json!({
            "contents": [
                {"role": "model", "parts": [{"text": "response"}]}
            ]
        });
        let (msgs, _) = extract_gemini_request(&body);
        assert_eq!(msgs[0].role, "assistant");
    }

    #[test]
    fn gemini_request_system_instruction_extracted() {
        let body = json!({
            "systemInstruction": {"parts": [{"text": "you are a helpful assistant"}]},
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
        });
        let (msgs, ptrs) = extract_gemini_request(&body);
        let sys = msgs.iter().find(|m| m.role == "system");
        assert!(sys.is_some());
        assert_eq!(sys.unwrap().content, json!("you are a helpful assistant"));
        assert!(ptrs.contains(&"/systemInstruction/parts/0/text".to_string()));
    }

    #[test]
    fn gemini_response_candidates_extracted() {
        let body = json!({
            "candidates": [
                {"content": {"parts": [{"text": "model reply"}], "role": "model"}}
            ]
        });
        let (msgs, ptrs) = extract_gemini_response(&body);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, json!("model reply"));
        assert_eq!(ptrs[0], "/candidates/0/content/parts/0/text");
    }

    // ---- extract_cohere_request / response ---------------------------------

    #[test]
    fn cohere_request_v1_message_and_history_extracted() {
        let body = json!({
            "message": "current question",
            "chat_history": [
                {"role": "USER", "message": "prev question"},
                {"role": "CHATBOT", "message": "prev answer"}
            ]
        });
        let (msgs, ptrs) = extract_cohere_request(&body);
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].role, "user");
        assert_eq!(msgs[0].content, json!("prev question"));
        assert_eq!(msgs[1].role, "assistant");
        assert_eq!(msgs[2].role, "user");
        assert_eq!(msgs[2].content, json!("current question"));
        assert_eq!(ptrs[2], "/message");
    }

    #[test]
    fn cohere_request_v2_delegates_to_openai() {
        let body = json!({
            "messages": [{"role": "user", "content": "hi"}]
        });
        let (msgs, _) = extract_cohere_request(&body);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, json!("hi"));
    }

    #[test]
    fn cohere_response_v1_text_extracted() {
        let body = json!({"text": "cohere answer"});
        let (msgs, ptrs) = extract_cohere_response(&body);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, json!("cohere answer"));
        assert_eq!(ptrs[0], "/text");
    }

    // ---- extract_bedrock_request / response --------------------------------

    #[test]
    fn bedrock_converse_request_extracted() {
        let body = json!({
            "system": [{"text": "system prompt"}],
            "messages": [
                {"role": "user", "content": [{"text": "hello"}]}
            ]
        });
        let (msgs, ptrs) = extract_bedrock_request(&body);
        let sys = msgs.iter().find(|m| m.role == "system");
        assert!(sys.is_some());
        assert_eq!(sys.unwrap().content, json!("system prompt"));
        let user = msgs.iter().find(|m| m.role == "user");
        assert!(user.is_some());
        assert_eq!(user.unwrap().content, json!("hello"));
        assert!(ptrs.contains(&"/system/0/text".to_string()));
    }

    #[test]
    fn bedrock_titan_invoke_extracted() {
        let body = json!({"inputText": "titan prompt"});
        let (msgs, ptrs) = extract_bedrock_request(&body);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, json!("titan prompt"));
        assert_eq!(ptrs[0], "/inputText");
    }

    #[test]
    fn bedrock_llama_invoke_extracted() {
        let body = json!({"prompt": "llama prompt"});
        let (msgs, ptrs) = extract_bedrock_request(&body);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, json!("llama prompt"));
        assert_eq!(ptrs[0], "/prompt");
    }

    #[test]
    fn bedrock_converse_response_extracted() {
        let body = json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "bedrock response"}]
                }
            }
        });
        let (msgs, ptrs) = extract_bedrock_response(&body);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, json!("bedrock response"));
        assert_eq!(ptrs[0], "/output/message/content/0/text");
    }

    #[test]
    fn gemini_request_multipart_produces_one_message_per_part() {
        // Each text part must get its own AidrMessage + pointer so AIDR can
        // independently redact later parts without affecting earlier ones.
        let body = json!({
            "contents": [
                {"role": "user", "parts": [{"text": "first"}, {"text": "second"}]}
            ]
        });
        let (msgs, ptrs) = extract_gemini_request(&body);
        assert_eq!(msgs.len(), 2, "each part must become a separate AidrMessage");
        assert_eq!(msgs[0].content, json!("first"));
        assert_eq!(msgs[1].content, json!("second"));
        assert_eq!(ptrs[0], "/contents/0/parts/0/text");
        assert_eq!(ptrs[1], "/contents/0/parts/1/text");
    }

    #[test]
    fn gemini_request_multipart_system_instruction_each_part_has_pointer() {
        let body = json!({
            "systemInstruction": {
                "parts": [{"text": "safe preamble"}, {"text": "injected system"}]
            },
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
        });
        let (msgs, ptrs) = extract_gemini_request(&body);
        let sys_msgs: Vec<_> = msgs.iter().filter(|m| m.role == "system").collect();
        assert_eq!(sys_msgs.len(), 2, "each system part must be a separate message");
        assert_eq!(ptrs[0], "/systemInstruction/parts/0/text");
        assert_eq!(ptrs[1], "/systemInstruction/parts/1/text");
    }

    #[test]
    fn bedrock_converse_response_multiblock_each_block_has_pointer() {
        // Multiple content blocks must each have an individual redaction pointer.
        let body = json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "first block"}, {"text": "second block"}]
                }
            }
        });
        let (msgs, ptrs) = extract_bedrock_response(&body);
        assert_eq!(msgs.len(), 2, "each content block must be a separate message");
        assert_eq!(ptrs[0], "/output/message/content/0/text");
        assert_eq!(ptrs[1], "/output/message/content/1/text");
    }

    #[test]
    fn bedrock_converse_system_multiblock_each_block_has_pointer() {
        let body = json!({
            "system": [{"text": "block one"}, {"text": "block two"}],
            "messages": [{"role": "user", "content": [{"text": "hi"}]}]
        });
        let (msgs, ptrs) = extract_bedrock_request(&body);
        let sys_msgs: Vec<_> = msgs.iter().filter(|m| m.role == "system").collect();
        assert_eq!(sys_msgs.len(), 2);
        assert_eq!(ptrs[0], "/system/0/text");
        assert_eq!(ptrs[1], "/system/1/text");
    }
}
