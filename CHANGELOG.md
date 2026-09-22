# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-09-02

### Added
- Initial release of the CrowdStrike AIDR policy for MuleSoft Omni Gateway.
- LLM request inspection (`input` event): blocks prompt injection, PII leakage, and jailbreak attempts.
- LLM response inspection (`output` event): blocks dangerous or sensitive content in model responses.
- LLM request redaction (`transformed`): rewrites flagged content in-place before forwarding to the LLM.
- LLM response redaction (`transformed`): rewrites flagged content in-place before returning to the client.
- MCP JSON-RPC 2.0 support:
  - `tools/call` request inspection (`tool_input` event).
  - `tools/call` response inspection (`tool_output` event).
  - `tools/list` response inspection (`tool_listing` event) to detect poisoned tool descriptions.
- Multi-provider support: OpenAI, Anthropic, Azure OpenAI, AWS Bedrock, Cohere, Google Gemini, Kong AI Gateway.
- Streaming bypass: SSE (`text/event-stream`) and Amazon EventStream responses pass through uninspected to avoid buffering.
- Configurable metadata forwarding to AIDR: `app_id`, `user_id`, `model`, `model_version`, `source_location`, `tenant_id`, `collector_instance_id`.
- `fail_open` configuration option (default: `false`): when `true`, passes traffic through if the AIDR service is unreachable rather than returning HTTP 500.
- Explicit 10-second timeout on all AIDR API calls.
- INFO-level decision logging for all AIDR decisions (BLOCKED, ALLOWED, TRANSFORMED).
- `content-length` header correctly recalculated after body redaction.

### Requirements
- MuleSoft Omni Gateway **1.12.0 or later** (requires body buffering via `enable_stop_iteration`).
- CrowdStrike AIDR API credentials (Bearer token).

### Known Limitations
- Streaming responses (SSE, EventStream) are not inspected. Apply AIDR inspection upstream or use non-streaming endpoints where security inspection is required.
- Binary or non-JSON request/response bodies are not inspected and pass through unmodified.
- Non-200 upstream responses pass through uninspected.
