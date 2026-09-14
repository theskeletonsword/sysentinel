// SPDX-License-Identifier: Apache-2.0
//! OpenAI Chat Completions backend.

use super::{ChatRequest, ExplainRequest, LlmBackend};
use crate::config::ProviderConfig;
use anyhow::{Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub struct OpenAiBackend {
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: u32,
    /// Optional `n_ctx` sent to the server (used by llama.cpp to cap context
    /// per request; adjustable live via `/settings llama_ctx`).
    n_ctx: Option<u32>,
    /// Per-request deadline; after it the backend is treated as failed and the
    /// fallback chain moves on.
    timeout: Duration,
}

impl OpenAiBackend {
    pub fn new(provider: &ProviderConfig, model: &str, max_tokens: u32, timeout: Duration) -> Self {
        Self {
            api_key: provider.api_key.clone(),
            base_url: provider.base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            max_tokens,
            n_ctx: None,
            timeout,
        }
    }

    /// Set the requested context length for this provider (llama.cpp only).
    pub fn set_ctx(&mut self, tokens: u32) {
        self.n_ctx = (tokens > 0).then_some(tokens);
    }
}

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct ApiChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    n_ctx: Option<u32>,
}

// ── Multimodal (vision) structures ───────────────────────────────────────────

#[derive(Serialize)]
struct VisionMessage {
    role: &'static str,
    content: Vec<VisionContent>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum VisionContent {
    Text { text: String },
    ImageUrl { image_url: ImageUrl },
}

#[derive(Serialize)]
struct ImageUrl {
    url: String,
}

#[derive(Serialize)]
struct VisionChatRequest<'a> {
    model: &'a str,
    messages: Vec<VisionMessage>,
    max_tokens: u32,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    content: String,
}

impl LlmBackend for OpenAiBackend {
    fn explain(&self, request: &ExplainRequest) -> Result<String> {
        let url = format!("{}/chat/completions", self.base_url);
        let body = ApiChatRequest {
            model: &self.model,
            messages: vec![
                ChatMessage {
                    role: "system",
                    content: request.system_prompt,
                },
                ChatMessage {
                    role: "user",
                    content: request.event_text,
                },
            ],
            max_tokens: request.max_tokens.max(self.max_tokens),
            n_ctx: self.n_ctx,
        };

        // Re-checked here, not only at config load: a file can be edited
        // after it was validated, and this is the request that carries the
        // API key.
        crate::httpsec::require_https(&url)?;
        let response: ChatResponse = crate::httpsec::shared()
            .post(&url)
            .timeout(self.timeout)
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .set("Content-Type", "application/json")
            .send_json(&body)
            .context("calling OpenAI chat completions API")?
            .into_json()
            .context("parsing OpenAI response body")?;

        response
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .context("OpenAI response contained no choices")
    }

    fn chat_with_image(&self, request: &ChatRequest, image_jpeg: &[u8]) -> Result<String> {
        let url = format!("{}/chat/completions", self.base_url);
        let b64 = base64::engine::general_purpose::STANDARD.encode(image_jpeg);
        let data_url = format!("data:image/jpeg;base64,{b64}");

        let mut user_text = String::new();
        if !request.system_context.is_empty() {
            user_text.push_str(&format!("System state:\n{}\n---\n", request.system_context));
        }
        if !request.conversation_history.is_empty() {
            user_text.push_str(&format!("History:\n{}\n---\n", request.conversation_history));
        }
        if !request.user_message.is_empty() {
            user_text.push_str(request.user_message);
        } else {
            user_text.push_str("What do you see in this image?");
        }

        let body = VisionChatRequest {
            model: &self.model,
            messages: vec![
                VisionMessage {
                    role: "system",
                    content: vec![VisionContent::Text { text: request.system_prompt.to_string() }],
                },
                VisionMessage {
                    role: "user",
                    content: vec![
                        VisionContent::Text { text: user_text },
                        VisionContent::ImageUrl { image_url: ImageUrl { url: data_url } },
                    ],
                },
            ],
            max_tokens: request.max_tokens.max(self.max_tokens),
        };
        crate::httpsec::require_https(&url)?;
        let response: ChatResponse = crate::httpsec::shared()
            .post(&url)
            .timeout(self.timeout)
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .set("Content-Type", "application/json")
            .send_json(&body)
            .context("calling OpenAI vision API")?
            .into_json()
            .context("parsing OpenAI vision response")?;
        response
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .context("OpenAI vision response contained no choices")
    }
}
