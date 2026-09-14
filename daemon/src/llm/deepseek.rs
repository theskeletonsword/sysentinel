// SPDX-License-Identifier: Apache-2.0
//! DeepSeek backend. DeepSeek's API is OpenAI-Chat-Completions-compatible,
//! so this is a thin, independently-configured wrapper around the same
//! request/response shape as `openai.rs` (kept separate so the two
//! providers can diverge in the future without entangling their code).

use super::{ChatRequest, ExplainRequest, LlmBackend};
use crate::config::ProviderConfig;
use anyhow::{Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub struct DeepSeekBackend {
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: u32,
    timeout: Duration,
}

impl DeepSeekBackend {
    pub fn new(provider: &ProviderConfig, model: &str, max_tokens: u32, timeout: Duration) -> Self {
        Self {
            api_key: provider.api_key.clone(),
            base_url: provider.base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            max_tokens,
            timeout,
        }
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

impl DeepSeekBackend {
    fn completions_url(&self) -> String {
        format!("{}/chat/completions", self.base_url)
    }

    fn call_api<B: serde::Serialize>(&self, url: &str, body: &B) -> Result<String> {
        crate::httpsec::require_https(url)?;
        let response: ChatResponse = crate::httpsec::shared()
            .post(url)
            .timeout(self.timeout)
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .set("Content-Type", "application/json")
            .send_json(body)
            .context("calling DeepSeek chat completions API")?
            .into_json()
            .context("parsing DeepSeek response body")?;
        response
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .context("DeepSeek response contained no choices")
    }
}

impl LlmBackend for DeepSeekBackend {
    fn explain(&self, request: &ExplainRequest) -> Result<String> {
        let url = self.completions_url();
        let body = ApiChatRequest {
            model: &self.model,
            messages: vec![
                ChatMessage { role: "system", content: request.system_prompt },
                ChatMessage { role: "user",   content: request.event_text },
            ],
            max_tokens: request.max_tokens.max(self.max_tokens),
        };
        self.call_api(&url, &body)
    }

    fn chat_with_image(&self, request: &ChatRequest, image_jpeg: &[u8]) -> Result<String> {
        let url = self.completions_url();
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
        self.call_api(&url, &body)
    }
}
