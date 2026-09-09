// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//! DeepSeek backend. DeepSeek's API is OpenAI-Chat-Completions-compatible,
//! so this is a thin, independently-configured wrapper around the same
//! request/response shape as `openai.rs` (kept separate so the two
//! providers can diverge in the future without entangling their code).

use super::{ExplainRequest, LlmBackend};
use crate::config::ProviderConfig;
use anyhow::{Context, Result};
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
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
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

impl LlmBackend for DeepSeekBackend {
    fn explain(&self, request: &ExplainRequest) -> Result<String> {
        let url = format!("{}/chat/completions", self.base_url);
        let body = ChatRequest {
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
        };

        let response: ChatResponse = ureq::post(&url)
            .timeout(self.timeout)
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .set("Content-Type", "application/json")
            .send_json(&body)
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
