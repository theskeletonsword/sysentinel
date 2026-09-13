// SPDX-License-Identifier: Apache-2.0
//! Anthropic Messages API backend.

use super::{ExplainRequest, LlmBackend};
use crate::config::ProviderConfig;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub struct AnthropicBackend {
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: u32,
    timeout: Duration,
}

impl AnthropicBackend {
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
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    system: &'a str,
    messages: Vec<Message<'a>>,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct MessagesResponse {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    #[serde(default)]
    text: String,
}

impl LlmBackend for AnthropicBackend {
    fn explain(&self, request: &ExplainRequest) -> Result<String> {
        let url = format!("{}/messages", self.base_url);
        let body = MessagesRequest {
            model: &self.model,
            max_tokens: request.max_tokens.max(self.max_tokens),
            system: request.system_prompt,
            messages: vec![Message {
                role: "user",
                content: request.event_text,
            }],
        };

        // Re-checked here, not only at config load: a file can be edited
        // after it was validated, and this is the request that carries the
        // API key.
        crate::httpsec::require_https(&url)?;
        let response: MessagesResponse = crate::httpsec::shared()
            .post(&url)
            .timeout(self.timeout)
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", "2023-06-01")
            .set("Content-Type", "application/json")
            .send_json(&body)
            .context("calling Anthropic messages API")?
            .into_json()
            .context("parsing Anthropic response body")?;

        let text = response
            .content
            .into_iter()
            .map(|b| b.text)
            .collect::<Vec<_>>()
            .join("");

        anyhow::ensure!(!text.is_empty(), "Anthropic response contained no text content");
        Ok(text)
    }
}
