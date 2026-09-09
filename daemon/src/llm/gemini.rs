// SPDX-License-Identifier: Apache-2.0
//! Google Gemini backend, using the `generateContent` REST endpoint.

use super::{ExplainRequest, LlmBackend};
use crate::config::ProviderConfig;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub struct GeminiBackend {
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: u32,
    timeout: Duration,
}

impl GeminiBackend {
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
struct GenerateContentRequest<'a> {
    system_instruction: SystemInstruction<'a>,
    contents: Vec<Content<'a>>,
    #[serde(rename = "generationConfig")]
    generation_config: GenerationConfig,
}

#[derive(Serialize)]
struct SystemInstruction<'a> {
    parts: Vec<Part<'a>>,
}

#[derive(Serialize)]
struct Content<'a> {
    role: &'a str,
    parts: Vec<Part<'a>>,
}

#[derive(Serialize)]
struct Part<'a> {
    text: &'a str,
}

#[derive(Serialize)]
struct GenerationConfig {
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: u32,
}

#[derive(Deserialize)]
struct GenerateContentResponse {
    candidates: Vec<Candidate>,
}

#[derive(Deserialize)]
struct Candidate {
    content: CandidateContent,
}

#[derive(Deserialize)]
struct CandidateContent {
    parts: Vec<ResponsePart>,
}

#[derive(Deserialize)]
struct ResponsePart {
    #[serde(default)]
    text: String,
}

impl LlmBackend for GeminiBackend {
    fn explain(&self, request: &ExplainRequest) -> Result<String> {
        let url = format!(
            "{}/models/{}:generateContent?key={}",
            self.base_url, self.model, self.api_key
        );

        let body = GenerateContentRequest {
            system_instruction: SystemInstruction {
                parts: vec![Part {
                    text: request.system_prompt,
                }],
            },
            contents: vec![Content {
                role: "user",
                parts: vec![Part {
                    text: request.event_text,
                }],
            }],
            generation_config: GenerationConfig {
                max_output_tokens: request.max_tokens.max(self.max_tokens),
            },
        };

        let response: GenerateContentResponse = ureq::post(&url)
            .timeout(self.timeout)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .context("calling Gemini generateContent API")?
            .into_json()
            .context("parsing Gemini response body")?;

        let text = response
            .candidates
            .into_iter()
            .next()
            .context("Gemini response contained no candidates")?
            .content
            .parts
            .into_iter()
            .map(|p| p.text)
            .collect::<Vec<_>>()
            .join("");

        anyhow::ensure!(!text.is_empty(), "Gemini response contained no text content");
        Ok(text)
    }
}
