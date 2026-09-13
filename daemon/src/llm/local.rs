// SPDX-License-Identifier: Apache-2.0
//! Local GGUF inference backend, built only when compiled with
//! `--features local-llm`. Kept out of the default build because it
//! pulls in a C++ compilation step (llama.cpp) — cloud backends need
//! nothing beyond the default feature set.

use super::{ExplainRequest, LlmBackend};
use anyhow::{Context, Result};
use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::AddBos;
use llama_cpp_2::model::LlamaModel;
use llama_cpp_2::sampling::LlamaSampler;
use std::path::Path;
use std::sync::Mutex;

pub struct LocalBackend {
    backend: LlamaBackend,
    model: LlamaModel,
    ctx_size: u32,
    /// Vision projector (`*-mmproj-*.gguf`) resolved for the selected model.
    /// Wiring vision input through `llama-cpp-2` v0.1 is not exposed yet; the
    /// full vision path runs via `llama-server` (`/models <name>` prints the
    /// command). Kept so the resolved companion is visible/loggable here.
    #[allow(dead_code)]
    mmproj_path: Option<std::path::PathBuf>,
    /// MTP companion (`mtp-*.gguf`) resolved for the selected model. Same
    /// caveat as `mmproj_path`: draft-MTP is consumed by `llama-server`.
    #[allow(dead_code)]
    mtp_path: Option<std::path::PathBuf>,
    state: Mutex<()>, // serializes inference; llama.cpp context is not Sync-safe to share concurrently
}

impl LocalBackend {
    pub fn new(
        main_model: &Path,
        mmproj_path: Option<&Path>,
        mtp_path: Option<&Path>,
        ctx_size: u32,
    ) -> Result<Self> {
        let backend = LlamaBackend::init().context("initializing llama.cpp backend")?;
        let model_params = LlamaModelParams::default();
        let model = LlamaModel::load_from_file(&backend, main_model, &model_params)
            .with_context(|| format!("loading local GGUF model from {}", main_model.display()))?;

        Ok(Self {
            backend,
            model,
            ctx_size,
            mmproj_path: mmproj_path.map(|p| p.to_path_buf()),
            mtp_path: mtp_path.map(|p| p.to_path_buf()),
            state: Mutex::new(()),
        })
    }
}

impl LlmBackend for LocalBackend {
    fn explain(&self, request: &ExplainRequest) -> Result<String> {
        let _guard = self.state.lock().expect("local LLM mutex poisoned");

        let prompt = format!(
            "{system}\n\nKernel event to explain:\n{event}\n\nExplanation:",
            system = request.system_prompt,
            event = request.event_text,
        );

        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(std::num::NonZeroU32::new(self.ctx_size))
            .with_n_batch(self.ctx_size.max(1024));
        let mut ctx = self
            .model
            .new_context(&self.backend, ctx_params)
            .context("creating local llama.cpp inference context")?;

        let prompt_tokens = self
            .model
            .str_to_token(&prompt, AddBos::Always)
            .context("tokenizing local LLM prompt")?;

        let batch_capacity = usize::try_from(ctx.n_batch()).unwrap_or(512).max(prompt_tokens.len() + 1);
        let mut batch = LlamaBatch::new(batch_capacity, 1);
        batch
            .add_sequence(&prompt_tokens, 0, false)
            .context("adding local LLM prompt to inference batch")?;
        ctx.decode(&mut batch)
            .context("decoding local LLM prompt")?;

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let mut sampler = LlamaSampler::chain_simple([
            LlamaSampler::temp(0.8),
            LlamaSampler::top_k(40),
            LlamaSampler::top_p(0.95, 1),
            LlamaSampler::dist(seed),
        ]);

        let mut output: Vec<u8> = Vec::new();
        let mut n_generated = 0usize;
        let mut pos = i32::try_from(prompt_tokens.len()).expect("prompt token count fits into i32");

        while n_generated < request.max_tokens as usize {
            let idx = batch.n_tokens() - 1;
            let token = sampler.sample(&ctx, idx);
            if self.model.is_eog_token(token) {
                break;
            }

            let piece = match self
                .model
                .token_to_piece_bytes(token, 256, false, None)
            {
                Err(llama_cpp_2::TokenToStringError::InsufficientBufferSpace(n)) => {
                    let size = usize::try_from(-n).expect("negative buffer size fits into usize");
                    self.model.token_to_piece_bytes(token, size, false, None)?
                }
                other => other?,
            };
            output.extend_from_slice(&piece);

            n_generated += 1;
            batch.clear();
            batch
                .add(token, pos, &[0], true)
                .context("adding local LLM output token to batch")?;
            pos += 1;
            ctx.decode(&mut batch)
                .context("decoding local LLM output token")?;
        }

        Ok(String::from_utf8_lossy(&output).into_owned())
    }
}
