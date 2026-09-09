// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//! Outbound-only Telegram alerting.
//!
//! This client does exactly one thing: call the Bot API's
//! `sendMessage` endpoint with a preconfigured `chat_id`. There is:
//!   - no long-polling `getUpdates` loop,
//!   - no webhook listener,
//!   - no inbound command parser,
//!   - no pairing/handshake flow of any kind.
//! The bot token and chat id are read once from the local config file
//! that the user filled in themselves; trust is established entirely
//! out-of-band (the user created the bot and copied the token in).

use crate::config::TelegramConfig;
use anyhow::{Context, Result};
use serde::Serialize;

pub struct TelegramNotifier {
    bot_token: String,
    chat_id: Option<i64>,
    enabled: bool,
}

#[derive(Serialize)]
struct SendMessageRequest<'a> {
    chat_id: i64,
    text: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_mode: Option<&'a str>,
    disable_web_page_preview: bool,
}

impl TelegramNotifier {
    pub fn new(cfg: &TelegramConfig) -> Self {
        Self {
            bot_token: cfg.bot_token.clone(),
            chat_id: cfg.chat_id,
            enabled: cfg.enabled,
        }
    }

    /// Send a plain-text alert. Best-effort: logs and returns an error
    /// on failure rather than panicking, since a Telegram outage should
    /// never take the whole watchdog down.
    pub fn send(&self, text: &str) -> Result<()> {
        if !self.enabled {
            log::debug!("telegram disabled in config; suppressing message: {text}");
            return Ok(());
        }

        // No paired chat yet — this notifier is outbound-only and cannot
        // initiate pairing, so it simply doesn't send until the interactive
        // bot binds a chat_id.
        let Some(chat_id) = self.chat_id else {
            log::debug!("telegram not paired yet; suppressing message: {text}");
            return Ok(());
        };

        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        let body = SendMessageRequest {
            chat_id,
            text,
            parse_mode: Some("Markdown"),
            disable_web_page_preview: true,
        };

        // `ureq` with the `tls` feature uses `rustls` under the hood —
        // no OpenSSL, no vendored C TLS stack, fully portable.
        let response = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_json(&body)
            .context("sending Telegram alert")?;

        anyhow::ensure!(
            response.status() == 200,
            "Telegram API returned non-200 status: {}",
            response.status()
        );

        Ok(())
    }
}
