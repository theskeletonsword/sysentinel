#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Launch llama-server for the "llama" LLM backend with hardware dispatch:
#   CUDA  → full GPU offload ( -ngl 99 )          [NVIDIA]
#   Vulkan→ full GPU offload ( -ngl 99 )          [AMD / NVIDIA / Intel]
#   else  → CPU via OpenBLAS   ( -ngl 0  )         [any machine]
#
# The daemon talks to this server via [llm.llama] base_url (127.0.0.1:8080).
# Portable: relies only on the prebuilt /opt/llama.cpp (dynamic backends).

set -euo pipefail

LLAMA_BIN="${LLAMA_BIN:-/opt/llama.cpp/bin/llama-server}"
MODEL_DIR="${MODEL_DIR:-/opt/sysentinel/models}"
MODEL="${MODEL:-$MODEL_DIR/Qwen3.5-0.8B-Q4_0.gguf}"
PORT="${PORT:-8080}"
CTX="${CTX:-4096}"

# ── Pick the most capable hardware backend available ─────────────────────────
NGL=0
DEVICE_ARGS=()

if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
    echo "[llama-link] NVIDIA GPU detected → full CUDA offload"
    NGL=99
    # Prefer device 0 (primary NVIDIA GPU). Empty string lets llama.cpp pick.
    : "${CUDA_VISIBLE_DEVICES:=0}"
    export CUDA_VISIBLE_DEVICES
elif command -v glxinfo >/dev/null 2>&1 && glxinfo 2>/dev/null | grep -qi "vulkan"; then
    echo "[llama-link] Vulkan available → full offload"
    NGL=99
else
    echo "[llama-link] No GPU detected → CPU with OpenBLAS fallback"
    NGL=0
fi

exec "$LLAMA_BIN" \
    -m "$MODEL" \
    --port "$PORT" \
    --ctx-size "$CTX" \
    --n-gpu-layers "$NGL" \
    "${DEVICE_ARGS[@]}" \
    --no-warmup