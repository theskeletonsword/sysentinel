# daemon/sysentinel-daemon

Userspace watchdog that:

1. Tails `/dev/kmsg` in real time (blocking `read()` in follow mode —
   no polling of `dmesg`).
2. Classifies each record: OOM kill, kernel panic, segfault, oops, or
   "other" (kept only if the kernel itself flagged it error-or-worse).
3. Optionally asks an LLM backend to explain the event in the tone/
   language you configured in `[persona]`.
4. Pushes the result to the paired phone over the direct channel.

## Build

```sh
cd daemon
cargo build --release
# binary at target/release/sysentinel-daemon
```

To build with local (GGUF) inference support:

```sh
cargo build --release --features local-llm
```

## Configure

```sh
sudo mkdir -p /etc/sysentinel
sudo cp config/config.example.toml /etc/sysentinel/config.toml
sudo chmod 640 /etc/sysentinel/config.toml && sudo chown root:sysentinel /etc/sysentinel/config.toml
sudo $EDITOR /etc/sysentinel/config.toml
```

Fill in:
- `[phone]` — the only channel out. Set `enabled = true` and `bind` to
  the address *the phone* sees this machine on (a listening address, not
  `0.0.0.0`: the QR carries it verbatim and the handset has to dial it).
  Leave `pairing_key` out and the daemon mints one, then draws a QR on the
  machine's console at startup — `/pair` redraws it. The key is shown on
  the console and never over the channel it opens.

  Whoever sees that screen can read the key, so it stops being enough the
  moment a handset registers: from then on the daemon also demands a
  signature from a key held inside *that* phone's TEE, and refuses any
  other handset outright.
- `[memory]` — paths to `memory.txt` (long-term facts, edit by hand) and
  `context.txt` (rolling conversation history; cleared with
  `/resetcontext` from the phone).
- `[llm]` — pick one backend and fill in its API key, or set
  `backend = "none"` to skip LLM explanations entirely and alert with
  the raw kernel message. Backends: `openai`, `anthropic` (Claude),
  `deepseek`, `gemini`, `llama` (llama.cpp HTTP server) and `local`.
  The paired user can switch backend live with `/llm <name>` (e.g.
  `/llm llama` → `llama-server -c 4096 --port 8080`), and pick the model
  with `/model <name>`:
  - providers `openai|deepseek|anthropic|gemini|llama` accept any API
    model name, including vision models (e.g.
    `deepseek-v4-flash-vision-exp`);
  - provider `local` reads `[llm.local] model_path`, which may be a
    **directory of models scanned recursively** (each GGUF with its
    `*mmproj*.gguf` projector and `mtp-*.gguf` MTP companion attached).
    `/models` lists them and prints the ready-to-run `llama-server`
    command for a model. Context is adjustable live with
    `/settings llama_ctx <tokens>` (server) / `/settings local_ctx <tokens>`
    (in-process).
- `[persona]` — free-text tone description, e.g. `"colloquial Chilean
  Spanish, direct and friendly"`.

## Run

```sh
sudo ./target/release/sysentinel-daemon --config /etc/sysentinel/config.toml --verbose
```

Reading `/dev/kmsg` requires `CAP_SYSLOG` (root satisfies this
trivially; see `capabilities(7)` if you want to run as a dedicated
unprivileged user with just that capability instead).

## Run as a systemd service

See `../scripts/install.sh`, which installs the binary, config
template, and a `sysentinel.service` unit.

## License

Apache-2.0 — same as the repository itself.
