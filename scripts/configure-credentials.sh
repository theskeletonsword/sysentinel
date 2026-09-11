#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Set up credentials and the phone channel without opening config.toml.
#
# # Why this exists
#
# The config is a long file with a lot of commentary in it, and the four things
# a new install actually needs are buried in it: which LLM answers, its API key,
# the address the phone dials, and the pairing key. Editing it by hand as root,
# in an editor, with a key on the clipboard, is where people paste into the
# wrong section and where a key ends up in shell history.
#
# # It is fine not to have an API key
#
# If you have no provider, or no credit left on one, say so and this sets the
# chain to `none`. Everything keeps working: the watchers watch, the phone gets
# its alerts, the confirmations confirm. What you lose is the sentence of
# explanation on top of a kernel message — the message itself still arrives. The
# script says that out loud rather than making it feel like a failed setup.
#
# # What it will not do
#
# It never prints a key back to the terminal, never writes one to a world- or
# group-readable file, and never leaves the config more permissive than it
# found it. Everything it changes is backed up first, and the daemon's own
# `--check-config` validates the result before it is kept.

set -euo pipefail

CONFIG="${SYSENTINEL_CONFIG:-/etc/sysentinel/config.toml}"
DAEMON="${SYSENTINEL_DAEMON:-/usr/local/bin/sysentinel-daemon}"
ASSUME_YES=0
OPT_PROVIDER=""
OPT_KEY_FILE=""
OPT_MODEL=""
OPT_BIND=""

# ── Output ───────────────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    B=$'\e[1m'; DIM=$'\e[2m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; R=$'\e[0m'
else
    B=""; DIM=""; GREEN=""; YELLOW=""; RED=""; R=""
fi

step() { printf '\n%s══ %s%s\n' "$B" "$1" "$R"; }
info() { printf '   %s\n' "$1"; }
ok()   { printf '   %s✔%s %s\n' "$GREEN" "$R" "$1"; }
warn() { printf '   %s!%s %s\n' "$YELLOW" "$R" "$1"; }
die()  { printf '\n%serror:%s %s\n' "$RED" "$R" "$1" >&2; exit 1; }

usage() {
    cat <<'USAGE'
scripts/configure-credentials.sh [options]

  --config PATH        config to edit (default /etc/sysentinel/config.toml)
  -y, --yes            accept the defaults instead of asking
  -h, --help           this

Non-interactive (for an installer or a script):

  --provider NAME      anthropic | openai | deepseek | gemini | llama | none
  --api-key-file PATH  read the key from this file, or "-" for stdin
  --model NAME         model name for that provider
  --bind ADDR:PORT     address the phone dials

Walks through: the LLM provider and its key (skippable), the phone channel's
listen address, and the pairing key. Reads keys without echoing them, backs the
config up, and validates the result with `sysentinel-daemon --check-config`
before keeping it.

There is deliberately no --api-key flag. Anything on a command line is visible
to every user on the machine for as long as the process runs, and a key is
exactly the thing not to put there — hence a file, or stdin.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config) CONFIG="${2:-}"; shift 2 ;;
        --provider) OPT_PROVIDER="${2:-}"; shift 2 ;;
        --api-key-file) OPT_KEY_FILE="${2:-}"; shift 2 ;;
        --model) OPT_MODEL="${2:-}"; shift 2 ;;
        --bind) OPT_BIND="${2:-}"; shift 2 ;;
        -y|--yes) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
done

# Anything given on the command line implies "do not ask me".
[[ -n "$OPT_PROVIDER$OPT_BIND$OPT_KEY_FILE$OPT_MODEL" ]] && ASSUME_YES=1

# ── Preconditions ────────────────────────────────────────────────────────────

# Without a terminal there is nobody to ask, and silently accepting every
# default would write a configuration nobody chose — including, quietly, no
# LLM at all. Say so instead.
if [[ ! -t 0 && $ASSUME_YES -eq 0 ]]; then
    die "no terminal to ask you on.
To run without questions:  $0 --yes
or give it the answers:    $0 --provider deepseek --api-key-file key.txt --bind 10.0.0.5:8443"
fi

[[ -f "$CONFIG" ]] || die "no config at $CONFIG
Install it first:  sudo ./scripts/install.sh
or point at another one:  --config /path/to/config.toml"

[[ -w "$CONFIG" ]] || die "cannot write $CONFIG — run with sudo"

# The daemon refuses to start on a config others can write, so refuse to make
# one here for the same reason: whoever can edit it can redirect the LLM
# endpoint and read every key that goes through it.
mode="$(stat -c '%a' "$CONFIG")"
if (( 8#$mode & 8#0022 )); then
    die "$CONFIG is mode $mode — writable by others.
Fix it before putting a key in it:  sudo chmod 640 $CONFIG"
fi

# ── Reading and writing single values, without disturbing the rest ───────────
#
# A tiny, deliberate subset of TOML: set `key = "value"` inside `[section]`,
# adding the section or the key if either is missing, and leaving every comment
# and every other line exactly where it was. Not a TOML parser and not trying to
# be one — the file it edits is the one this repo ships, and everything it
# writes is checked afterwards by the daemon, which does have a real parser.

current() { # (section, key) -> value on stdout, empty if unset or commented
    awk -v section="$1" -v key="$2" '
        /^[[:space:]]*\[/ { in_section = ($0 ~ "^[[:space:]]*\\[" section "\\]") ; next }
        in_section && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            sub(/^[^=]*=[[:space:]]*/, "")
            gsub(/^"|"$/, "")
            print
            exit
        }
    ' "$CONFIG"
}

set_value() { # (section, key, value, quoted?)
    local section="$1" key="$2" value="$3" quoted="${4:-yes}" rendered
    if [[ "$quoted" == yes ]]; then
        # Only " and \ mean anything inside a TOML basic string.
        rendered="\"$(printf '%s' "$value" | sed 's/\\/\\\\/g; s/"/\\"/g')\""
    else
        rendered="$value"
    fi

    local tmp
    tmp="$(mktemp "${CONFIG}.XXXXXX")"
    chmod --reference="$CONFIG" "$tmp"
    chown --reference="$CONFIG" "$tmp" 2>/dev/null || true

    SECTION="$section" KEY="$key" VALUE="$rendered" awk '
        BEGIN { section = ENVIRON["SECTION"]; key = ENVIRON["KEY"]; value = ENVIRON["VALUE"] }
        /^[[:space:]]*\[/ {
            if (in_section && !done) { print key " = " value; done = 1 }
            in_section = ($0 ~ "^[[:space:]]*\\[" section "\\]")
            if (in_section) seen_section = 1
            print
            next
        }
        in_section && $0 ~ "^[[:space:]]*#?[[:space:]]*" key "[[:space:]]*=" {
            if (!done) { print key " = " value; done = 1 }
            next
        }
        { print }
        END {
            if (!done) {
                if (!seen_section) print "\n[" section "]"
                print key " = " value
            }
        }
    ' "$CONFIG" > "$tmp"

    mv "$tmp" "$CONFIG"
}

ask() { # (prompt, default) -> answer on stdout
    local prompt="$1" default="${2:-}" answer
    if (( ASSUME_YES )); then printf '%s' "$default"; return; fi
    if [[ -n "$default" ]]; then
        read -r -p "   $prompt [$default]: " answer </dev/tty || true
        printf '%s' "${answer:-$default}"
    else
        read -r -p "   $prompt: " answer </dev/tty || true
        printf '%s' "$answer"
    fi
}

ask_secret() { # (prompt) -> secret on stdout, never echoed
    local prompt="$1" answer
    read -r -s -p "   $prompt: " answer </dev/tty || true
    printf '\n' >&2
    printf '%s' "$answer"
}

confirm() { # (prompt) -> 0/1
    (( ASSUME_YES )) && return 0
    local answer
    read -r -p "   $1 [y/N]: " answer </dev/tty || true
    # Accepts the owner's own words as well as the English ones: this reads an
    # answer a person types, and a Spanish-speaking owner types "si".
    [[ "$answer" =~ ^([yY]|yes|[sS]|si|sí)$ ]]
}

# ── Back it up before touching anything ──────────────────────────────────────
#
# Once, at the start, rather than per edit: one file to go back to, and it
# carries the same permissions as the original so the backup is not the leak.

BACKUP="${CONFIG}.bak-$(date +%Y%m%d-%H%M%S)"
umask 077
cp -p "$CONFIG" "$BACKUP"
chmod --reference="$CONFIG" "$BACKUP" 2>/dev/null || true
info "backup: $BACKUP"

# ── 1. The LLM ───────────────────────────────────────────────────────────────

step "The model that explains events"
cat <<EOF
   When something happens in the kernel, the daemon can ask a model to explain
   it in your language before sending it on. This is optional.

     ${B}1${R}  Anthropic (Claude)
     ${B}2${R}  OpenAI
     ${B}3${R}  DeepSeek
     ${B}4${R}  Gemini
     ${B}5${R}  llama.cpp on this machine (no API, no account, nothing spent)
     ${B}6${R}  None ${DIM}— I have no API key, or no credit left${R}
EOF

# What is configured right now, so the default can be "leave it alone".
#
# This used to default to 6 ("none"), which meant a non-interactive run given
# only `--bind` — the obvious way to point an existing install at a new
# address — quietly replaced a working provider chain with "none" and left the
# API key orphaned. Changing where the phone dials must never cost the owner
# their LLM.
existing_chain="$(current llm backend)"
if [[ -n "$existing_chain" && "$existing_chain" != '["none"]' ]]; then
    info "Currently configured: ${B}${existing_chain}${R}"
    info "     ${B}7${R}  Keep it as it is"
    default_choice=7
else
    default_choice=6
fi

if [[ -n "$OPT_PROVIDER" ]]; then
    choice="$OPT_PROVIDER"
elif (( ASSUME_YES )); then
    # Nobody to ask and nothing asked for: keep whatever is there.
    choice=keep
else
    choice="$(ask "Choose" "$default_choice")"
fi

# The menu answers by number; --provider answers by name. Fold both into a
# name, then decide once.
case "$choice" in
    1) choice=anthropic ;;
    2) choice=openai ;;
    3) choice=deepseek ;;
    4) choice=gemini ;;
    5) choice=llama ;;
    6) choice=none ;;
    7|"") choice=keep ;;
esac

case "$choice" in
    anthropic) provider=anthropic; default_model="claude-sonnet-5" ;;
    openai)    provider=openai;    default_model="gpt-4o" ;;
    deepseek)  provider=deepseek;  default_model="deepseek-chat" ;;
    gemini)    provider=gemini;    default_model="gemini-1.5-pro" ;;
    llama)     provider=llama;     default_model="" ;;
    none)      provider=none;      default_model="" ;;
    keep)      provider=keep;      default_model="" ;;
    *) die "I did not understand «$choice»" ;;
esac
[[ -n "$OPT_MODEL" ]] && default_model="$OPT_MODEL"

case "$provider" in
    keep)
        ok "LLM left exactly as it was: ${existing_chain:-(nothing configured)}"
        ;;

    none)
        set_value llm backend '["none"]' no
        ok "no model: alerts carry the kernel message as it came"
        info "${DIM}This is not a half-finished setup. The watchers watch, the${R}"
        info "${DIM}alerts arrive and the confirmations work exactly the same;${R}"
        info "${DIM}the only thing missing is the sentence explaining them.${R}"
        info "${DIM}When you have a key, run this again.${R}"
        ;;

    llama)
        set_value llm backend '["llama", "none"]' no
        base="$(ask "llama.cpp server URL" "http://127.0.0.1:8080")"
        set_value "llm.llama" base_url "$base"
        model="$(ask "Model it serves (informational)" "local-gguf")"
        set_value llm model "$model"
        ok "llama.cpp at $base, with «none» behind it in case it goes down"
        info "${DIM}http:// is allowed here on purpose: it is loopback and nothing${R}"
        info "${DIM}leaves the machine. Every other provider is required to be https.${R}"
        ;;

    *)
        info ""
        info "The key is not echoed as you type it, and does not land in your"
        info "shell history. Press Enter to skip this provider."
        if [[ -n "$OPT_KEY_FILE" ]]; then
            if [[ "$OPT_KEY_FILE" == "-" ]]; then
                key="$(cat)"
            else
                [[ -r "$OPT_KEY_FILE" ]] || die "cannot read $OPT_KEY_FILE"
                key="$(cat "$OPT_KEY_FILE")"
            fi
            key="${key//[$'\r\n']/}"
        else
            key="$(ask_secret "$provider API key")"
        fi
        if [[ -z "$key" ]]; then
            warn "no key: leaving the chain on «none» — you still get your alerts"
            set_value llm backend '["none"]' no
        else
            # Shape check only — nobody here can tell whether a key is live, and
            # pretending to would be worse than saying nothing.
            if [[ ${#key} -lt 16 ]]; then
                warn "that key is very short (${#key} characters). Saving it anyway;"
                warn "if it is wrong, the daemon will say so on the first event."
            fi
            set_value "llm.$provider" api_key "$key"
            set_value llm backend "[\"$provider\", \"none\"]" no
            model="$(ask "Model" "$default_model")"
            set_value llm model "$model"
            ok "$provider configured (key saved, never displayed)"
            info "${DIM}«none» sits behind it in the chain: if the provider fails${R}"
            info "${DIM}or runs out of credit, the alert still arrives, unexplained.${R}"
            unset key
        fi
        ;;
esac

# ── 2. Certificate pinning for that provider (optional) ──────────────────────

if [[ "$provider" != none && "$provider" != llama && "$provider" != keep ]] \
    && command -v openssl >/dev/null; then
    step "Pin the provider public key (optional)"
    info "Validating the certificate answers «one of the hundred CAs in the"
    info "store vouches for it». Pinning narrows that to the provider key."
    info "${DIM}The cost: if they rotate the key it stops working until you run${R}"
    info "${DIM}this again. That is why it is optional.${R}"
    if confirm "Pin it?"; then
        host="$(current "llm.$provider" base_url | sed -E 's#https?://##; s#/.*##')"
        if [[ -n "$host" ]]; then
            pin="$(openssl s_client -connect "$host:443" </dev/null 2>/dev/null \
                | openssl x509 -pubkey -noout 2>/dev/null \
                | openssl pkey -pubin -outform der 2>/dev/null \
                | openssl dgst -sha256 -binary 2>/dev/null \
                | openssl enc -base64 2>/dev/null || true)"
            if [[ -n "$pin" ]]; then
                set_value llm tls_pins "[\"sha256/$pin\"]" no
                ok "pinned the key for $host"
            else
                warn "could not read the certificate for $host — leaving it unpinned"
            fi
        fi
    fi
fi

# ── 3. The phone channel ─────────────────────────────────────────────────────

step "The phone channel"
info "This is the only way the daemon has to reach you. Without it, it watches"
info "and can tell nobody."

# Offer the addresses this machine actually has, so nobody has to guess.
mapfile -t addrs < <(ip -4 -o addr show scope global 2>/dev/null \
    | awk '{ split($4, a, "/"); print $2 "\t" a[1] }')
tailscale_ip=""
if command -v tailscale >/dev/null; then
    tailscale_ip="$(tailscale ip -4 2>/dev/null | head -n1 || true)"
fi

if (( ${#addrs[@]} )); then
    info ""
    info "Addresses on this machine:"
    for a in "${addrs[@]}"; do
        iface="${a%%$'\t'*}"; addr="${a##*$'\t'}"
        if [[ -n "$tailscale_ip" && "$addr" == "$tailscale_ip" ]]; then
            printf '     %s%s%s\t%s  %s← Tailscale: the same address at home and away%s\n' \
                "$B" "$addr" "$R" "$iface" "$GREEN" "$R"
        else
            printf '     %s%s%s\t%s\n' "$B" "$addr" "$R" "$iface"
        fi
    done
fi

default_bind="$(current phone bind)"
if [[ -z "$default_bind" ]]; then
    if [[ -n "$tailscale_ip" ]]; then
        default_bind="$tailscale_ip:8443"
    elif (( ${#addrs[@]} )); then
        default_bind="${addrs[0]##*$'\t'}:8443"
    else
        default_bind="192.168.1.5:8443"
    fi
fi

info ""
info "Enter the address the PHONE sees this machine on, with a port."
if [[ -n "$OPT_BIND" ]]; then
    bind="$OPT_BIND"
else
    bind="$(ask "bind" "$default_bind")"
fi

case "$bind" in
    0.0.0.0:*|\[::\]:*|:::*)
        die "0.0.0.0 is a listen address, not a destination: the QR carries it
verbatim and the phone would not know where to dial. Use a specific one." ;;
    *:*) : ;;
    *) die "the port is missing: something like ${bind}:8443" ;;
esac

set_value phone bind "$bind"
set_value phone enabled true no
ok "phone channel enabled on $bind"

if [[ -n "$tailscale_ip" && "$bind" == "$tailscale_ip:"* ]]; then
    info "${DIM}With the Tailscale address nothing needs changing when you${R}"
    info "${DIM}travel. See tutorial-tailscale.md.${R}"
fi

# Only ask about `advertise` when it would actually mean something.
if [[ "$bind" == 127.* || "$bind" == "localhost:"* ]]; then
    warn "listening on loopback: that only makes sense with a tunnel in front"
    adv="$(ask "The tunnel public address (the one that goes in the QR)" "")"
    [[ -n "$adv" ]] && set_value phone advertise "$adv" && ok "the QR will say $adv"
fi

# ── 4. The pairing key ───────────────────────────────────────────────────────

step "Pairing key"
existing="$(current phone pairing_key)"
if [[ ${#existing} -eq 64 ]]; then
    ok "there is already a 64-hex key; leaving it alone"
    info "${DIM}Changing it forces the phone to pair again.${R}"
else
    # From the kernel CSPRNG. Never echoed: sealing a frame with it IS the
    # authentication, so it is the whole secret.
    newkey="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
    [[ ${#newkey} -eq 64 ]] || die "could not get 32 bytes from /dev/urandom"
    set_value phone pairing_key "$newkey"
    unset newkey
    ok "new key generated and saved (not shown: it goes in the QR)"
fi

# ── 5. Check it ──────────────────────────────────────────────────────────────

step "Checking"
if [[ -x "$DAEMON" ]]; then
    if "$DAEMON" --config "$CONFIG" --check-config; then
        ok "the daemon reads this config without complaint"
    else
        die "the daemon refuses this config.
Restore the previous one with:  sudo cp $BACKUP $CONFIG"
    fi
else
    warn "$DAEMON not found, so this could not be validated"
    info "Once installed:  $DAEMON --config $CONFIG --check-config"
fi

# Leave it no more readable than the installer intended.
chmod 640 "$CONFIG" 2>/dev/null || true
if getent group sysentinel >/dev/null; then
    chown root:sysentinel "$CONFIG" 2>/dev/null || true
fi
ok "permissions: $(stat -c '%U:%G %a' "$CONFIG")"

step "Done"
cat <<EOF
   Start it and watch the log: with no phone paired it draws a QR.

       sudo systemctl restart sysentinel
       sudo journalctl -u sysentinel -f

   Scan it from the sysentinel app. The QR carries the address, the key and
   the machine TLS fingerprint; the app requires all three.

   Backup of the previous config: $BACKUP
EOF
