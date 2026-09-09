#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Installs the built sysentinel-daemon binary, config template, state
# directory, and systemd unit.
#
# Does NOT enable/start the service — you must edit config.toml first.
# Does NOT install the kernel module — see kernel_module/README.md.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY="$REPO_ROOT/daemon/target/release/sysentinel-daemon"

if [[ ! -f "$BINARY" ]]; then
    echo "Binary not found at $BINARY — build first: cd daemon && cargo build --release" >&2
    exit 1
fi

echo "==> Installing binary"
install -Dm755 "$BINARY" /usr/local/bin/sysentinel-daemon

echo "==> Creating service user 'sysentinel'"
if ! id -u sysentinel >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin sysentinel
fi

# The sysentinel group authorises the control channel: the kernel module's
# /proc/sysentinel_metrics write() gate-keeps commands via `write_gid`, and
# /var/log is shared with the pair tooling below.
if ! getent group sysentinel >/dev/null 2>&1; then
    groupadd --system sysentinel
fi

echo "==> Installing config"
mkdir -p /etc/sysentinel
if [[ ! -f /etc/sysentinel/config.toml ]]; then
    # Prefer the real (possibly customized) config over the placeholder.
    SOURCE="$REPO_ROOT/daemon/config/config.example.toml"
    if [[ -f "$REPO_ROOT/daemon/config/config.toml" ]]; then
        SOURCE="$REPO_ROOT/daemon/config/config.toml"
    fi
    install -Dm640 -o root -g sysentinel "$SOURCE" /etc/sysentinel/config.toml
    echo "    Wrote /etc/sysentinel/config.toml from $(basename "$SOURCE") — review it before starting."
else
    echo "    /etc/sysentinel/config.toml already exists, skipping."
fi

echo "==> Creating state and log directories"
install -dm750 -o sysentinel -g sysentinel /var/lib/sysentinel
install -dm750 -o sysentinel -g sysentinel /var/log/sysentinel

echo "==> Installing systemd unit"
install -Dm644 "$SCRIPT_DIR/sysentinel.service" /etc/systemd/system/sysentinel.service
systemctl daemon-reload

echo
echo "════════════════════════════════════════════════════════════"
echo " Installation complete. Next steps:"
echo ""
echo "  1. Edit /etc/sysentinel/config.toml"
echo "     - Set telegram.bot_token (create a bot via @BotFather)"
echo "     - Set llm.backend and the matching API key"
echo "     - Adjust persona.tone, persona.language, persona.emotions,"
echo "       persona.undervolted to your taste"
echo ""
echo "  2. Start the service:"
echo "     sudo systemctl enable --now sysentinel"
echo ""
echo "  3. Watch the log for the pairing token:"
echo "     journalctl -u sysentinel -f"
echo "     (Look for the SYN-XXXXX token — send it to your Telegram bot)"
echo ""
echo "  4. Build + load the kernel module for live Intel ME firmware,"
echo "     AMD PSP detection, CR register reads, and the privileged"
echo "     control channel (/proc/sysentinel_metrics):"
echo "     cd kernel_module && make && sudo make modules_install"
echo "     # root-only control by default. To let the 'sysentinel' service"
echo "     # user send control commands, pass its GID:"
echo "     sudo modprobe sysentinel_metrics write_gid=\$(id -g sysentinel)"
echo "     cat /proc/sysentinel_metrics"
echo "     # The broadcast: echo restart | sudo tee /proc/sysentinel_metrics"
echo ""
echo "  IMPORTANT: the module is currently LOADED from a previous install."
echo "  To switch to the new /proc interface you MUST reload it:"
echo "     sudo rmmod sysentinel_metrics && sudo modprobe sysentinel_metrics"
echo "════════════════════════════════════════════════════════════"
