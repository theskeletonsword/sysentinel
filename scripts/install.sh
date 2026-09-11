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

echo "==> Configuring kernel-module control channel (write_gid)"
SYSENTINEL_GID="$(id -g sysentinel)"
MODPROBE_CONF=/etc/modprobe.d/sysentinel.conf
if [[ -f "$MODPROBE_CONF" ]] && grep -q '^options sysentinel_metrics write_gid=' "$MODPROBE_CONF"; then
    echo "    $MODPROBE_CONF already has a write_gid option, skipping."
else
    echo "options sysentinel_metrics write_gid=$SYSENTINEL_GID" > "$MODPROBE_CONF"
    echo "    Wrote options sysentinel_metrics write_gid=$SYSENTINEL_GID to $MODPROBE_CONF"
fi
if [[ -f /etc/modprobe.d/sysentinel ]] || [[ -f /etc/modprobe.conf ]]; then
    echo "    NOTE: a stray /etc/modprobe.d/sysentinel or /etc/modprobe.conf exists —"
    echo "    check it is not overriding the write_gid option."
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
echo " Daemon installed. Next steps:"
echo ""
echo "  1. Edit /etc/sysentinel/config.toml"
echo "     - [phone] enabled = true, and bind = \"YOUR_IP:8443\""
echo "       That is the address your phone can reach this machine on."
echo "       NOT 0.0.0.0: that is a listen address, not somewhere to dial,"
echo "       and the pairing QR carries it verbatim."
echo "     - Set llm.backend and the matching API key"
echo "     - Adjust persona.tone, persona.language, persona.emotions"
echo ""
echo "  2. Start the service:"
echo "     sudo systemctl enable --now sysentinel"
echo ""
echo "  3. Pair your phone. With none registered the daemon draws a QR"
echo "     on its console at startup:"
echo "     sudo journalctl -u sysentinel -f"
echo "     Scan it from the app. After the first pairing the key alone"
echo "     stops being enough: the machine also requires a signature from"
echo "     THAT handset, and refuses any other."
echo ""
echo "  4. Kernel module — live Intel ME firmware, AMD PSP detection, CR"
echo "     register reads and the privileged control channel"
echo "     (/proc/sysentinel_metrics):"
echo "     sudo modprobe sysentinel_metrics"
echo "     cat /proc/sysentinel_metrics"
echo ""
echo "     If you installed piece by piece rather than with"
echo "     scripts/install-all.sh, build and install it first:"
echo "     cd kernel_module && make && sudo make modules_install && sudo depmod -a"
echo ""
if lsmod | grep -q '^sysentinel_metrics'; then
echo "  NOTE: sysentinel_metrics is currently loaded from an earlier install."
echo "  Reload it to pick up this one:"
echo "     sudo rmmod sysentinel_metrics && sudo modprobe sysentinel_metrics"
echo ""
fi
echo "════════════════════════════════════════════════════════════"
