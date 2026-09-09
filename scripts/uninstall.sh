#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

echo "==> Stopping and disabling service (if present)"
systemctl disable --now sysentinel.service 2>/dev/null || true

echo "==> Removing binary and systemd unit"
rm -f /usr/local/bin/sysentinel-daemon
rm -f /etc/systemd/system/sysentinel.service
systemctl daemon-reload

echo "==> Unloading kernel module (if loaded)"
if lsmod | grep -q '^sysentinel_metrics'; then
    rmmod sysentinel_metrics
fi

echo
echo "Note: /etc/sysentinel/config.toml (your secrets) and the 'sysentinel'"
echo "system user were intentionally left in place. Remove them manually if desired:"
echo "  sudo rm -rf /etc/sysentinel /var/log/sysentinel"
echo "  sudo userdel sysentinel"
