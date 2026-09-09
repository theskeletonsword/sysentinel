#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# dracut pre-udev hook (00) — bring up sysentinel_metrics + webcam early.
#
# Loaded before udev coldplug so that:
#   - /proc/sysentinel_metrics exists as soon as possible (early control
#     / verdict channel, used by the daemon for poweroff / triple-fault).
#   - uvcvideo is resident for whatever udev discovers right after.

modprobe -q sysentinel_metrics 2>/dev/null || true
modprobe -q uvcvideo 2>/dev/null || true

return 0