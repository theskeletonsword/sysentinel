# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Top-level convenience Makefile. Each component also builds
# standalone from within its own directory.

.PHONY: all daemon kernel-module ramdisk clean install install-dracut uninstall

all: daemon kernel-module ramdisk

daemon:
	cd daemon && cargo build --release

kernel-module:
	$(MAKE) -C kernel_module

# V4L2 photo tool used by both the initramfs (LUKS evidence) and the daemon
# (login-watch intrusions). Pure-Rust, no external deps.
ramdisk:
	cd ramdisk && cargo build --release

clean:
	cd daemon && cargo clean
	cd ramdisk && cargo clean
	$(MAKE) -C kernel_module clean

install: all
	./scripts/install.sh

# Loads the sysentinel_metrics kernel module + webcam stack into the
# initramfs and regenerates it (backs up first). Must run as root.
install-dracut: ramdisk
	./scripts/install-dracut.sh

uninstall:
	./scripts/uninstall.sh
