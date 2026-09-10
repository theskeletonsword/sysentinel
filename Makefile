# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Top-level convenience Makefile. Each component also builds
# standalone from within its own directory.

.PHONY: all daemon kernel-module ramdisk gui check licence-map licence-audit clean install install-dracut uninstall

all: daemon kernel-module ramdisk

daemon:
	cd daemon && cargo build --release

kernel-module:
	$(MAKE) -C kernel_module

# V4L2 photo tool used by both the initramfs (LUKS evidence) and the daemon
# (login-watch intrusions). Pure-Rust, no external deps.
ramdisk:
	cd ramdisk && cargo build --release

# Everything CI enforces, runnable locally. No `cargo fmt --check`: this tree
# uses hand-aligned columns that rustfmt would rewrite.
check:
	cargo clippy --manifest-path daemon/Cargo.toml  --all-targets -- -D warnings
	cargo clippy --manifest-path ramdisk/Cargo.toml --all-targets -- -D warnings
	cargo test   --manifest-path daemon/Cargo.toml
	cargo test   --manifest-path ramdisk/Cargo.toml
	@# The GUI only builds where GTK's dev packages exist; skip cleanly elsewhere.
	@if pkg-config --exists gtk4 libadwaita-1; then \
		cargo clippy --manifest-path gui/linux/Cargo.toml --all-targets -- -D warnings; \
		cargo test   --manifest-path gui/linux/Cargo.toml; \
	else \
		echo "gui: skipping (no gtk4-devel/libadwaita-devel)"; \
	fi
	shellcheck -S warning $$(git ls-files '*.sh')
	./scripts/licence-map-check.sh

# Verify the per-directory licence map: SPDX header on every file matching its
# directory, real licence texts present, MODULE_LICENSE idents consistent.
licence-map:
	./scripts/licence-map-check.sh

# Provenance check for the Apache-2.0 daemon: report every word sequence it
# shares with a GPL reference tree, so each one can be read and explained.
# Needs a Linux source tree, so it is not part of `check` or CI.
#   make licence-audit LINUX_SRC=/path/to/linux
LINUX_SRC ?= /usr/src/linux
licence-audit:
	./scripts/licence-audit.sh "$(LINUX_SRC)"

# GTK4 desktop front-end. Needs gtk4-devel/libadwaita-devel; kept out of `all`
# so a machine without them can still build everything else.
gui:
	cargo build --release --manifest-path gui/linux/Cargo.toml

clean:
	cd daemon && cargo clean
	cargo clean --manifest-path gui/linux/Cargo.toml
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
