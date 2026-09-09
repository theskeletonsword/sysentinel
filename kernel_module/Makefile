# SPDX-License-Identifier: GPL-2.0-only
#
# Out-of-tree build wrapper for sysentinel_metrics.
#
# Requirements:
#   - A Linux kernel built with CONFIG_RUST=y (rust-for-linux support).
#   - rustc and bindgen at the exact version pinned by that kernel tree
#     (`scripts/min-tool-version.sh rustc` / `bindgen`).
#   - For Intel ME support (optional): CONFIG_INTEL_MEI=y in the host kernel.
#
# Usage:
#
#   # Default build (metrics + hypervisor detection only):
#   make KDIR=/path/to/kernel/source
#
#   # With Intel MEI kernel client driver (requires CONFIG_INTEL_MEI=y):
#   make MEI=y KDIR=/path/to/kernel/source
#
#   sudo make KDIR=/path/to/kernel/source modules_install
#   sudo modprobe sysentinel_metrics
#   cat /proc/sysentinel_metrics
#   # privileged control (optional): allow GID 1000 to send commands:
#   sudo modprobe sysentinel_metrics write_gid=1000
#   echo reboot | sudo tee /proc/sysentinel_metrics   # ← confirms first!
#   sudo rmmod sysentinel_metrics

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# The kernel's prebuilt rust/ metadata (.rmeta) was compiled by a specific
# `rustc` (on Fedora, the distro compiler at /usr/bin/rustc). A rustup
# toolchain, even of the same release, embeds a different build string and
# kbuild rejects it with E0514 "incompatible version of rustc". Pin the
# compiler explicitly so that a cargo/rustup `rustc` earlier in PATH can
# never shadow it.
RUSTC_BIN := $(shell command -v /usr/bin/rustc 2>/dev/null || command -v rustc 2>/dev/null)
RUSTC_BIN := $(if $(RUSTC_BIN),$(RUSTC_BIN),rustc)
$(info sysentinel: using rustc: $(RUSTC_BIN))

# Enable the Kconfig symbol for the out-of-tree build.
export CONFIG_SYSENTINEL_METRICS := m

# ── Optional Intel MEI support ──────────────────────────────────────────────
# MEI is enabled by default now (it compiles and links against the Fedora
# kernel's `mei` module — ver `modinfo: depends: mei`). Use MEI=n to build
# the metrics-only variant (no Intel ME status).

MEI ?= y

ifeq ($(MEI),y)
# Tell rustc that MEI bindings are available.
export SYSENTINEL_EXTRA_RUSTFLAGS := --cfg mei_available
# The C shim is compiled and linked alongside the Rust object.
export CONFIG_SYSENTINEL_MEI_SHIM := y
$(info sysentinel: Intel MEI support ENABLED (default))
else
export SYSENTINEL_EXTRA_RUSTFLAGS :=
export CONFIG_SYSENTINEL_MEI_SHIM := n
$(info sysentinel: Intel MEI support DISABLED (use MEI=y to enable))
endif

all:
	$(MAKE) -C $(KDIR) M=$(PWD) RUSTC=$(RUSTC_BIN) HOSTRUSTC=$(RUSTC_BIN) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) RUSTC=$(RUSTC_BIN) HOSTRUSTC=$(RUSTC_BIN) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all modules_install clean
