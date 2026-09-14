# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# akmod package for sysentinel_metrics — the Fedora-native counterpart to the
# DKMS packaging in kernel/linux/dkms.conf.
#
# akmod and DKMS solve the same problem (rebuild this out-of-tree module when a
# new kernel lands) and both are supported on purpose: Fedora ships akmods and
# wires it into the kernel install path, while DKMS is what Debian, Arch and
# almost everything else expect.
#
# USE ONE, NOT BOTH. They install to different paths —
#   akmod: /lib/modules/<kver>/extra/sysentinel_metrics/sysentinel_metrics.ko.xz
#   dkms:  /lib/modules/<kver>/extra/sysentinel_metrics.ko.xz
# — so nothing collides at install time and depmod ends up with two modules of
# the same name. Which one modprobe picks is then down to depmod's search
# order, which is not something to leave to chance for a module that can
# poweroff the machine. scripts/install-akmod.sh refuses to proceed while a
# DKMS registration exists.
#
# Build and register it with:  sudo scripts/install-akmod.sh
#
# WHAT MAKES THIS ONE UNUSUAL
#
# The %build below does not call make directly. It calls build-module.sh, the
# same wrapper DKMS uses, because a rust-for-linux module cannot be built
# against a plain kernel-devel tree: that package ships no compiled Rust crates,
# and the crate hashes baked into every exported symbol depend on the exact
# rustc BUILD. The wrapper finds a prepared tree and a matching rustc, or
# refuses. See the comment at the top of build-module.sh.
#
# Consequence worth knowing: on a brand-new kernel, akmods will FAIL here until
# `scripts/prepare-kernel-rust-tree.sh <kver>` has been run for it. That is the
# intended behaviour — the alternative is a module that installs and then
# cannot load.

# Build an akmod (source package rebuilt on the user's machine per kernel)
# rather than kmods for a fixed kernel list.
%global buildforkernels akmod
%global debug_package %{nil}

Name:           sysentinel_metrics-kmod
Version:        0.1.0
Release:        1%{?dist}
Summary:        Ring-0 metrics and control channel for sysentinel
License:        MIT OR GPL-2.0-or-later
URL:            https://github.com/prhxntaiii/sysentinel
Source0:        sysentinel_metrics-kmod-%{version}.tar.xz

BuildRequires:  %{_bindir}/kmodtool
# The Rust toolchain is NOT a BuildRequires: the module must be built with the
# exact rustc the target kernel was built with, which is not the distro's
# current rust package. build-module.sh locates it under /opt/sysentinel.

%{!?kernels:BuildRequires: gcc, make, elfutils-libelf-devel}

# kmodtool generates the per-kernel subpackages and the akmod package.
%{expand:%(kmodtool --target %{_target_cpu} --kmodname %{name} %{?buildforkernels:--%{buildforkernels}} %{?kernels:--for-kernels "%{?kernels}"} 2>/dev/null) }

%description
The sysentinel_metrics kernel module: ring-0 system metrics, Intel ME / AMD PSP
status over the MEI and CCP buses, hypervisor and hypercall observation, and the
confirmed control channel exposed at /proc/sysentinel_metrics.

# kmodtool puts `Requires: %{name}-common >= %{version}` on every per-kernel
# kmod subpackage it generates, so this has to exist or nothing installs. It is
# the conventional home for the parts that are not kernel-specific; here that
# is only the licences and the README, because everything else this module
# needs already belongs to the daemon package.
%package common
Summary:        Common files for the sysentinel_metrics kernel module
# NOT BuildArch: noarch, even though licences and a README plainly are.
# akmodsbuild harvests only ${tmpdir}/RPMS/${target}/ — the arch directory —
# so a noarch subpackage is built correctly, written to RPMS/noarch/, and then
# silently left behind. The kmod package then fails to install against a
# dependency whose package exists and was never collected.

%description common
Licences and documentation shared by every per-kernel build of the
sysentinel_metrics kernel module.

%prep
%{?kmodtool_check}
%setup -q -c

# One build tree per kernel being built for, which is how kmodtool's loop
# expects to find them.
for kernel_version in %{?kernel_versions}; do
    cp -a sysentinel_metrics-kmod-%{version} _kmod_build_${kernel_version%%___*}
done

%build
for kernel_version in %{?kernel_versions}; do
    pushd _kmod_build_${kernel_version%%___*}/
        # The wrapper resolves the kernel tree itself. It deliberately ignores
        # the ${kernel_version##*___} path kmodtool hands over (that is the
        # kernel-devel tree, which has no Rust artefacts) and looks for the
        # prepared tree recorded in /etc/sysentinel/kdir-<kver>.
        ./build-module.sh build "${kernel_version%%___*}"
    popd
done

%install
for kernel_version in %{?kernel_versions}; do
    mkdir -p $RPM_BUILD_ROOT/%{kmodinstdir_prefix}/${kernel_version%%___*}/%{kmodinstdir_postfix}/
    install -D -m 0755 _kmod_build_${kernel_version%%___*}/sysentinel_metrics.ko \
        $RPM_BUILD_ROOT/%{kmodinstdir_prefix}/${kernel_version%%___*}/%{kmodinstdir_postfix}/
done
%{?akmod_install}

%files common
%license sysentinel_metrics-kmod-%{version}/LICENSE-MIT
%license sysentinel_metrics-kmod-%{version}/LICENSE-GPL
%doc sysentinel_metrics-kmod-%{version}/README.md

%changelog
* Sat Sep 12 2026 sysentinel contributors - 0.1.0-1
- Initial akmod packaging, sharing build-module.sh with the DKMS path.
