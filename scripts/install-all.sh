#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Build and install the whole pack: kernel module, daemon, initramfs tools,
# face models, dracut hooks, systemd unit and (optionally) the desktop GUI.
#
# The pieces each had their own script and the last mile was a list of commands
# in someone's terminal history. This is that list, in order, with the checks
# that stop it failing halfway.
#
# # Run it as yourself, not as root
#
# Building under sudo means every build.rs in the dependency tree — hundreds of
# crates — executes as root, and so does every proc macro. This script builds as
# you and calls sudo only for the steps that install, so you can see exactly
# which ones need privilege. It refuses to run as root for that reason.
#
# Usage:
#   scripts/install-all.sh [options]
#
#     --no-module      skip the kernel module
#     --no-initramfs   skip the dracut hooks and initramfs regeneration
#     --no-gui         skip the GTK4 desktop front-end
#     --no-models      do not fetch the ONNX face models (the face tool then
#                      cannot be built: it embeds them with include_bytes!)
#     --dry-run        print every step without running any of it
#     -y, --yes        do not ask before the privileged steps

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WITH_MODULE=1
WITH_INITRAMFS=1
WITH_GUI=1
WITH_MODELS=1
DRY_RUN=0
ASSUME_YES=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-module)     WITH_MODULE=0 ;;
        --no-initramfs)  WITH_INITRAMFS=0 ;;
        --no-gui)        WITH_GUI=0 ;;
        --no-models)     WITH_MODELS=0 ;;
        --dry-run)       DRY_RUN=1 ;;
        -y|--yes)        ASSUME_YES=1 ;;
        -h|--help)       sed -n '3,26p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

# ── Output ────────────────────────────────────────────────────────────────────

step()  { printf '\n\033[1;36m==>\033[0m \033[1m%s\033[0m\n' "$*"; }
info()  { printf '    %s\n' "$*"; }
ok()    { printf '    \033[32m✓\033[0m %s\n' "$*"; }
warn()  { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()   { printf '\n\033[1;31mABORTA:\033[0m %s\n' "$*" >&2; exit 1; }

run() {
    if (( DRY_RUN )); then
        printf '    \033[2m[dry-run]\033[0m %s\n' "$*"
    else
        "$@"
    fi
}

# Privileged step: shown before it runs, so nothing happens as root by surprise.
sudo_run() {
    if (( DRY_RUN )); then
        printf '    \033[2m[dry-run]\033[0m sudo %s\n' "$*"
    else
        printf '    \033[33msudo\033[0m %s\n' "$*"
        sudo "$@"
    fi
}

confirm() {
    (( ASSUME_YES )) && return 0
    (( DRY_RUN )) && return 0
    read -r -p "    $1 [s/N] " reply
    [[ "$reply" =~ ^[sSyY]$ ]]
}

# ── Preflight ─────────────────────────────────────────────────────────────────
#
# Everything is checked before anything is built or installed. An installer that
# stops halfway leaves a machine in a state nobody planned for, and on this one
# that could mean an initramfs that was regenerated without the tools it now
# refers to.

step "Comprobando el entorno"

[[ $EUID -ne 0 ]] || die "no lo ejecutes como root: compila como tú y pide sudo solo para instalar.
       Con sudo, cada build.rs de cientos de dependencias correría como root."

command -v sudo >/dev/null || die "hace falta sudo para los pasos de instalación"
command -v cargo >/dev/null || die "falta cargo — instala Rust (https://rustup.rs)"
ok "cargo $(cargo --version | awk '{print $2}')"

MUSL_TARGET=x86_64-unknown-linux-musl
if ! rustup target list --installed 2>/dev/null | grep -qx "$MUSL_TARGET"; then
    warn "falta el target $MUSL_TARGET (lo necesitan las herramientas del initramfs)"
    if confirm "¿Lo instalo con rustup?"; then
        run rustup target add "$MUSL_TARGET"
    else
        die "sin $MUSL_TARGET no se pueden construir sysentinel-cam ni sysentinel-face"
    fi
fi
ok "target $MUSL_TARGET"

command -v musl-gcc >/dev/null 2>&1 || warn "no encuentro musl-gcc; si el enlazado musl falla, instala musl-gcc/musl-tools"

if (( WITH_MODULE )); then
    KVER="$(uname -r)"
    [[ -d "/lib/modules/$KVER/build" ]] \
        || die "no hay cabeceras del kernel para $KVER (/lib/modules/$KVER/build).
       Instala kernel-devel, o usa --no-module."
    ok "cabeceras del kernel para $KVER"
fi

if (( WITH_INITRAMFS )); then
    command -v dracut >/dev/null || die "falta dracut (o usa --no-initramfs)"
    ok "dracut $(dracut --version 2>/dev/null | head -1 | awk '{print $NF}')"
fi

if (( WITH_GUI )); then
    if pkg-config --exists gtk4 libadwaita-1 2>/dev/null; then
        ok "gtk4 $(pkg-config --modversion gtk4) + libadwaita $(pkg-config --modversion libadwaita-1)"
    else
        warn "faltan gtk4-devel/libadwaita-devel — me salto la GUI"
        WITH_GUI=0
    fi
fi

# ── Face models ───────────────────────────────────────────────────────────────
#
# Before the build, not after: sysentinel-face embeds the ONNX graphs with
# include_bytes!, so they have to exist on disk or the binary will not compile.

if (( WITH_MODELS )); then
    step "Modelos de reconocimiento facial (ONNX)"
    if [[ -f ramdisk/face/models/scrfd_2.5g_bnkps.onnx && -f ramdisk/face/models/mobilefacenet.onnx ]]; then
        ok "ya están (verificación de integridad en fetch-face-models.sh)"
    else
        info "descargando y verificando sha256…"
        run ./scripts/fetch-face-models.sh
    fi
else
    warn "--no-models: sysentinel-face no se podrá construir (embebe los modelos)"
fi

# ── Build ─────────────────────────────────────────────────────────────────────
#
# All of it as the invoking user.

step "Compilando (sin privilegios)"

info "daemon (release)…"
run cargo build --release --manifest-path daemon/Cargo.toml
ok "daemon/target/release/sysentinel-daemon"

if [[ -f ramdisk/face/models/scrfd_2.5g_bnkps.onnx ]]; then
    info "herramientas del initramfs, estáticas musl…"
    run cargo build --release --manifest-path ramdisk/Cargo.toml --target "$MUSL_TARGET"
    ok "sysentinel-cam + sysentinel-face"
else
    info "herramientas del initramfs (solo cam, sin modelos)…"
    run cargo build --release --manifest-path ramdisk/Cargo.toml --target "$MUSL_TARGET" -p sysentinel-cam
    ok "sysentinel-cam"
fi

if (( WITH_MODULE )); then
    info "módulo del kernel…"
    run make -C kernel_module
    ok "kernel_module/sysentinel_metrics.ko"
fi

if (( WITH_GUI )); then
    info "GUI de escritorio (GTK4)…"
    run cargo build --release --manifest-path gui/linux/Cargo.toml
    ok "gui/linux/target/release/sysentinel-gui"
fi

# The initramfs tools must be static: a dynamic binary cannot run on a bare
# ramdisk, and it fails at boot rather than here.
if (( ! DRY_RUN )); then
    for b in sysentinel-cam sysentinel-face; do
        p="ramdisk/target/$MUSL_TARGET/release/$b"
        [[ -f "$p" ]] || continue
        file "$p" | grep -qE 'static-pie linked|statically linked' \
            || die "$b no quedó enlazado estáticamente; en el initramfs no arrancaría"
    done
    ok "las herramientas del initramfs son estáticas"
fi

# ── Install ───────────────────────────────────────────────────────────────────

step "Instalando (aquí sí hace falta sudo)"

if ! confirm "¿Instalo en el sistema?"; then
    info "nada instalado. Los binarios están compilados."
    exit 0
fi

if (( WITH_MODULE )); then
    info "módulo del kernel → /lib/modules/$(uname -r)/…"
    sudo_run make -C kernel_module modules_install
    sudo_run depmod -a
    ok "módulo instalado (cárgalo con: sudo modprobe sysentinel_metrics write_gid=\$(id -g sysentinel))"
fi

info "daemon, config, unidad systemd…"
sudo_run ./scripts/install.sh

if (( WITH_INITRAMFS )); then
    info "herramientas del initramfs + hooks de dracut + regenerar initramfs…"
    warn "esto regenera tu initramfs actual (install-dracut.sh hace copia antes)"
    if confirm "¿Sigo?"; then
        sudo_run ./scripts/install-dracut.sh
    else
        warn "initramfs sin tocar: no habrá captura pre-LUKS hasta que lo hagas"
    fi
fi

if (( WITH_GUI )); then
    info "GUI → /usr/local/bin/sysentinel-gui…"
    sudo_run install -Dm755 gui/linux/target/release/sysentinel-gui /usr/local/bin/sysentinel-gui
    ok "sysentinel-gui"
fi

# ── What is left for a human ──────────────────────────────────────────────────
#
# Deliberately not automated: these are choices, not steps. An installer that
# picks a listen address or mints a key without being asked has made a security
# decision on the owner's behalf.

step "Listo — lo que queda es tuyo"
cat <<'NEXT'
    1. Configura el daemon. Lo más fácil, sin abrir el fichero:
           sudo ./scripts/configure-credentials.sh

       Te pregunta el proveedor de LLM y su clave (si no tienes, contesta
       "ninguno" y sigue funcionando todo menos la explicación), la dirección
       por la que te ve el teléfono, y genera la clave de emparejamiento.

       A mano, si prefieres:
           sudoedit /etc/sysentinel/config.toml

       Mínimo para que el teléfono funcione:
           [phone]
           enabled = true
           bind = "TU_IP:8443"      # la IP por la que te ve el móvil,
                                    # NO 0.0.0.0 (es de escucha, no un destino)

    2. Arranca y mira el log: sin teléfono emparejado dibuja un QR.
           sudo systemctl enable --now sysentinel
           sudo journalctl -u sysentinel -f

    3. Escanéalo desde la app. Después del primer emparejamiento la clave
       deja de bastar: el equipo exige además la firma de ESE móvil.

    4. Módulo del kernel (opcional, habilita el canal ring 0 → ring −3):
           sudo modprobe sysentinel_metrics write_gid=$(id -g sysentinel)

       El write_gid es lo que deja al daemon mandar controles confirmados y
       leer CR2/CR3. Sin él el módulo funciona igual, pero esos dos registros
       salen como `restricted`: son direcciones, y publicarlas a cualquier
       proceso local es justo lo que quiere un exploit para saltarse KASLR.
NEXT
