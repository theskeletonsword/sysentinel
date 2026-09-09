# Tutorial de instalación — sysentinel

Instala **todo**: el daemon (vigilante de logs del kernel + compañero IA por
Telegram), su servicio systemd y el módulo del kernel `/proc/sysentinel_metrics`.

> Destinado a sistemas con kernel habilitado para Rust (`CONFIG_RUST=y`), por
> ejemplo Fedora 44 con `kernel-devel` ≥ 7.1.8. El flujo es el mismo en otras
> distros; adapta los nombres de paquete (`dnf` → `apt`/`pacman`) y el ruta del
> árbol del kernel.

---

## 0. Requisitos

```sh
# Fedora / RHEL:
sudo dnf install git gcc make pkgconfig openssl-devel rust-up rust-std-static \
                 systemd-devel kernel-devel kernel-headers bindgen rust-bindgen

# Python 3.10+ (herramienta de soporte del kernel, si la necesitas)
```

Necesitas además **Rust** para el daemon (usa `rustup`):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**Importante:** para el módulo del kernel, el `rustc` usado debe ser el **mismo
`rustc` que compiló tu kernel** (ver [Paso 4 - Módulo del kernel](#4-módulo-del-kernel-opcional)).

---

## 1. Clonar y compilar el daemon

```sh
git clone https://github.com/tu-usuario/kernelgpt   # o copia el repo donde esté
cd kernelgpt
make daemon        # => cargo build --release (en daemon/)
```

El binario queda en `daemon/target/release/sysentinel-daemon`.

Para verificar que todo compila y pasa sus tests:

```sh
cd daemon && cargo test
```

---

## 2. Crear y configurar el bot de Telegram

1. Abre Telegram y habla con **[@BotFather](https://t.me/BotFather)**.
2. Envía `/newbot`, ponle nombre y username. BotFather te da un **token**
   (formato `123456:AAH…`). Guárdalo.
3. Consigue tu **ID de usuario** (lo usamos para AMARRAR el token de pareo a tu
   cuenta): habla con **[@userinfobot](https://t.me/userinfobot)** —te responde
   un número, p. ej. `6069669002`.

---

## 3. Configurar el daemon

```sh
cp daemon/config/config.example.toml daemon/config/config.toml
nano daemon/config/config.toml
```

Edita como mínimo estas claves:

| Clave | Qué poner |
|---|---|
| `[telegram] bot_token` | El token de @BotFather |
| `[telegram] telegram_id` | Tu ID de usuario; **sin esto el daemon se niega a generar token de pareo** |
| `[llm] backend` | `deepseek`, `openai`, `anthropic`, `gemini`, `local` o `none` |
| `[llm.deepseek] api_key` (o el backend que uses) | Tu API key del proveedor |
| `[persona] tone` / `language` | Tono y idioma de las respuestas |
| `[memory] memory_file` / `context_file` | Archivos de memoria; déjalos en `/var/lib/sysentinel/*` |

Protege el archivo (contiene secretos):

```sh
chmod 600 daemon/config/config.toml
```

> **No** subas `config.toml` con secretos reales a git. El repo solo debe
> contener `config.example.toml` con placeholders.

---

## 4. Módulo del kernel (opcional)

> El daemon funciona sin el módulo (solo lee `/dev/kmsg`). El módulo expone
> `/proc/sysentinel_metrics` con un snapshot de métricas, y sirve como ejemplo de
> módulo Rust contra `rust-for-linux`.

### 4.1 Verificar que tu kernel soporta Rust

```sh
grep CONFIG_RUST /boot/config-$(uname -r)
# => CONFIG_RUST=y
```

Si sale `# CONFIG_RUST is not set`, tu kernel no puede cargar módulos Rust:
compila un kernel con `CONFIG_RUST=y` o salta este paso.

### 4.2 Usar el `rustc` exacto del kernel

Los bindings precompilados del kernel (`/usr/src/kernels/<versión>/rust/*.rmeta`)
**exigen el `rustc` con el que se construyeron**. Un `rustc` de la misma versión
de *otra* fuente (p. ej. rustup) falla con `E0514 "found crate core compiled by
an incompatible version of rustc"`.

En Fedora 44 eso NO es problema: el compilador exacto ya viene instalado como
**`/usr/bin/rustc`**, y el `Makefile` del módulo ancla `RUSTC`/`HOSTRUSTC` a
esa ruta automáticamente. Solo compila (sin tocar el PATH):

```sh
cd kernel_module
make
# => sysentinel: using rustc: /usr/bin/rustc
```

En otras distros: averigua cuál exige tu kernel y asegúrate de que ese `rustc`
esté en `PATH` (o pásalo explícito: `make RUSTC=/ruta/al/rustc`):

```sh
grep CONFIG_RUSTC_VERSION_TEXT /boot/config-$(uname -r)
# => CONFIG_RUSTC_VERSION_TEXT="rustc 1.97.1 (…)(Fedora 1.97.1-1.fc44)"
```

### 4.3 Compilar y cargar

```sh
cd kernel_module
make            # MEI habilitado por defecto (usa el árbol de /lib/modules/$(uname -r)/build)
sudo make modules_install
sudo modprobe sysentinel_metrics
cat /proc/sysentinel_metrics
# uptime_s=12345 modules=64 mem_free_kb=204800 mem_total_kb=8388608 hypervisor=... me_fw=18.1.2204.0 psp=n/a
#   - me_fw=  … solo en plataformas Intel con ME conectado, vía el bus MEI del kernel
#   - psp=    … "present" solo en CPUs AMD (detector portátil por vendor; en este Intel saldrá n/a)
sudo rmmod sysentinel_metrics
```

El archivo vive en `/proc` (no `/dev`), es de solo lectura para cualquiera, y
además acepta **escribir comandos privilegiados** (`reboot`, `poweroff`,
`cr0_wp on|off`, `cr3=0x…`), gatecircuited por el grupo `write_gid`:

```sh
# Dar control al grupo del servicio (id del grupo 'sysentinel'):
sudo modprobe sysentinel_metrics write_gid=$(id -g sysentinel)
# NUNCA pruebes con reboot directo: confirma primero. El bot exige confirm.
```

Para arrancarlo al encender, instala un `modprobe.d`:

```sh
echo 'sysentinel_metrics' | sudo tee /etc/modules-load.d/sysentinel.conf
```

### 4.4 Si cambias de kernel

Recompila contra el nuevo árbol:

```sh
make clean && make
sudo make modules_install
sudo depmod -a
```

---

## 5. Instalar el daemon como servicio

```sh
make install        # compila + scripts/install.sh (requiere sudo)
```

`scripts/install.sh`:

1. Copia `sysentinel-daemon` a `/usr/local/bin/`, y el **template** de config a
   `/etc/sysentinel/config.toml` (solo si no existe — **si ya configurabas un
   config, edita el de `/etc/sysentinel/`**).
2. Crea el usuario de sistema `sysentinel`.
3. Crea `/var/lib/sysentinel` y `/var/log/sysentinel`.
4. Instala el unit systemd `sysentinel.service`.

> El unit monta *hardening*: usuario sin privilegios, `NoNewPrivileges=true`,
> filesystem read-only salvo rutas de estado, y solo `CAP_SYSLOG` +
> `CAP_PERFMON` (ambient). No activa `PrivateNetwork` a propósito porque el
> daemon hace HTTPS saliente a Telegram/LLM.

### 5.1 Configuración de producción

```sh
sudo cp daemon/config/config.toml /etc/sysentinel/config.toml   # el tuyo (con tus secretos)
sudo chown root:sysentinel /etc/sysentinel/config.toml
sudo chmod 640   /etc/sysentinel/config.toml   # el usuario del servicio (grupo sysentinel) tiene que poder LEERLO
```

Para ME/PSP NO necesitas grupos extra: la versión de Intel ME la lee el
módulo kernel `sysentinel_metrics` en ring-0 (a través del bus MEI del
kernel) y el daemon la obtiene de `/proc/sysentinel_metrics`; el PSP/TPM de
AMD se lee desde sysfs con la etiqueta correcta según fabricante. El archivo
`/proc/sysentinel_metrics` es legible por cualquiera (0644), no hay regla
udev ni grupos que configurar. En hosts AMD (PSP) no hay MEI que consultar,
y en hosts Intel no se reporta PSP — el código es agnóstico de plataforma.

### 5.2 Comandos privilegiados (opcional, requiere confirmación)

El módulo también acepta **escribir** comandos de control; el bot añade un
flujo de confirmación doble (armar + `confirm` en 60 s) y es el único que
escribe. Para que el servicio pueda escribir hay que cargar el módulo con el
GID de su grupo:

```sh
sudo modprobe sysentinel_metrics write_gid=$(id -g sysentinel)
```

Con esto, ya en Telegram: `/cr0`, `/cr3`, `/cr4`, `/cr8` leen registros de
control (sin confirmación, no cuesta tokens); `/reboot`, `/poweroff`,
`/cr0 wp off`, `/cr3=0x…` **arman** una acción y exigen `confirm`.

### 5.2 Arrancar

```sh
sudo systemctl enable --now sysentinel
systemctl status sysentinel
journalctl -u sysentinel -f
```

---

## 6. Pareo con Telegram

1. En el log del servicio busca el token:

   ```sh
   journalctl -u sysentinel -f | grep -i syn-
   # => pair: token SYN-A1B2C3D4 minted for telegram_id 6069669002 (5 min)
   ```

2. Abre tu bot y envía el token **desde tu propia cuenta** (la del
   `telegram_id`): `SYN-A1B2C3D4`.
3. El bot responde pidiendo confirmación. Envía `YES` para completar (o `DENY`
   para quemar el intento).
4. Después de parear:
   - `/start` → menú.
   - `/status` → estado del sistema (incluye contexto PMU si `[pmu] enabled`).
   - `/resetcontext` → limpia `context.txt` (contexto de conversación).
   - `/unpair` → deshace el pareo (si existe).
   - Cualquier mensaje de texto → consulta al LLM con memoria + conversación.

Seguridad del token: expira a los 5 min, se quema tras 5 intentos fallidos,
solo se acepta desde el `telegram_id` configurado, y se guarda hasheado con
Argon2id (nunca en texto plano).

Si no aparece token: revisa que `bot_token` y `telegram_id` estén configurados y
que `enabled=true` e `interactive=true` en `[telegram]`.

---

## 7. Pruébalo sin Telegram (opcional)

```sh
RUST_LOG=debug /usr/local/bin/sysentinel-daemon \
    --config /etc/sysentinel/config.toml --dry-run --verbose
```

- `--dry-run` no envía alertas por Telegram (útil para probar el backend LLM).
- `--verbose` imprime cada evento clasificado de kmsg en stdout.
- `RUST_LOG=debug` sube el nivel de log.

---

## 8. Troubleshooting

| Síntoma | Causa / solución |
|---|---|
| `make[5]: *** No rule to make target 'sysentinel_metrics.o'` | El `.rs` raíz no está junto al `.o` (debe estar en la raíz de `kernel_module/`, regla `$(obj)/%.o: $(obj)/%.rs`). Este repo ya lo tiene así. |
| `E0514: found crate core compiled by an incompatible version of rustc` | `rustc` ≠ al del kernel (rustup vs `/usr/bin/rustc`). En Fedora el `Makefile` ya lo resuelve solo; en otras distros usa el build exacto del kernel. |
| `error: no such file or directory: 'bindgen'` / `bindgen` no encontrado | Instala `bindgen` (Rust): `cargo install bindgen-cli` o `sudo dnf install bindgen rust-bindgen`. |
| `connector must be configured with Long Polling` / bot no responde | Falta `interactive=true` en `[telegram]` o el `bot_token` es inválido. |
| Bot responde "pareo denegado" o ignora el token | El token se envió desde una cuenta distinta a `telegram_id`, expiró (5 min) o se quemó por 5 fallos. Vuelve a generarlo (reinicia el daemon) y envíalo desde la cuenta correcta. |
| No llegan alertas | Revisa `enabled=true`, `min_severity`, y que el backend LLM tenga API key válida. |
| `error: while loading config` | Falta una sección/clave; compara con `config.example.toml`. |
| Módulo compila pero `modprobe` dice "invalid module format" | Modulo construido contra otro kernel. `make clean && make && make modules_install && depmod -a`. |

---

## 9. Desinstalar

```sh
make uninstall   # para/borra servicio + descarga módulo (no borra secretos)
# borra también, si quieres:
sudo rm -rf /etc/sysentinel /var/log/sysentinel
sudo userdel sysentinel
sudo rm -f /etc/modules-load.d/sysentinel.conf
```

---

## 10. Seguridad (resumen)

- `config.toml` con `chmod 600`; nunca lo subas a git. Rota el bot token/API key
  si alguna vez los expusiste.
- El daemon corre sin privilegios; solo `CAP_SYSLOG` (kmsg) y `CAP_PERFMON`
  (contadores HW PMU). Se degrada con gracia si falta `CAP_PERFMON`.
- El módulo del kernel expone lectura global (`/proc/sysentinel_metrics`) y
  **escribe solo comandos de control**, gatecircuited por el grupo `write_gid`
  (por defecto solo root). Los comandos van precedidos de un flujo de
  confirmación de la persona (armar + `confirm` en 60 s): nunca se ejecutan
  solos, y fuera de ese flujo el módulo los rechaza por permisos.
- El token de pareo es de un solo uso, con TTL, ligado a tu cuenta y a prueba de
  fuerza bruta.