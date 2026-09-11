# Tutorial de instalación — sysentinel

Instala **todo**: el daemon (vigilante de logs del kernel + compañero IA que
te habla al teléfono), su servicio systemd y el módulo del kernel
`/proc/sysentinel_metrics`.

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

## 2. La app del teléfono (el canal de salida)

No hay bot en ninguna red pública: el único canal es tu propio teléfono,
conectado directo contra el daemon. Compila e instala el APK antes de seguir,
para tenerlo a mano cuando aparezca el QR de pareo:

```sh
make apk-release          # las dos variantes, desde la raíz del repo
# o, con más control:
cd gui/android && gradle assembleModernRelease   # armv8a, GUI moderna
cd gui/android && gradle assembleLegacyRelease   # armeabi-v7a, GUI clásica

adb install -r gui/android/app/build/outputs/apk/modern/release/app-modern-release.apk
```

Necesita un JDK, el Android SDK y **Gradle 9+** (el 8 no sabe leer Java 25).
No hay wrapper en el repo: usa tu `gradle`, o `make apk-release`, que es lo
mismo con `GRADLE=` configurable.

Firma de release: `gui/android/keystore.properties` (fuera de git) apunta a tu
`.jks`. Sin ese archivo los APK salen SIN firmar y `apksigner` te lo dirá.

> **Enlazar y alcanzar son dos cosas distintas.** Enlazar se hace UNA vez, en
> casa, con el móvil en el mismo WiFi que el PC (sección 6). A partir de ahí el
> vínculo no caduca y no depende de la red: da igual que estés en Italia, en
> España o en Marte, sigue siendo tu PC. Lo que sí cambia con el sitio es si el
> móvil puede ALCANZAR la máquina: en tu red funciona tal cual, y desde fuera
> necesitas un camino que pongas tú (WireGuard o Tailscale — y si pones `bind`
> en la dirección de la VPN, la misma dirección vale en casa y fuera, así que
> no tocas nada al viajar). Sin camino, el daemon encola las alertas y te las
> entrega enteras al reconectar: no las pierde.

---

## 3. Configurar el daemon

```sh
cp daemon/config/config.example.toml daemon/config/config.toml
nano daemon/config/config.toml
```

Edita como mínimo estas claves:

| Clave | Qué poner |
|---|---|
| `[phone] enabled` | `true` para levantar el canal del teléfono |
| `[phone] bind` | La dirección por la que el TELÉFONO ve esta máquina (p. ej. `10.0.0.5:8443`). **No pongas `0.0.0.0`**: el QR la lleva tal cual y el móvil no sabría a dónde marcar |
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
# uptime_s=12345 modules=64 mem_free_kb=204800 mem_total_kb=8388608 hypervisor=... ring3=intel-me me_fw=18.1.2204.0
#   - ring3=   … resultado del dispatcher HAL del módulo: intel-me | amd-psp | none
#   - me_fw=   … solo cuando ring3=intel-me (ME conectado, vía el bus MEI del kernel)
#   - psp=     … solo cuando ring3=amd-psp (handshake HSTI vía el ccp platform-access)
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
> daemon hace HTTPS saliente al proveedor LLM y escucha en `[phone] bind`.

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

Con esto, ya desde la app: `/cr0`, `/cr3`, `/cr4`, `/cr8` leen registros de
control (sin confirmación, no cuesta tokens); `/reboot`, `/poweroff`,
`/cr0 wp off`, `/cr3=0x…` **arman** una acción y exigen `confirm`.

### 5.2 Arrancar

```sh
sudo systemctl enable --now sysentinel
systemctl status sysentinel
journalctl -u sysentinel -f
```

---

## 6. Pareo con el teléfono

1. Sin teléfono registrado, el daemon dibuja un **QR en la consola del equipo**
   al arrancar. Si ya se fue del scrollback, pídelo de nuevo:

   ```sh
   journalctl -u sysentinel -f | grep -i 'pair'
   ```

   `/pair` lo vuelve a dibujar — siempre en la consola local, nunca por el
   canal: mandar la clave por el canal que esa clave abre sería al revés.

2. Escanéalo desde la app. Nadie teclea 64 hexadecimales.
3. La app genera acto seguido una llave dentro del TEE del teléfono
   (StrongBox/Titan si el modelo lo tiene) y la registra. A partir de ahí el
   equipo exige **también** la firma de ESE móvil y rechaza cualquier otro,
   aunque sea el mismo modelo.
4. Después de parear:
   - `/status` → estado del sistema (incluye contexto PMU si `[pmu] enabled`).
   - `/resetcontext` → limpia `context.txt` (contexto de conversación).
   - `/unpair` → olvida el teléfono registrado.
   - Cualquier mensaje de texto → consulta al LLM con memoria + conversación.

5. **Ya está, para siempre.** Desde ese momento puedes irte donde quieras: el
   enlace es entre ESTA máquina y ESE teléfono, no entre dos direcciones IP.
   Si la dirección cambia (estás fuera y entras por la VPN), corrígela en la
   app — toca `equipo: …` en la cabecera — y sigue todo igual; no se vuelve a
   emparejar. En la variante `legacy` (armeabi-v7a) eso se hace por adb:

   ```sh
   adb shell am start -n org.sysentinel.app/.ChatActivity -e host 100.101.102.103 -e port 8443
   ```

Quien vea la pantalla del QR puede leer la clave: por eso deja de bastar en
cuanto hay un móvil registrado. Las acciones privilegiadas piden tu huella o
tu cara en el teléfono, no un `YES` tecleado que alguien puede exigirte en voz
alta o leer por encima del hombro.

Si no aparece QR: revisa que `enabled=true` y que `bind` tenga una dirección
real (no `0.0.0.0`) en `[phone]`.

---

## 7. Pruébalo sin teléfono (opcional)

```sh
RUST_LOG=debug /usr/local/bin/sysentinel-daemon \
    --config /etc/sysentinel/config.toml --dry-run --verbose
```

- `--dry-run` no entrega alertas al teléfono (útil para probar el backend LLM).
- `--verbose` imprime cada evento clasificado de kmsg en stdout.
- `RUST_LOG=debug` sube el nivel de log.

---

## 8. Troubleshooting

| Síntoma | Causa / solución |
|---|---|
| `make[5]: *** No rule to make target 'sysentinel_metrics.o'` | El `.rs` raíz no está junto al `.o` (debe estar en la raíz de `kernel_module/`, regla `$(obj)/%.o: $(obj)/%.rs`). Este repo ya lo tiene así. |
| `E0514: found crate core compiled by an incompatible version of rustc` | `rustc` ≠ al del kernel (rustup vs `/usr/bin/rustc`). En Fedora el `Makefile` ya lo resuelve solo; en otras distros usa el build exacto del kernel. |
| `error: no such file or directory: 'bindgen'` / `bindgen` no encontrado | Instala `bindgen` (Rust): `cargo install bindgen-cli` o `sudo dnf install bindgen rust-bindgen`. |
| La app no conecta | `[phone] bind` apunta a una dirección que el teléfono no alcanza (o es `0.0.0.0`). Comprueba desde el móvil que llegas a ese `IP:puerto`. |
| La app dice que el equipo la rechaza | Ya hay OTRO teléfono registrado: el equipo exige la firma de ese. Haz `/unpair` desde el teléfono registrado, o borra el registro en el equipo, y vuelve a escanear. |
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