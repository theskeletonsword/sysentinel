<!-- SPDX-License-Identifier: Apache-2.0 -->

# Enlazar el PC y el celular por Tailscale

Esto es la ruta recomendada para llegar a tu equipo desde fuera de casa, y la
razón es una sola: **la dirección de Tailscale es la misma en el sofá y en
Marte**. El QR que escaneas una vez sigue valiendo desde otro continente, no
hay que reconfigurar nada al viajar, y el puerto del daemon no existe fuera de
tu red privada — los escaneos de internet ni lo ven. Funciona además bajo CGNAT,
que es donde el port forwarding simplemente no es posible.

Si prefieres las otras dos rutas (redirección de puerto + DDNS, o un túnel tipo
ngrok), están en `daemon/config/config.example.toml` con sus pegas escritas sin
adornos. Esta es la que menos te va a molestar.

> **Qué cuesta, para que lo sepas antes de empezar.** Tailscale coordina las
> claves con un servidor suyo. El tráfico **no** pasa por ahí — es WireGuard
> punto a punto, y si no hay ruta directa el relay DERP solo ve cifrado — pero
> ese servidor sabe qué equipos tienes, cómo se llaman y cuándo se conectan. Si
> eso te sobra, al final hay una sección con las alternativas.

---

## Lo que vas a tener al terminar

```
   Celular (cliente)                        PC (host)
   ┌────────────────┐                       ┌────────────────────────┐
   │ app sysentinel │                       │ sysentinel-daemon      │
   │ app Tailscale  │                       │ tailscaled             │
   └───────┬────────┘                       └───────────┬────────────┘
           │  100.x.y.z:8443                            │
           │  TLS 1.3 + frames sellados                 │
           └──────────── WireGuard ─────────────────────┘
                    (directo, o relay DERP cifrado)
```

Cuatro cosas tienen que ser verdad a la vez, y el tutorial es básicamente
comprobarlas en orden:

1. Los dos equipos están en **la misma cuenta** de Tailscale (el error nº 1).
2. `[phone] bind` apunta a la **IP de Tailscale del PC**, no a la de la LAN.
3. `tailscaled` arranca **antes** que el daemon.
4. El celular escaneó el QR **después** de todo lo anterior.

---

## 1. Tailscale en el PC

En Fedora (que es lo que corres):

```sh
sudo dnf install tailscale
sudo systemctl enable --now tailscaled
sudo tailscale up
```

`tailscale up` imprime una URL. Ábrela, inicia sesión, y **fíjate con qué
cuenta** — ese detalle es el que hay que repetir en el celular.

Comprueba que quedó arriba y apunta tu dirección:

```sh
tailscale status
tailscale ip -4        # => 100.101.102.103   ← esta es la que importa
```

Esa `100.x` es tuya para siempre mientras el equipo siga en el tailnet. No
cambia de red en red: ese es el truco entero.

## 2. Tailscale en el celular

Instala la app de Tailscale desde Play Store (o el APK de tailscale.com si no
usas Play), ábrela y entra **con la misma cuenta del paso anterior**. Nada más;
no hace falta tocar exit nodes, subnet routers ni MagicDNS.

Verifica desde el PC que el celular ya está en el tailnet:

```sh
tailscale status        # el celular tiene que aparecer en la lista
tailscale ping <nombre-del-celular>
```

Si `tailscale ping` responde `direct`, van punto a punto. Si dice `via DERP`,
también funciona — el relay solo mueve bytes cifrados que no puede leer — pero
la latencia es peor. No hay nada que arreglar en ninguno de los dos casos.

## 3. Apuntar el daemon a la dirección de Tailscale

Lo más rápido, sin abrir el config:

```sh
sudo ./scripts/configure-credentials.sh --bind "$(tailscale ip -4):8443"
```

O a mano, en `/etc/sysentinel/config.toml`:

```toml
[phone]
enabled = true
bind    = "100.101.102.103:8443"   # la 100.x de `tailscale ip -4`
```

Tres cosas que la gente hace mal aquí:

- **`bind` es la IP de Tailscale, no la de la LAN.** Si pones la 192.168.x
  funciona en casa y deja de funcionar al salir, que es justo lo que veníamos a
  evitar.
- **No pongas `0.0.0.0`.** Es una dirección de escucha, no un destino; el QR la
  lleva tal cual y el celular no sabría a dónde marcar. El daemon te avisa.
- **No hace falta `advertise`.** Es para cuando el QR tiene que decir algo
  distinto de donde escuchas — un túnel, un nombre DDNS. Aquí escuchas justo
  donde el celular marca.

Con MagicDNS puedes poner el nombre en `advertise` si prefieres leerlo
(`advertise = "mi-pc.tailnet-1234.ts.net:8443"`), pero `bind` sigue siendo la
IP: es lo que la máquina tiene de verdad, y es lo que se puede escuchar.

## 4. Arrancar, y escanear el QR

```sh
sudo systemctl restart sysentinel
sudo journalctl -u sysentinel -f
```

Si nunca lo arrancaste, `enable --now` en vez de `restart`.

Sin teléfono registrado, el daemon dibuja el QR en la consola del equipo.
Escanéalo **desde la app de sysentinel**, no desde la de Tailscale.

Ese QR lleva tres cosas: la dirección, la clave de emparejamiento, y la
**huella TLS del equipo**. La app exige las tres — un QR sin huella lo rechaza
en vez de conectarse a ciegas. Si vienes de una versión anterior de este
proyecto, tu emparejamiento viejo no vale: hay que volver a escanear.

Justo después de escanear, el celular genera una llave dentro de su TEE
(StrongBox/Titan si el modelo lo tiene) y la registra. A partir de ahí el
equipo exige **además** la firma de ESE móvil y rechaza cualquier otro, aunque
sea el mismo modelo con la misma clave de emparejamiento copiada.

---

## Comprobar que quedó bien

Lo primero, antes de culpar a nada: que los dos aparezcan en el mismo tailnet.

```sh
tailscale status
# 100.101.102.103  mi-pc     tu-cuenta@  linux    -
# 100.104.105.106  mi-movil  tu-cuenta@  android  -

tailscale ping mi-movil
# pong from mi-movil (100.104.105.106) via 203.0.113.9:39380 in 117ms
```

`pong … via <IP>:<puerto>` es conexión directa. `via DERP` también sirve.

Desde el PC, que el puerto esté escuchando en la dirección correcta:

```sh
ss -ltnp | grep 8443
# LISTEN 0 128 100.101.102.103:8443 ...
```

Desde el celular, antes de culpar a la app: abre la de Tailscale y mira que el
PC aparezca como conectado. Si tienes Termux, `nc -vz 100.101.102.103 8443`
responde en una línea.

Y en el log del daemon, la línea que confirma las dos capas:

```
phone: listening on 100.101.102.103:8443 — direct, no relay, no third party
phone: authenticated client (app 0.1.0)
```

---

## Cuando algo no va

| Síntoma | Qué está pasando |
|---|---|
| `phone: 100.x.y.z:8443 no existe todavía — esperando a que aparezca la interfaz` | El daemon arrancó antes que `tailscaled`. Espera hasta un minuto por su cuenta y el unit ya va detrás de `tailscaled.service`, así que normalmente se resuelve solo. Si persiste: `systemctl is-active tailscaled`. |
| `phone: cannot listen on … Cannot assign requested address` | La `100.x` del config no es la de esta máquina (o Tailscale está caído). `tailscale ip -4` y corrige. |
| La app dice «No pude conectar» | Mira la app de Tailscale en el celular: si el tailnet está caído ahí, no es cosa de sysentinel. Después, `tailscale status` en el PC para ver si el celular aparece. |
| La app dice que la llave del equipo no es la que guardó | O reinstalaste el daemon (y se hizo un certificado nuevo), o alguien responde en su lugar. Si fuiste tú: borra el emparejamiento en la app y vuelve a escanear. Si no fuiste tú, ese mensaje es exactamente lo que esta herramienta existe para darte. |
| Todo bien pero lento | `tailscale ping <celular>`: si va `via DERP`, estás pasando por un relay. Suele arreglarlo abrir UDP 41641 saliente en el router, y si no, funciona igual, más lento. |
| Cuentas distintas | El error nº 1. `tailscale status` en el PC no lista el celular. Sal de la sesión en la app del celular y entra con la misma cuenta. |

**Sobre el firewall, en tu máquina concreta:** esta Fedora Workstation usa la
zona `FedoraWorkstation`, que ya permite TCP 1025-65535 entrante — o sea que
8443 está abierto y no tienes que tocar nada. En Fedora **Server** (zona
`FedoraServer`) o con la zona `public`, no lo está, y entonces sí:

```sh
# Lo correcto es abrirlo SOLO en la interfaz de Tailscale, no en todas:
sudo firewall-cmd --permanent --zone=trusted --change-interface=tailscale0
sudo firewall-cmd --reload
```

Poner `tailscale0` en la zona `trusted` es lo que recomienda la propia
Tailscale, y es mejor que abrir el puerto a secas: el puerto queda accesible
desde tu tailnet y desde ningún otro sitio.

---

## Endurecerlo un poco más (opcional, y vale la pena)

Por defecto, en un tailnet personal **todos tus dispositivos pueden hablar con
todos**. Si tienes más equipos ahí dentro, puedes dejar que solo el celular
llegue al puerto del daemon, editando las ACL en la consola de Tailscale:

```jsonc
{
  "acls": [
    // Tu celular al puerto del daemon, y nada más hacia ese equipo.
    { "action": "accept", "src": ["tag:celular"], "dst": ["tag:pc-vigilado:8443"] }
  ],
  "tagOwners": {
    "tag:celular":    ["autogroup:admin"],
    "tag:pc-vigilado": ["autogroup:admin"]
  }
}
```

Luego etiquetas cada máquina (`tailscale up --advertise-tags=tag:pc-vigilado`).
No es imprescindible — la clave de emparejamiento y la firma del móvil ya
deciden quién habla — pero reduce a quién le contesta siquiera el socket, y eso
es una superficie menos.

Otras dos, gratis:

- **Key expiry.** Por defecto las llaves de un nodo caducan cada 180 días y hay
  que reautenticar. Para el PC que vigila tu casa eso es una interrupción en el
  peor momento: desactívalo para ese nodo en la consola (*Disable key expiry*).
- **Tailnet lock**, si te lo tomas en serio: hace que un nodo nuevo tenga que
  ser firmado por uno de confianza, de modo que ni alguien con acceso a tu
  cuenta de Tailscale pueda meter un equipo en tu tailnet sin tocar tu llave.

---

## Si no quieres un coordinador ajeno

Lo dicho al principio: el tráfico no pasa por Tailscale, pero su servidor de
coordinación sí sabe qué nodos tienes y cuándo se conectan. Dos salidas:

- **Headscale** — el plano de control de Tailscale, reimplementado en abierto,
  corriendo en tu propia máquina. Las apps oficiales de Tailscale funcionan
  contra él. Es la opción si quieres exactamente esto sin el tercero.
- **WireGuard a pelo** — sin coordinador de ningún tipo. Pierdes el
  descubrimiento automático, el NAT traversal y el roaming, que es justo lo que
  hace cómodo a Tailscale; a cambio no hay nadie más en la ecuación. Configura
  el túnel, pon `bind` en la IP de WireGuard del PC, y el resto de este tutorial
  vale igual.

En los dos casos, para sysentinel no cambia nada: `bind` apunta a la dirección
de la interfaz del túnel y el QR se escanea igual.

---

## Lo que sigue protegiéndote aunque el túnel falle

Tailscale es cómo se *llega* al equipo, no cómo se *autentica* quien llega. Aún
dentro del tailnet, para que algo hable con tu daemon hacen falta tres cosas a
la vez:

1. Completar un **TLS 1.3** cuya llave el celular fijó al emparejar.
2. Abrir un frame sellado con la **clave de emparejamiento**.
3. Firmar un desafío con la llave que vive **dentro del TEE de ese celular**.

Un nodo cualquiera de tu tailnet, o Tailscale mismo, no tiene ninguna de las
tres. Por eso el canal no se apoya en la VPN para su seguridad: se apoya en
ella para su alcance.

Ver también: [`tutorial.md`](tutorial.md) para la instalación completa,
[`SECURITY.md`](SECURITY.md) para qué está en scope y qué no, y la sección
`[phone]` de `daemon/config/config.example.toml` para las otras dos rutas de
acceso remoto con sus costes.
