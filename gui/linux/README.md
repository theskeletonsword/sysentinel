# gui/linux — GTK4 desktop front-end

Apache-2.0. A separate crate on purpose: GTK is a heavy dependency tree, and
building it has nothing to do with building the daemon. Keeping it out means
`daemon/` and its CI never grow a GTK requirement, and anyone who does not want
a GUI does not compile one.

## Building

Needs the development packages, not just the runtimes most desktops already
have:

```sh
# Fedora
sudo dnf install gtk4-devel libadwaita-devel
# Debian/Ubuntu
sudo apt install libgtk-4-dev libadwaita-1-dev
```

Then:

```sh
cargo build --release --manifest-path gui/linux/Cargo.toml
```

## Talking to the daemon

Over the local Unix socket, which is off by default. Enable it in `config.toml`:

```toml
[ipc]
enabled = true
# group = "sysentinel"   # else the socket stays 0600 root-only
```

The socket's permissions are the whole access control, because the daemon behind
it runs as root. See the `[ipc]` block in `daemon/config/config.example.toml`.

## What it will not do

Raise notifications. See [`../README.md`](../README.md).
