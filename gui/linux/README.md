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

Two modes, same crate. The mode is decided by the environment the binary starts in.

### Local — server GUI

Default. Talks to the daemon on this same machine through the Unix socket.

```sh
# no env var needed: the GUI reads /run/sysentinel/gui.sock (or
# SYSENTINEL_SOCKET) automatically.
./target/release/sysentinel-gui
```

The daemon needs the socket on in `config.toml`:

```toml
[ipc]
enabled = true
# group = "sysentinel"   # else the socket stays 0600 root-only
```

The socket's permissions are the access control: the daemon behind it runs as
root.

### Remote — client GUI

Points at a different machine. TLS 1.3 with the remote machine's pinned
certificate proves this GUI is talking to the right daemon, and a token
authenticates this client to it. Both halves are part of the string the daemon
prints at start:

```text
  Network console — point the client GUI at this machine:

    address  192.168.1.50:8888
    pin      sha256/...
    token    the [ipc] net_token from config.toml
    env      SYSENTINEL_CONNECT="sysentinel://connect?addr=192.168.1.50:8888&pin=sha256/...&token=<net_token>"

    Nothing is served to anyone who does not present that token over a
    handshake pinned to this machine's key.
```

Pass the connect string as an environment variable and the same binary switches
to client mode:

```sh
SYSENTINEL_CONNECT="sysentinel://connect?addr=192.168.1.50:8888&pin=sha256/...&token=<64 hex>" \
    ./target/release/sysentinel-gui
```

The header shows `client → 192.168.1.50:8888` and the panels pull from the
remote daemon over pinned TLS. The token lives in the remote daemon's
`config.toml` under `[ipc] net_token`.

See the `[ipc]` block in `daemon/config/config.example.toml` for the full set
of options.

## What it will not do

Raise notifications. See [`../README.md`](../README.md).
