# ramdisk/ — initramfs tools

> ## ⚠️ THIS DIRECTORY IS **NOT** APACHE-2.0 ⚠️
>
> The rest of this repository is Apache-2.0. **This directory is
> `MIT OR GPL-2.0-or-later`** — dual-licensed, so you may take it under MIT
> alone. Licence texts: [`LICENSE-MIT`](LICENSE-MIT) ·
> [`LICENSE-GPL`](LICENSE-GPL). Every source file carries an
> `SPDX-License-Identifier` header, which is authoritative for that file.
>
> Unlike [`kernel_module/`](../kernel_module/), nothing here links against the
> kernel: these are ordinary static user-space binaries that happen to run
> inside an initramfs. The MIT option therefore survives into the built
> binaries.
>
> One exception to watch: the ONNX face models under
> [`face/models/`](face/models/) are **third-party, Apache-2.0**, and are not
> covered by this directory's licence. They are gitignored and fetched by
> `scripts/fetch-face-models.sh`; attribution lives in
> [`face/models/NOTICE`](face/models/NOTICE).

Two statically-linked `x86_64-unknown-linux-musl` binaries plus the dracut
module that installs them, so they run on a bare ramdisk with no libc to load:

| Path | What it is |
|---|---|
| `cam/` | `sysentinel-cam` — V4L2 snapshot tool (libc + `image` only, tiny) |
| `face/` | `sysentinel-face` — SCRFD detect + MobileFaceNet embed, via `tract`; models embedded with `include_bytes!` |
| `91sysentinel/` | dracut module: hooks that load the kernel module and capture LUKS evidence |

Build and install through the top-level Makefile:

```sh
make ramdisk          # cargo build --release for both binaries
sudo make install-dracut   # stage 91sysentinel + regenerate the initramfs
```

The daemon (`daemon/`) stays a glibc build; musl is only for these initramfs
tools.
