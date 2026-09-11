<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security policy

**Everything in this repository is in scope, and every vulnerability is
eligible for a report.** There is no carve-out, no component that "does not
count", and no class of finding that gets waved away as by design.

Report to **agustin.pereira.ro@gmail.com**.

---

## Scope: all of it

| Component | What it is | In scope |
|---|---|---|
| `daemon/` | The userspace watchdog: the phone channel, the command layer, the LLM calls, the face pipeline, every watcher | ✅ |
| `kernel_module/` | A ring-0 kernel module: procfs nodes, the MEI/HECI client, the rootkit defender, the hypercall watcher, the triple-fault path | ✅ |
| `ramdisk/` | `sysentinel-cam` and `sysentinel-face`, both running **as root inside the initramfs** before the disk is unlocked | ✅ |
| `ramdisk/91sysentinel/` | The dracut hooks, also root, also pre-unlock | ✅ |
| `gui/android/` | The phone app: pairing, the device key in the TEE, the biometric confirmation | ✅ |
| `gui/linux/` | The GTK4 desktop front-end and its control socket client | ✅ |
| `scripts/` | Installers, the systemd unit, the model fetcher | ✅ |
| Documentation | `README.md`, `tutorial.md`, `daemon/config/config.example.toml` | ✅ |

**Documentation counts.** A tutorial that tells someone to `chmod 644` a file
holding a pairing key is a vulnerability in the same way the code would be —
most people will do what the instructions say, and the instructions are part of
what ships. The same goes for a config comment that recommends a weak setup, or
a default in `config.example.toml` that is unsafe.

Findings in dependencies are in scope too when this project's *use* of them is
what makes them exploitable. A CVE in a crate nothing calls is worth a mention;
a crate called with input from the network is worth a report.

## What counts as a vulnerability here

This is a security tool, so the usual list is only half of it. The other half
is anything that stops it from doing its job.

**The usual list.** Memory corruption, privilege escalation, an unauthenticated
peer reaching something they should not, key or credential disclosure, path
traversal, injection of any kind, a check that can be bypassed, a cryptographic
mistake — nonce reuse, a fixed salt, a signature that is verified against the
wrong thing, a comparison that leaks timing when it matters.

**And the half specific to this project:**

- **Silencing it.** Anything that stops an alert reaching the owner is a
  vulnerability, not a bug. A watchdog that watches and cannot tell anyone has
  failed completely. That includes denial of service against the phone channel,
  a panic that kills a watcher thread, and a way to drain or empty an audit log
  before the daemon reads it.
- **Lying to it.** Anything that lets someone fabricate evidence — a forged
  LUKS marker, a face template the machine did not enrol, a log line that reads
  like the daemon's own words. An alarm that can be made to say the wrong thing
  is worse than no alarm, because it is believed.
- **Fail-open.** Anywhere a damaged, missing or unreadable file turns a check
  off instead of turning the daemon off. If corrupting one file downgrades this
  machine to "trust anyone", that is a finding even though nothing was
  technically bypassed.
- **Leaking what it learns.** This daemon handles biometric templates, machine
  fingerprints, photographs of whoever is at the keyboard, and kernel state.
  Any path that puts those somewhere they should not go — removable media, a
  world-readable file, a third party, a log — is in scope.
- **Coercion paths.** A design where a confirmation can be demanded out loud,
  read over a shoulder, or replayed by somebody who is not present. The
  confirmation ladder in `daemon/src/confirm.rs` exists for this; anything that
  quietly downgrades a rung is a finding.
- **Ring −3 and ring 0.** Anything reachable through the MEI/HECI client, the
  PSP path, the SMM posture reader, or the kernel module's procfs nodes. These
  run where a mistake is not recoverable from userspace.
- **An unimplemented security control.** A feature documented as protecting
  something that is not wired up protects nothing, and the documentation makes
  it worse by being believed. Two were found this way in September 2026.

Design decisions are in scope as findings, not just implementation slips. "This
was deliberate" is an answer to *why*, not a reason to close the report.

## What is not a vulnerability

Only two things, and both are stated on purpose rather than to narrow the
surface:

- **The dangerous features being dangerous.** `/reboot`, `/poweroff`,
  `/triplefault`, `/kernelpanic` and the control-register writes are meant to
  take the machine down; the kernel module is meant to write CR0.WP; the
  rootkit defender is meant to rewrite IDT gates. That they are destructive is
  the feature. *How they are reached* is absolutely in scope: a way around the
  ARM → confirm ritual, a confirmation that can be replayed, a gate that admits
  the wrong caller.
- **Needing root or the owner's own phone to begin with.** An attack that
  starts with "assume you are already root on the machine" is not usually
  telling us anything — though a way to *keep* that access invisibly, or to
  turn root on one machine into access to the owner's phone or another host,
  very much is.

If you are unsure which side of the line something falls on, send it. Getting a
report that turns out to be intended behaviour costs a reply; not getting one
costs a lot more.

## How to report

Email **agustin.pereira.ro@gmail.com** with whatever you have. There is no
template and no required format — a short paragraph and a reproduction is worth
more than a polished document.

Useful, if you have them:

- what an attacker gets out of it, in one sentence;
- the steps, the commit, or a patch that makes it happen;
- which component and file, if you already know;
- whether it needs local access, physical access, the phone, or nothing.

**Do not open a public issue for something exploitable.** Anything else —
hardening ideas, a suspicious-looking function, a question about whether
something is intended — is fine in the open.

Please do not run tests against machines that are not yours. This software
watches somebody's computer and photographs whoever sits at it; testing it
against a stranger's install is the thing it exists to catch.

## What to expect back

One person maintains this, so: a reply as soon as it is read, and an honest
answer about whether and when it will be fixed. If a finding is real and I
cannot fix it quickly, it gets written down publicly rather than left quiet —
users of a security tool are entitled to know what it does not protect them
from.

Credit in the commit and the release notes if you want it, and none if you
prefer. No bounty: this is a personal project with no budget behind it, and
pretending otherwise would waste your time.

## Known limitations

Stated plainly, because a security tool that hides what it cannot do is selling
something:

- **The kernel module is out-of-tree and runs in ring 0.** A bug in it is a
  kernel bug. It writes control registers and IDT gates by design.
- **`PrivateTmp=false` in the systemd unit**, deliberately: the module analyser
  has to see the system `/tmp` to find an intruder's dropped `.ko`. Anything
  the daemon stages now goes to a private `0700` directory instead.
- **The rootkit defender's baseline is whatever was there at module load.** A
  rootkit already resident before the module loads becomes the trusted state.
- **The phone app has never run on real hardware.** StrongBox, Keystore and
  the biometric flows compile and pass their JVM tests; nobody has yet paired a
  real handset.
- **Key attestation is recorded, not verified.** A phone's claim about what
  backs its key is downgraded rather than trusted (see
  `ConfirmMethod::proven`), but the certificate chain is not yet parsed.
- **Exposing the phone port to the internet is your decision.** The daemon
  refuses nothing, and `config.example.toml` ranks the options with their real
  costs. A VPN address is the recommended one.

## History

A full internal review ran on 2026-09-11: 33 findings across two passes, all
fixed, classified critical through informational. Nothing critical was found;
the serious ones were a pre-authentication denial of service against the alert
channel, kernel addresses published to every local process by two separate
procfs nodes, the TPM-sealed key written through a predictable `/tmp` path, and
the initramfs trusting any vfat filesystem — a USB stick — as the machine's own
EFI partition.

Two of them are worth repeating here, because they are the reason the
"unimplemented security control" clause above exists: the fingerprint
confirmation path existed, compiled, was documented, and had no caller
anywhere in the app; and `daemon/src/exec.rs` is not declared in `main.rs`, so
`/exec` is not a command the daemon answers at all.
