<!-- SPDX-License-Identifier: Apache-2.0 -->

# Translations

The source of this project is English — every comment, every identifier, every
string as it appears in the file. What the *owner* reads can also exist in
their own language, and that copy lives here instead of in the middle of a
function.

## How it works

A call site reads:

```rust
crate::lang::t("face.head.owner_alone", "👤 The owner, alone")
```

The key finds the translation in `<tag>.toml`; the second argument **is** the
English text. Two things follow from that shape, and both are the point:

- You can read the code and know exactly what it prints, without opening a
  catalogue.
- A missing, partial or damaged catalogue costs nothing. Every lookup falls
  back to the English that is already there, so this layer can never leave the
  daemon mute or printing a key name at somebody. A translation system that can
  break the program is a worse bug than the untranslated text it replaced.

The catalogue is chosen by `[persona] language` in `config.toml`. A regional
tag falls back to its language, so `es-CL` finds `es.toml` and nobody has to
ship a file per region.

Files are looked for in `/usr/share/sysentinel/lang/` first, then `lang/` and
`../lang/` relative to the working directory, so a git checkout behaves like an
install without setting anything.

## Adding a language

Copy `es.toml` to `<tag>.toml`, translate the values, and leave out any key you
are unsure about — it falls back to English on its own. A partial translation
is a perfectly good translation here.

The format is a flat TOML table, `"key" = "value"`, and nothing else. A file
that does not parse is refused with a warning rather than half-applied, so a
typo shows up in the log instead of as three sentences in the wrong language.

## What is not translated, and why

- **Log lines and error chains.** They are read in `journalctl` at three in the
  morning and pasted into bug reports. One language is worth more there than a
  familiar one.
- **The persona's own voice.** The model already answers in
  `[persona] language`; this catalogue is the fixed text around it.
- **Input vocabulary.** The words the daemon *accepts* — `sí`, `confirmar`,
  `sácalo` — are not translations of anything. They are what a person actually
  types at their own machine, and they live in the matchers in `bot.rs`.

## Documentation

`lang/es/` holds the Spanish versions of the guides. The English ones at the
repository root are the originals; these are kept in step by hand.
