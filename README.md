# mitos-service

The permission policy daemon the [MITOS permissions design][doc]
describes as "the brain of the permission system": it owns the
permanent rulebook, classifies how dangerous a requested capability is,
and answers the question "has this app already been told yes or no for
this?" - `ALLOW`, `DENY`, or `ASK` when nothing's on file yet.

[doc]: ../mitos-services/APPS.md

## What this is (today) and isn't (yet)

The full design ties together four components: mitos-kernel intercepts
a sensitive syscall and reports it; mitos-service looks up or asks for a
decision; mitos-session verifies a password; mitos-gui draws a prompt no
other app can fake. Two of those four are real from here: this daemon
(rulebook + risk classification), and a real, working call into
mitos-session's own elevation prompt (`session_client.rs`) for anything
`GRANT`ed at `dangerous`/`critical` risk. mitos-kernel and mitos-gui
still don't exist in any codebase this project can see, so:

- **No enforcement.** `CHECK` answers a question; it never blocks a
  syscall. That's mitos-kernel's job once it exists.
- **`ASK` is still a dead end on its own.** It means exactly "nothing's
  stored"; this daemon has no way to turn an app's live `CHECK` into a
  prompt by itself. `mitosvc-ctl grant` (or any other client of `GRANT`,
  e.g. mitos-settings) remains today's only way to turn an `ASK` into a
  stored decision.
- **`GRANT` on anything dangerous is real, not administrative
  rubber-stamping.** It blocks on an actual password prompt, drawn by
  mitos-gui, checked by mitos-session over real PAM, before this
  daemon records anything - see `session_client.rs` and
  `INTEGRATION.md`'s `GRANT` section for exactly how and what its three
  distinct response shapes (`granted` / `denied: ...` / `error: ...`)
  mean.

See `src/main.rs`'s module doc for the same thing in more detail, and
`APPS.md` (in mitos-services) for the seam that already exists on the
other side: `apps.rs::authorize()` is written to call this daemon once
it's reachable.

## Building and running

```
cargo build --release
sudo ./target/release/mitos-service &
./target/release/mitosvc-ctl ping
```

Almost no dependencies beyond the standard library (see `Cargo.toml`) -
the one exception is `serde`+`bincode`, needed only to speak
mitos-session's real wire protocol for elevation (see `Cargo.toml`'s
comment on `session_wire` for why). Nothing here needs a raw syscall
directly, unlike mitos-services.

Can also run as an ordinary mitos-services-supervised service - see
`INTEGRATION.md`.

## mitosvc-ctl

```
mitosvc-ctl check <sha256> <capability>                                # ALLOW / DENY / ASK <risk>
mitosvc-ctl grant <sha256> <capability> <allow|deny> <scope> <uid>     # scope: once/session/always
mitosvc-ctl revoke <sha256> <capability>                                # remove a decision
mitosvc-ctl list                                                        # every current grant, human-readable
mitosvc-ctl list-raw                                                    # same, one grant per line, pipe-delimited
mitosvc-ctl ping                                                        # liveness check
```

`<uid>` is whose mitos-session session gets asked to verify, if
`<capability>` turns out to be `dangerous`/`critical` - see
`INTEGRATION.md`'s `GRANT` section. It's required either way (even for
a `low`/`moderate` grant that won't end up using it), so every grant is
attributable to whoever asked for it, not just the ones that needed a
password.

Talks to `/run/mitos-service/control.sock` (mode `0600` - root only,
same reasoning as mitos-services' own control socket) over the same
plain newline-delimited text protocol every other MITOS control socket
uses - see `src/ipc.rs`'s module doc for the full command reference.

## Identity: hash, not app id

Grants are keyed by the **SHA-256 of the binary**, not the app id
mitos-services' `apps.rs` generates per launch. An app id identifies one
running instance; the hash is what's stable across every future launch
of the same binary - matching the permissions design's own description
of an "Always allow" grant: tied to the binary hash, reset if the
executable ever changes. See `rulebook.rs`'s module doc.

## Layout

- `src/main.rs` - entry point: loads the rulebook, starts the control
  socket, then just stays alive (see its own doc comment for why there's
  no event loop here the way mitos-services has one)
- `src/rulebook.rs` - the permission database: grants, lookup,
  `Once`/`Session`/`Always` scoping, persistence for `Always` grants
- `src/risk.rs` - capability name -> risk level classification
- `src/ipc.rs` - the control socket `mitosvc-ctl` talks to
- `src/session_client.rs` - calls mitos-session's real elevation
  endpoint for a dangerous `GRANT`
- `src/session_wire.rs` - hand-mirrored copy of the slice of
  mitos-session's wire protocol `session_client.rs` needs (see its own
  doc comment for why it's a mirror rather than a dependency on the
  `mitos-session` crate)
- `src/bin/mitosvc-ctl.rs` - the CLI client for that socket
- `src/logging.rs` - same shape as mitos-services' own (duplicated
  rather than shared, matching that project's own established reasoning
  for why - see its `README.md`)

## What's deliberately not here yet

Flagged rather than silently missing - most of this list exists because
mitos-kernel and mitos-gui don't exist yet, not because of anything
left half-finished within this repo itself:

- **Enforcement** - nothing here can actually block a syscall. Needs
  mitos-kernel.
- **A live, in-the-moment prompt triggered by an app's own request** -
  `GRANT` now genuinely does verify a password when it needs to, but
  only when *something already connected to this socket* calls it.
  Nothing here turns an app's `CHECK` coming back `ASK` into a `GRANT`
  automatically; that loop (needing mitos-kernel or mitos-services'
  `apps.rs`, and mitos-gui to draw the prompt mitos-session asks for)
  isn't closed. See `INTEGRATION.md`'s future-seams section.
- **Per-app identity beyond the binary hash** - a legitimate update to
  an app resets every grant it had (the hash changed), with no smoother
  path (e.g. a signing-key-based identity that survives updates) built
  yet. Worth having eventually; not guessed at here.
- **Rate limiting / audit log rotation** - every `CHECK`/`GRANT`/
  `REVOKE` is logged (see `logging.rs`) but never rotated or capped -
  fine for now, worth revisiting once this runs somewhere for real.
- **A configurable mitos-session socket path** - `session_client.rs`
  hardcodes `/run/mitos-session/session.sock`, matching that project's
  own default. A real deployment that relocates it would need a
  matching code change here, not a config option.

## License

Dual-licensed under MIT or Apache-2.0, matching the rest of MITOS.
