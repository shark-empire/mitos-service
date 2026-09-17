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
other app can fake. Only this one - the rulebook and risk classification
- exists as real code right now. The other three don't exist in this
codebase yet, so:

- **No enforcement.** `CHECK` answers a question; it never blocks a
  syscall. That's mitos-kernel's job once it exists.
- **No interactive prompt.** An `ASK` response means exactly that:
  nothing's stored, and this daemon has no way to go get a decision
  itself. `mitosvc-ctl grant` is today's stand-in for what a real
  password-verified prompt would eventually do.
- **No password handling anywhere in this codebase** - matching the
  design's own rule that only mitos-session may check one. There's
  simply no code path here that could get that wrong.

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

No dependencies beyond the standard library (see `Cargo.toml`) - nothing
here needs a raw syscall directly, unlike mitos-services.

Can also run as an ordinary mitos-services-supervised service - see
`INTEGRATION.md`.

## mitosvc-ctl

```
mitosvc-ctl check <sha256> <capability>                          # ALLOW / DENY / ASK <risk>
mitosvc-ctl grant <sha256> <capability> <allow|deny> <scope>      # scope: once/session/always
mitosvc-ctl revoke <sha256> <capability>                           # remove a decision
mitosvc-ctl list                                                    # every current grant
mitosvc-ctl ping                                                     # liveness check
```

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
- `src/bin/mitosvc-ctl.rs` - the CLI client for that socket
- `src/logging.rs` - same shape as mitos-services' own (duplicated
  rather than shared, matching that project's own established reasoning
  for why - see its `README.md`)

## What's deliberately not here yet

Flagged rather than silently missing - this entire list exists because
mitos-kernel, mitos-session, and mitos-gui don't exist yet, not because
of anything left half-finished within this repo itself:

- **Enforcement** - nothing here can actually block a syscall.
- **An interactive prompt flow** - `ASK` is a dead end without
  `mitosvc-ctl grant` today; no password verification, no compositor-
  drawn prompt.
- **Per-app identity beyond the binary hash** - a legitimate update to
  an app resets every grant it had (the hash changed), with no smoother
  path (e.g. a signing-key-based identity that survives updates) built
  yet. Worth having eventually; not guessed at here.
- **Rate limiting / audit log rotation** - every `CHECK`/`GRANT`/
  `REVOKE` is logged (see `logging.rs`) but never rotated or capped -
  fine for now, worth revisiting once this runs somewhere for real.

## License

Dual-licensed under MIT or Apache-2.0, matching the rest of MITOS.
