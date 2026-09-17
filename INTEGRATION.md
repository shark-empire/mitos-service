# Integrating a project with mitos-service

How another MITOS project asks mitos-service for a permission decision,
or records one. See `README.md` for what this daemon does and
doesn't do yet before building against it - in particular, `CHECK`
never blocks anything itself, and there's no real interactive prompt
flow behind `ASK` yet.

## The short version

Connect to `/run/mitos-service/control.sock`, write one line, read one
line (or, for `LIST`, one block of lines) back, disconnect. Same
transport every other MITOS control socket uses.

```
$ printf 'CHECK abc123...def raw_disk\n' | nc -U /run/mitos-service/control.sock
ASK dangerous
```

## Commands

### `CHECK <sha256> <capability>`

The one call an app-launcher or (eventually) mitos-kernel makes before
letting something sensitive happen. `<sha256>` is the exact binary's
hash - mitos-services' `apps.rs` already computes this for every
launched app; see its own doc comment for where. `<capability>` is a
free-form name (see `risk.rs` for the ones this daemon currently
recognizes; an unrecognized one is treated as `dangerous`, not rejected).

- `ALLOW` / `DENY` - a stored decision already exists.
- `ASK <risk>` - nothing's stored. `<risk>` is
  `low`/`moderate`/`dangerous`/`critical` - see `risk.rs`. There is
  **no prompt shown anywhere** as a result of this response; it's
  purely informational until something (today: an administrator, via
  `mitosvc-ctl grant`) records a decision.

### `GRANT <sha256> <capability> <allow|deny> <once|session|always>`

Records a decision. `once` is consumed by the very next `CHECK` for the
same pair (whatever the result); `session` lasts until mitos-service
restarts; `always` is persisted to `rulebook::DEFAULT_PATH` and
survives a restart, until explicitly revoked or the hash changes.

This is the call a real password-verified prompt flow would make once
mitos-session/mitos-gui exist. Until then, it's an administrative
action - nothing currently connecting to this socket makes it on a
user's behalf automatically.

### `REVOKE <sha256> <capability>`

Removes whatever decision (any scope) is on file for the pair.

### `LIST`

Every currently-held grant - `sha256`, `capability`, decision, scope,
and when it was granted (unix seconds), one per line.

### `PING`

Liveness check - replies `PONG`.

## What a caller should and shouldn't assume

- **Do** treat `ALLOW`/`DENY` as authoritative - once stored, `CHECK`
  won't ask again for the same pair (except a `once`-scoped grant,
  which is meant to be asked exactly once more).
- **Do** expect `CHECK` to be fast and non-blocking - it's a rulebook
  lookup, not a network call or a prompt wait.
- **Don't** treat `ASK` as `DENY` unless that's genuinely the right
  fallback for your caller. mitos-services' `apps.rs::authorize()`
  currently does exactly that (fails closed on an explicit `ASK` or
  `DENY`, but fails *open* - allows - if mitos-service isn't reachable
  at all, as a deliberate bootstrapping exception; see that function's
  doc comment for the reasoning) - a different caller with different
  stakes might reasonably choose differently.
- **Don't** assume a `sha256` you haven't independently verified.
  This daemon trusts whatever hash a caller sends it; it doesn't (and
  can't, without mitos-kernel) verify that the hash actually
  corresponds to the process making the underlying request.

## Running mitos-service as a mitos-services-supervised unit

mitos-service doesn't need to be PID 1 or anything special - a plain
`mitos-service.service` unit works, as long as it starts before
anything tries to `CHECK` against it:

```ini
[Service]
ExecStart=/usr/bin/mitos-service
Restart=always
User=mitos-service
Group=mitos-service
NoNewPrivileges=true
```

(`User=`/`Group=` here assumes a dedicated `mitos-service` system
account with write access to `/var/lib/mitos-service` and
`/run/mitos-service` - this repo doesn't create one for you.)

## Future integration seams

- **mitos-kernel**: expected to call `CHECK` (or a lower-latency
  variant of it) from whatever intercepts a sensitive syscall, and to
  be told about `Always`/`Session` grants so it can enforce them
  itself without round-tripping to this daemon every time - not
  implemented; `rulebook::list()` is the natural source for that today.
- **mitos-session**: expected to be the one mitos-service asks to
  verify a password before recording an `Always`/`Session` grant from
  a real (non-administrative) prompt flow. No code here calls out to
  it yet - see `README.md`'s "what this isn't yet" section.
- **mitos-gui**: expected to draw the actual prompt a user sees. Same
  status - no integration exists yet.
