# Integrating a project with mitos-service

How another MITOS project asks mitos-service for a permission decision,
or records one. See `README.md` for what this daemon does and
doesn't do yet before building against it - in particular, `CHECK`
never blocks anything itself, and an `ASK` reply is still a dead end on
its own (nothing here turns an app's live request into a prompt) - but
`GRANT` on a dangerous capability is now a real, password-verified
elevation, not an administrative rubber stamp.

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

### `GRANT <sha256> <capability> <allow|deny> <once|session|always> <uid>`

Records a decision on `<uid>`'s behalf. `once` is consumed by the very
next `CHECK` for the same pair (whatever the result); `session` lasts
until mitos-service restarts; `always` is persisted to
`rulebook::DEFAULT_PATH` and survives a restart, until explicitly
revoked or the hash changes.

For a `dangerous`/`critical` capability, this now genuinely is the real
password-verified prompt flow the design describes -
`session_client::request_elevation` asks `<uid>`'s own mitos-session
session to verify their password before anything is recorded, and this
call blocks until they answer (or decline, or it times out). For
`low`/`moderate`, it still applies immediately with no verification,
same as before this daemon could reach mitos-session at all.

Three shapes of response, not just success/failure - a caller should
handle all three distinctly rather than treating "not `granted`" as one
undifferentiated failure:
- `granted` - recorded.
- `denied: ...` - elevation ran and came back negative (wrong password
  repeatedly, or declined). The rulebook is unchanged.
- `error: ...` - something failed before a decision could even be
  reached (bad arguments, mitos-service can't reach mitos-session,
  `<uid>` has no active mitos-session session). Also leaves the
  rulebook unchanged.

### `REVOKE <sha256> <capability>`

Removes whatever decision (any scope) is on file for the pair.

### `LIST`

Every currently-held grant - `sha256`, `capability`, decision, scope,
and when it was granted (unix seconds), formatted for a human reading
`mitosvc-ctl list`'s own output.

### `LIST-RAW`

The same data, `sha256|capability|decision|scope|granted_at` one grant
per line, no header or trailing summary - for a caller that wants to
parse it (e.g. mitos-settings) instead of displaying `LIST`'s output
verbatim.

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
  implemented; `rulebook::list()` (or `LIST-RAW` over the socket) is
  the natural source for that today.
- **mitos-session**: done - `session_client.rs` calls
  `RequestElevation` for `dangerous`/`critical` `GRANT`s, on the
  account whose uid the caller passes. mitos-session's own
  authorization accepts that request from this daemon specifically
  (root, or its configured `[elevation].service_user`, which should be
  set to whatever account mitos-service runs as - see this file's
  systemd unit example above) - see mitos-session's own
  `docs/security.md` for that reasoning in full.
- **mitos-gui**: draws the actual prompt a user sees once mitos-session
  asks it to. Not this repository's concern at all - mitos-service
  never talks to mitos-gui directly, only to mitos-session.
- **What still doesn't exist anywhere**: a way for an app's own
  *live*, in-the-moment permission request to reach this daemon and
  become a `GRANT` call automatically. `GRANT` today is always
  initiated by whatever's on the other end of the control socket
  (`mitosvc-ctl grant`, or a client like mitos-settings) - not by this
  daemon reacting to an app's `CHECK` coming back `ASK`. Closing that
  loop is mitos-services' `apps.rs` (or mitos-kernel's) job, not
  something this daemon does on its own.
