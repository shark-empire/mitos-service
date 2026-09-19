# Changelog

This project is brand new - a first version, built alongside (and
integrated with, via `apps.rs::authorize()`) mitos-services, but as its
own independent repository. Like the rest of MITOS's newer components,
it's been checked against a compiler and its own unit tests, but never
run for real: no real rulebook file has been written by a real prompt
flow, and the control socket has only ever been exercised by
`mitosvc-ctl` in the same development session that wrote it. Treat it
accordingly.

## [0.1.0] - Unreleased

### Added
- Initial implementation: the rulebook (`rulebook.rs` - `Once`/
  `Session`/`Always`-scoped grants, keyed by binary SHA-256 rather than
  the ephemeral per-launch app id mitos-services' `apps.rs` generates,
  with `Always` grants persisted to `/var/lib/mitos-service/permissions.db`),
  risk classification (`risk.rs` - an unrecognized capability defaults
  to `Dangerous` rather than being silently permissive), and the control
  socket (`ipc.rs` - `CHECK`/`GRANT`/`REVOKE`/`LIST`/`PING`) plus its CLI
  client (`mitosvc-ctl`).
- No enforcement, no interactive prompt flow, no password handling -
  deliberately, since mitos-kernel/mitos-session/mitos-gui don't exist
  yet to build those against. See `README.md`'s "what this is and
  isn't" section.
- Real elevation for dangerous grants: `GRANT` on a `dangerous`/
  `critical` capability now calls mitos-session's real
  `RequestElevation` (`session_client.rs`, mirroring its wire protocol
  in `session_wire.rs`) and blocks until the target uid's session
  answers, instead of applying immediately on the strength of whoever
  could reach the control socket. `GRANT`'s wire format gained a
  required `<uid>` parameter as part of this (a breaking change to the
  command, made now rather than after any real deployment exists to
  break). Added `LIST-RAW` alongside the existing `LIST`, for a
  programmatic caller (mitos-settings) to parse without depending on
  `LIST`'s human-formatted output.
