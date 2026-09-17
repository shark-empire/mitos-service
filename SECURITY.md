# Security Policy

mitos-service holds the permission rulebook and is meant to run
privileged enough to be trusted by whatever eventually enforces its
decisions. This project is pre-1.0 and has never been run for real (see
`CHANGELOG.md`) - please report anything that looks like a security
issue rather than opening a public issue for it first.

## Reporting a vulnerability

Email <security@example.invalid> with a description of the issue and,
if possible, steps to reproduce it. (Replace this address with a real
contact before publishing this project - same placeholder mitos-services'
own `SECURITY.md` uses.)

Please don't open a public GitHub issue for a suspected vulnerability
until there's been a chance to assess and, where needed, fix it first.

## Scope

Anything that lets an unprivileged local process read, forge, or
tamper with a grant - directly (writing to `permissions.db`, which
should be root-owned and not group/world-writable once a real install
sets it up) or via the control socket (`ipc.rs`, restricted to `0600`,
same reasoning as mitos-services' own); anything that lets a `GRANT`/
`REVOKE` be attributed to the wrong binary hash; a `Once`-scoped grant
being usable more than once, or a `Session`-scoped one surviving a
restart (see `rulebook.rs`'s tests for the invariants this is supposed
to already guarantee - a failure there is a bug).

Known, already-documented limitations that are *not* new reports:
this daemon does no enforcement and has no real interactive prompt
flow, because mitos-kernel/mitos-session/mitos-gui don't exist yet -
see `README.md`. It also doesn't (and can't, without mitos-kernel)
independently verify that a `sha256` a caller sends actually
corresponds to the process making the underlying request - that
verification has to happen upstream, in whatever eventually calls
`CHECK` for real.

## Supported versions

Pre-1.0: only the latest commit on the default branch is supported.
There's no backport policy yet.
