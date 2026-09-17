# Contributing

## Before you start

This process holds the permission rulebook - a bug here doesn't crash
anything else, but a wrong `ALLOW` is exactly the kind of mistake the
whole point of this project is to avoid. A few habits worth keeping up:

- **Prefer `Result` over panicking**, same as every other MITOS
  component - a `CHECK` that panics mid-request is worse than one that
  returns a clear error.
- **A `Once`-scoped grant must be consumed on lookup, no exceptions.**
  This is the one invariant `rulebook.rs`'s tests exist specifically to
  guard (`once_scoped_grant_is_consumed_after_one_lookup`) - if you're
  touching `lookup`, run that test, not just the suite as a whole.
- **New parsing/lookup logic gets tests.** See the `#[cfg(test)]`
  modules in `rulebook.rs`/`risk.rs` for the existing pattern -
  especially anything touching scope handling (`Once` vs `Session` vs
  `Always`) or persistence (`load`/`persist` round-tripping correctly).
- **An unrecognized capability defaults to `Dangerous`, not `Low`.**
  If you're adding to `risk.rs`'s table, that's the one direction worth
  double-checking your own change against: is this genuinely safer than
  the earlier list, or does it just look shorter?

## Workflow

1. `cargo fmt --all` before committing (or let
   `.github/workflows/auto-format.yml` do it for you on push to `main` -
   see mitos-services' own copy of this workflow, which this repo's is
   copied from).
2. `cargo clippy --all-targets -- -D warnings` and `cargo test` should
   both be clean - CI (`.github/workflows/ci.yml`) runs both, along with
   `cargo check` and a `fmt --check`.
3. This daemon has never been run for real (see `CHANGELOG.md`) - if
   you're touching `ipc.rs` or `rulebook.rs`'s persistence, actually run
   `mitos-service` and drive it with `mitosvc-ctl` before considering a
   change done. Unit tests cover the pure logic; they don't cover a real
   socket or a real file on disk.

## Where things live

See the README's "Layout" section for a one-line-per-file map, and
`INTEGRATION.md` for how another MITOS project (today: mitos-services'
`apps.rs`) is meant to call into this one.
