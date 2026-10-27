@README.md

## Domain language

Develop using Domain-Driven Design (Eric Evans), strategic ideas first.

- **Ubiquitous language.** [`design/glossary.md`](design/glossary.md) names things, in docs and code alike: one name per concept, defined once.
  A new concept enters the glossary before the code.
- **Bounded contexts**, each with its own model and crate; don't reach into another's internals.
- **Tactical patterns where they earn their place:**
    - value objects as newtypes that are valid on construction;
    - entities by GUID;

Keep domain logic pure, with I/O at the edges.

## Rust conventions

- Edition 2024; toolchain pinned in `rust-toolchain.toml`; one Cargo workspace with dependency versions held in
  `[workspace.dependencies]`.
- Formatting follows `rustfmt.toml`: max width 140, 4-space indents, no tabs. **Do not run `cargo fmt` before
  committing.**
- Use functional programming (iterators > for loops) where possible.
- Use inline format arguments: `format!("bad split {guid}")`.
- Keep functions short and doing one thing; split long ones into named helpers.
- Libraries return typed errors with `thiserror`; only the binary uses `anyhow`.
- No `unwrap`, `expect` or `panic!` outside tests. A malformed file is an error, never a crash.
- Public items have doc comments. Comments say *why*, not what.
- Output must be deterministic: no `HashMap` iteration order in anything that is written to disk or the wire.

## Specification

The product specification is in @design/iron-vault-specification.md. After writing a piece of code, check the code's function against 
the specification. If there is a conflict, prefer the specification and change the code to confirm.
If you feel that the specification is wrong, STOP and ask the user for direction.

## Workflow

Use the Kanban board to plan, track and review work.

- **Tickets are small and self-contained.** A PR's code (excluding docs and tests) should be under 400 lines and never
  over 1000; past 500, look for a split.
- **Each feature is an Epic.** Its description says what the feature does and why, so context isn't lost across small
  tickets. Parity features name the GnuCash behaviour they match, with citations.
- **Reviews:** re-read the mission and the relevant design docs, then ask:
    - Does this clearly move us toward the mission?
    - Does it fit the design?
    - Could it damage a user's book?
    - What code should be *removed*? The only bug-free code is code never written. Code that is not in the ticket's scope
      comes out, even if useful; argue for it in a new ticket.
- **Commits** follow Conventional Commits (`feat(sql): read scheduled transactions`). Collect dependency changes
  under a "Dependency updates" heading, one line each: `crate: old => new`.
