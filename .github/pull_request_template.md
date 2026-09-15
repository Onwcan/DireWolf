## What and why

<!-- One paragraph. What changes, and what forced the change. -->

## Checks

- [ ] `make check` passes locally
- [ ] New behaviour has a test that fails without the change

## Boundary questions

Answer only the ones that apply; delete the rest.

- [ ] **This touches `dwkd-authority` or `dwkd-broker`.** It has a reviewer
      other than the author, and it does not move a decision into the broker or
      a parser into authority.
- [ ] **This adds a DWKP operation.** Attached is a written argument for why it
      is not a second path from cognition to effect, reviewed by someone other
      than the author, and a statement of whether it is an authority primitive
      or a runtime-shaped convenience (ADR-0029).
- [ ] **This adds a dependency.** The purpose is stated below, and if it lands
      in `dwkd-authority`'s dependency closure there is a note on ADR-0019.
- [ ] **This changes an interface between the planes.** There is an ADR.
- [ ] **This changes an accepted decision.** There is a *new* ADR that
      supersedes or amends the old one. Accepted ADRs are never rewritten.
- [ ] **This adds `unsafe` Rust.** Each block carries its safety invariant, and
      the crate-level exception is recorded in an ADR.

## Anything a reviewer should look at first

<!-- Where the risk is. "Nothing" is a valid answer for a typo fix. -->
