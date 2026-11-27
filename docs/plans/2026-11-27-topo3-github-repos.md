---
canonical: decisions:docs/plans/2026-11-27-topo3-github-repos.md
phases: [1]
status: done
branch: chore/t25-topo3
repos: [authelia-oidc-operator]
---
# Move the GitHub app and operator repos to greentopo 3.0.0

Pointer to the canonical plan in the decisions repository (programme
topo-spotter-rename, ticket t25). This repository is Phase 1: the CI pin
moves to greentopo 3.0.0 with the re-vendored pack and the regenerated hook
script.

## Code review
- authelia-oidc-operator: none — CI pin, re-vendored pack, regenerated hook and gate block, one comment, no code

## Implementation review
- implementation-review (opus): approve-with-changes (48k, 31 s): Outcome lacked source commit and full pack sha; fixed in the canonical plan.
