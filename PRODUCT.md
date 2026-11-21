# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- **Primary: platform engineers and SREs** who author or review a
  `CiliumNetworkPolicy`/`CiliumClusterwideNetworkPolicy` before it merges.
  They are fluent in Kubernetes and Cilium. They want to know, before merge,
  which real flows a policy would break or newly allow. On day 2 they use
  `blame` to find out which live policy dropped a flow.
- **Secondary: application developers** writing a CNP for their own
  namespace. They know Cilium semantics less well. The UI must stay usable
  for them, but it is designed for the platform user first.

## Product Purpose

GuardBee is a Cilium policy pre-flight simulator. It judges a candidate
policy against real recent Hubble flows from the user's cluster, twice:
once against the live baseline and once against baseline plus candidate. It
reports every flow as `NEWLY_DROPPED`, `NEWLY_ALLOWED` or `UNCHANGED`.
Success means a policy regression shows up as a verdict before merge, not
as a page afterward.

## Positioning

- Verdicts come from Cilium's own `pkg/policy` engine, embedded and pinned
  to a specific Cilium version. They are not a reimplementation of Cilium's
  semantics.
- It judges real traffic from the user's own cluster, not synthetic test
  cases.
- It runs locally: one binary (Go CLI plus an embedded web UI), the user's
  kubeconfig and read-only RBAC. There is no in-cluster agent and no
  persisted flow store.

## Operating Context

- **CLI:** `policies`, `flows`, `blame`, `verdict`, `ui`, `compat` and
  `version`. Flag names follow hubble CLI conventions (`-n`, `-A`, `-f`,
  `--last`). `verdict` also runs in CI (`--fail-on-allowed`, multi-file and
  stdin input).
- **Local web UI** (`guardbee ui`): Flows, Policies, Policy Editor (graph
  based, with presets) and Verdict tabs, plus a Compatibility modal. It
  calls the same functions as the CLI, so the two can never disagree on a
  verdict.
- **Public site** (GitHub Pages, `docs/`): a landing page and a guide
  (install, build, run, commands, how it works, lab, TCP probes).
- **Self-paced Lab** (`mise run lab-up`): a disposable cluster with a
  postgres scenario that `examples/` candidates are built to match.

## Capabilities and Constraints

- Read-only against the cluster by default. The one exception is the
  opt-in `--enable-probes`: bounded TCP/UDP connectivity tests that run as
  restricted ephemeral containers, using images from a server-side catalog
  only.
- **Honest uncertainty is part of the product.** L7/FQDN flows, port-0
  flows, `fromNodes`/`toNodes` baselines, unattributed flows and incomplete
  probe captures are shown as `NOT_SIMULATED`, "not attributed", skipped or
  withheld. They are never guessed. These are the documented v1
  simplifications (see `CLAUDE.md`/`README.md`).
- `--last` is a ceiling, not a guarantee. Hubble's ring buffer is shared
  across the whole cluster.
- Engine/cluster version skew is shown as a warning (CLI stderr, UI
  banner). Constructs deprecated or removed as of the pinned version are
  rejected through the `compat` gate table.
- Desktop and laptop browsers only. Phones are out of support scope
  (decided 2026-11-21); don't spend design or test effort on phone widths.

## Brand Commitments

- Name **GuardBee**, tagline **"Ship the policy. Not the outage."**
- Existing assets: `docs/branding/guardbee-logo.svg`/`.png` and
  `guardbee-mascot.png`.
- Existing voice on the landing page: dry and slightly wry ("true story.
  sort of."), technically exact, no hype.

## Evidence on Hand

- The self-paced Lab scenario is the demo and the evidence: the postgres
  scenario, `examples/postgres-*.yaml` and `examples/ccnp-postgres-*.yaml`,
  and the `docs/images/lab-*.png` screenshots generated from it.
- The "how it works" guide describes two real regressions verdict caught.
- There are no customers, testimonials, benchmarks or adoption numbers.
  Future work must not invent any.

## Product Principles

1. **Cilium's verdict, not ours.** Every judgment comes from the embedded
   engine. The UI shows it and never adds its own interpretation.
2. **Say what wasn't simulated.** Gaps and withheld conclusions get as much
   visibility as the verdicts themselves.
3. **Platform engineer first, app developer welcome.** Use dense, exact
   Cilium/hubble terminology, but give a less fluent author a way into it.
4. **One engine, many faces.** The CLI, UI and CI are presentations of the
   same functions and never diverge in logic.
5. **Local and read-only by default.** Anything that touches the cluster is
   explicit, opt-in and bounded.
