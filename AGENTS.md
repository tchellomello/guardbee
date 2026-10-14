# GuardBee

Cilium policy pre-flight simulator. Answers one question before a
`CiliumNetworkPolicy`/`CiliumClusterwideNetworkPolicy` merges: **which real
flows on this cluster would it break or newly allow?**

Go CLI + embedded local web UI. No in-cluster agent, no persisted flow store.

This file covers code-level facts: architecture, known engine gotchas, build/
test, and house style. If a `AGENTS.local.md` exists next to this file
(gitignored — personal notes, not published), read that too.

## What this actually is

- `guardbee policies [-n <ns>|-A]` — lists live CNPs (namespaced) + CCNPs
  (cluster-wide) via the generated Cilium clientset. Pure read, proves RBAC.
- `guardbee flows [-n <ns>|-A] [--last N] [-f]` — port-forwards to
  `hubble-relay` (`cilium-system` namespace) and streams real flows via
  Hubble's `Observer.GetFlows` gRPC API.
- `guardbee verdict [-n <ns>|-A] [--last N] [-f] <candidate.yaml>` — the
  actual engine. Judges real recent flows twice (baseline live policy vs.
  baseline+candidate) using **Cilium's own `pkg/policy` engine** — not a
  reimplementation — and prints `NEWLY_DROPPED`/`NEWLY_ALLOWED`/`UNCHANGED`.
- `guardbee ui [--addr host:port]` — milestone 1 web UI: a local HTTP server
  exposing the exact same `computeVerdict`/`fetchFlows` functions the CLI
  calls, over JSON, for a React/TS frontend. No parallel implementation —
  UI and CLI can't disagree on a verdict for the same input, only present it
  differently.

All four are read-only against the cluster, by design, in v1.

## Architecture principle that overrides convenience

**The whole trust model rests on embedding Cilium's actual `pkg/policy`
engine** (`ResolvePolicy`/`DistillPolicy`/`EndpointPolicy.Lookup`, plus the
generated `.Parse()` conversions for CNP/CCNP), pinned to the cluster's exact
Cilium version (`go.mod`: `github.com/cilium/cilium v1.20.2`). A verdict from
this tool must be a verdict from Cilium's own code, never this project's
guess at Cilium's semantics.

Consequences that follow directly from this, non-negotiably:
- Never hand-roll policy-matching logic that duplicates what `pkg/policy`
  already does — call the real engine, even when it's less convenient.
- The internal Go packages this embeds (`pkg/policy`, `pkg/identity`, etc.)
  carry **no stability guarantee** across Cilium versions — they're agent
  implementation details, not a public API. Real bugs have already come
  from exactly this (see "Gotchas already hit" below). Any Cilium version
  bump needs the full `mise run check` pass plus live re-validation against
  the real cluster, not just `go get`.
- `go.mod`'s Cilium version must track the cluster's actual running version.
  A startup check that warns on drift is an open follow-up, not yet built —
  don't assume it exists.

### Gotchas already hit (don't rediscover these)

- **Dual selector-cache gotcha.** `policy.Repository` has *two separate*
  selector caches — `GetSelectorCache()` (peer matching: `FromEndpoints`/
  `ToEndpoints` against remote identities) and an internal
  `subjectSelectorCache` (matching a rule's own `EndpointSelector` against
  the identity being resolved). Both must be told about identities
  independently. Missing the second call doesn't error — it silently makes
  every rule's `EndpointSelector` fail to match anything, so the rule has
  zero effect and `DistillPolicy` falls back to
  default-deny-with-reserved-identity-exceptions, which *looks* like a
  working result but is wrong.
- **`Get`-vs-default-allow bug.** A naive `epp.Get(key)` check treats "no
  explicit MapState entry" as always-deny. Wrong for the overwhelmingly
  common case — a workload with *no* CNP at all is fully default-allow, not
  default-deny. Fixed via `isAllowed()` falling back to
  `epp.SelectorPolicy.IngressPolicyEnabled`.
- **Identity minimum.** Hand-picked numeric identities must be
  `>= identity.MinimalNumericIdentity` (256) — lower values are reserved for
  Cilium's own special identities.
- **Hubble buffer semantics.** `GetFlows` samples a shared, cluster-wide
  bounded ring buffer, not a per-namespace one — counts drift run-to-run;
  this is what the `--last`-is-a-ceiling behavior above is actually about.

## Known v1 simplifications (intentional, documented in code — don't "fix" silently)

- Only **ingress-at-destination** is evaluated, not full bidirectional
  ingress+egress correctness.
- L7/FQDN-decided flows are `NOT_SIMULATED`, never guessed — those verdicts
  live in Envoy/the DNS proxy, not the policy map this engine computes.
- A flow's identities must already be real and currently allocated (resolved
  directly off Hubble's `Endpoint.Identity`). Candidate labels with no
  matching live pod are simply never exercised — this tool never invents a
  fake identity.
- Reply packets of established connections are skipped — connection
  tracking always allows those regardless of CNP ingress rules.
- `--last` is a **ceiling, not a guarantee**: Hubble relay's flow buffer is
  a small, fixed-size ring for the *whole cluster*, not scoped to one
  namespace. Getting fewer flows than requested is expected, not a bug.
  `--follow`/`-f` is the real lever for more volume over time, not raising
  `--last`.

## Repo layout

```
main.go           entry point, subcommand dispatch, --help text
globals.go        binName (single source of truth for the binary's name — see below)
kube.go           shared flags (--namespace/-n, --all-namespaces/-A, --kubeconfig), clientset wiring
policies.go       `policies` subcommand
flows.go          `flows` subcommand (hubble-relay port-forward + GetFlows)
verdict.go        `verdict` subcommand — the core engine (690 lines, read this first for engine changes)
templates.go      Policy Editor "preset" templates, loaded from templates/*.yaml, not hardcoded data
ui.go             `ui` subcommand — local HTTP/JSON API over the same verdict/flows functions
embed.go          go:embed of ui/dist (Argo CD's own UI packaging pattern)
colors.go         ANSI color helpers (NO_COLOR-aware, terminal-detecting)
kubernetes/rbac.yaml  read-only ServiceAccount/ClusterRole for the CLI's own access, validated live
templates/        generic/ingress/egress CiliumNetworkPolicy YAML presets (real, standalone CNPs)
examples/         ready-to-run candidate policies matching the self-paced Lab's scenario, plus generic patterns
ui/               React + TypeScript + Vite + Tailwind + @xyflow/react frontend (milestone 1 web UI)
```

### Renaming the binary

The name (`guardbee`) lives in **exactly one place**: `binName` in
`globals.go`. `mise.toml`'s build/clean tasks and `scripts/gen-completions.sh`
extract it via `sed`. To rename: change `binName`, then
`mise run build && mise run completions`. Nothing else needs touching except
`.gitignore` (lists prior names literally: `cilium-policy-simulator`,
`cilium-network-editor-live`, `guardbee`).

This project has been renamed before (most recently to **GuardBee**) — the
`.gitignore` entries above are the trace of that. If you're working from a
fork or clone where that history matters, check `AGENTS.local.md` or the
git log rather than assuming the current name is the first one.

## Build & test

Preferred, via [mise](https://mise.jdx.dev) (pins exact Go/Node toolchains):

```
mise run build     # npm run build in ui/, then go build -o guardbee .
mise run check     # build + go vet + go test, in that order
mise run test      # engine-spike + verdict-engine regression tests only
mise run clean
mise run ui-dev     # frontend dev server, proxies /api to a separately-running "guardbee ui" on :4747
mise run completions  # regenerate shell completions after a rename or flag/subcommand change
```

`mise run build` **always rebuilds the frontend first** — the Go binary
embeds whatever's currently in `ui/dist` via `go:embed`, so a stale
`ui/dist` would silently ship an outdated UI. Node is deliberately *not*
pinned via mise (no NixOS prebuilt → triggers a 20-60min from-source build);
on NixOS pin Node through the system's own Nix config instead.

Go tests follow Cilium's own testing pattern for exercising the policy
engine standalone (`engine_spike_test.go` mirrors Cilium's
`distillery_test.go` approach — no live agent, no datapath, no cluster
connection needed to run `go test ./...`). `verdict_test.go` holds the
regression suite (e.g. `TestVerdictEngineNewlyDroppedOnDefaultDenyFlip`) —
anything touching `pkg/policy` usage in `verdict.go` should have a
regression test here before being trusted.

## Running against a real cluster

Needs a kubeconfig with read access — either the user's own, or the scoped
`guardbee` ServiceAccount (`kubernetes/rbac.yaml`), validated live against
the actual cluster (not admin credentials — no RBAC gaps found). RBAC is a
ClusterRole (get/list/watch on CNP/CCNP/CiliumIdentity/CiliumEndpoint/
namespaces) plus a `cilium-system`-scoped Role (pods get/list +
pods/portforward create — required because `kubectl port-forward
svc/hubble-relay` resolves to a backing pod client-side, so RBAC can't be
scoped tighter than the Service's selector). Hubble relay itself listens on
containerPort 4245 in `cilium-system`. Give the ServiceAccount its own
namespace rather than reusing `default` — it's a credential/identity, not a
disposable workload. **Never commit a kubeconfig holding a live SA bearer
token** (one was generated and briefly left around during RBAC smoke
testing — delete it after use, don't let it linger as a tracked file).

```
export KUBECONFIG=/path/to/kubeconfig
./guardbee verdict -n myapp --last 50 your-candidate.yaml
```

`-n`/`--namespace` is always correct for a CNP candidate (can only ever
affect its own namespace). For a CCNP candidate, use `--all-namespaces`/`-A`
instead — it can span multiple namespaces and a namespace filter could miss
a real regression elsewhere in its blast radius. Flag naming deliberately
follows [hubble CLI](https://github.com/cilium/cilium/tree/main/hubble)'s own
conventions (`-n`, `-A`, `-f`, `--last`) everywhere this tool overlaps with
it.

For a first smoke test without a cluster of your own, spin up the
self-paced Lab (`mise run lab-up` — see `docs/guide/lab.md`):
`examples/postgres-*.yaml` and `examples/ccnp-postgres-*.yaml` are built
to match its scenario exactly. The rest of `examples/*.yaml` are generic
patterns (deny-all, egress-only) demonstrating real Cilium policy
mistakes, not tied to any one cluster; point `verdict` at your own
namespace/candidate for anything beyond what's there.

## House style in this codebase (match it, don't "improve" it)

- Comments explain **why**, especially non-obvious Cilium-internal-API
  subtleties, version-coupling caveats, or a design decision's rationale —
  not what the code visibly does. Follow this density; don't strip comments
  down to the project's or your own default style, and don't add
  what-explaining comments either.
- Flag names/semantics mirror hubble CLI's own conventions wherever this
  tool overlaps with it — check hubble's actual flags before inventing a
  different convention for something hubble already named.
- "Known v1 simplifications" are stated explicitly in both code comments and
  the README, never silently assumed — if you add a new one, document it the
  same way, in both places.
- UI and CLI must stay provably the same engine (`ui.go` calls the exact
  functions `verdict.go`/`flows.go` define) — never fork logic between them.
