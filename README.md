# GuardBee

<p align="center">
  <img src="docs/branding/guardbee-logo.png" alt="GuardBee Logo" width="140" />
</p>

> **Inspect the flow before it lands in production.**  
> Pre-flight verification and live visual policy editing for Cilium and Kubernetes NetworkPolicies.

Answers one question before a CiliumNetworkPolicy merges: which real flows on this
cluster would it break or newly allow? No in-cluster agent, no persisted flow
store — see the design docs for why and for the wedge/UI scoping decisions:
`Obsidian projects/cilium-network-policy-editor/design-2026-10-11.md` (CLI wedge)
and `design-2026-10-12.md` (web UI, milestone 1).

## What's here today

- `guardbee policies [-n <namespace>|-A]` — lists live `CiliumNetworkPolicy` in
  that namespace (or every namespace, with `--all-namespaces`/`-A`) plus cluster-wide
  `CiliumClusterwideNetworkPolicy`, via the generated Cilium clientset.
- `guardbee flows [-n <namespace>|-A] [--last N] [-f]` — port-forwards to the
  cluster's `hubble-relay` pod (`cilium-system`) and streams real flows touching
  that namespace (or cluster-wide), via Hubble's `Observer.GetFlows` gRPC API.
  `--follow`/`-f` keeps tailing new flows until Ctrl+C instead of stopping after
  `--last`.
- `guardbee verdict [-n <namespace>|-A] [--last N] [-f] <candidate.yaml>` —
  the actual verdict engine: diffs a candidate `CiliumNetworkPolicy`/`CiliumClusterwideNetworkPolicy`
  against today's live policy state, judging real recent Hubble flows against
  both. `-n`/`--namespace` is always right for a `CiliumNetworkPolicy` candidate
  (it can only ever affect its own namespace); for a `CiliumClusterwideNetworkPolicy`
  candidate, which can span several namespaces or all of them, use
  `--all-namespaces`/`-A` instead so flow sampling actually covers its full blast
  radius. Prints `NEWLY_DROPPED` / `NEWLY_ALLOWED` rows (each color-coded and
  with a one-line plain-English reason) and, by default, just an `UNCHANGED`
  count rather than one row per unchanged flow — pass `--show-unchanged` to
  also print those rows (grouped after the regressions, so NEWLY_DROPPED/
  NEWLY_ALLOWED stay the first thing you see). A short legend explains
  whichever categories actually occurred this run — kept deliberately terse
  (see this README for the blank-peer and flow-buffer caveats it no longer
  spells out every run). In one-shot mode, identical rows across multiple
  flows (e.g. a kubelet probe firing every ~10s against the same port) are
  deduplicated to one line with a `(seen Nx in this sample)` count instead of
  repeating, grouped `NEWLY_DROPPED` first, then `NEWLY_ALLOWED`, then
  `UNCHANGED` (only with `--show-unchanged`). `--follow`/`-f` keeps
  judging new flows live until Ctrl+C instead of stopping after `--last`
  (printing each as it happens, undeduplicated, since each live event is
  distinct), registering any newly-seen identity with the engine as it shows
  up, so it stays correct no matter how long it runs.
  See `examples/` for ready-to-run candidates, covering both policy kinds:
  for `CiliumNetworkPolicy`, one that looks correct but isn't, one
  deliberately broken, and one that's actually merge-ready (built across
  three rounds of real traffic sampling — each round caught one more thing
  the others missed); for `CiliumClusterwideNetworkPolicy`, a
  `--all-namespaces` pair demonstrating the same "looks correct but isn't"
  lesson cluster-wide — restricting CoreDNS ingress to just DNS queries
  looks right, but silently breaks kubelet's health probes and Prometheus's
  metrics scrape, both caught live. These were all captured against the
  author's own homelab cluster, so they're real demonstrated catches, not
  synthetic — running them against a *different* cluster won't find
  matching traffic; point `verdict -n <your-namespace>` (or
  `--all-namespaces` for a CCNP) at your own candidate instead.
  Flag naming follows [hubble CLI](https://github.com/cilium/cilium/tree/main/hubble)'s
  own conventions (`--namespace`/`-n`, `--all-namespaces`/`-A`, `--follow`/`-f`,
  `--last`) wherever this tool overlaps with it, so anyone who already knows
  hubble doesn't have to relearn a different style here.
- `guardbee ui [--addr host:port]` — milestone 1 of the web UI
  (see `design-2026-10-12.md`): starts a local HTTP server (default
  `127.0.0.1:4747`) serving the same flows/verdict capability as the two
  subcommands above, in a browser instead of a terminal. Same access model as
  every other subcommand — your own kubeconfig, no new cluster footprint, no
  remote hosting or auth (a stated future direction, not this milestone). The
  JSON API (`POST /api/verdict`, `GET /api/flows`) is built from the exact
  same `computeVerdict`/`fetchFlows` functions the CLI itself calls — never a
  parallel implementation, so the UI and the CLI can't compute different
  answers for the same input, only present them differently. The
  React/TypeScript frontend (`ui/`, Vite + Tailwind) is built separately and
  embedded directly into this binary via `go:embed` — the same packaging
  pattern Argo CD's own UI uses (confirmed against its actual architecture,
  not assumed), so the shipped artifact stays one executable with no
  separate frontend server or Node runtime needed at runtime.

All four are read-only against the cluster. RBAC
(`apps/cilium-policy-simulator/rbac.yaml` in the `TOCA` repo) has been validated
live against the actual scoped `cilium-policy-simulator` ServiceAccount token
(not admin credentials) — no gaps found.

### How `verdict` works

Every sampled flow is judged twice — once against the real baseline CNPs/CCNPs,
once against baseline+candidate — using Cilium's own `pkg/policy` engine (same
`.Parse()` conversion the real agent uses, not a reimplementation). Flow
identities come directly from Hubble's own resolved `Endpoint.Identity`, so no
separate `CiliumIdentity` lookup is needed.

Known v1 simplifications (documented in code, not silent):
- Only ingress-at-destination is evaluated — the common "does my new CNP break
  traffic into this workload" case, not full bidirectional ingress+egress
  correctness.
- L7/FQDN-decided flows are counted as `not simulated` rather than guessed —
  those verdicts live in Envoy/the DNS proxy, not the policy map this engine
  computes.
- Reply packets of an already-established connection are skipped (`reply
  (skipped)` in the summary) — connection tracking always allows those
  regardless of CNP ingress rules, which only gate new connections.
- A flow's identities must already be real and currently allocated. Candidate
  labels with no matching live pod are simply never exercised by any sampled
  flow — this tool never invents a fake identity.
- Hubble's flow buffer is a small recent-flow ring, not a persisted history. A
  `0 newly dropped` result can mean "nothing in the sample touched the port
  you changed," not "nothing would break" — re-run or raise `--last` if a
  result looks too clean. For the same reason, `--last` is a ceiling, not a
  guarantee: `verdict` reports "using N of up to `--last` requested flows"
  when Hubble's buffer holds fewer matching flows than asked for — that's the
  buffer being exhausted, not a bug. Raising `--last` further won't help
  once the buffer's actual contents are exhausted; use `--follow` to keep
  accumulating flows over time instead.

A blank source/destination in the output (e.g. `reserved:host`) is a non-pod
peer, not a bug — most commonly kubelet's TCP liveness/readiness probe. That's
exactly what `examples/homeassistant-allow-mosquitto.yaml` caught (see the
note above on why these particular examples are tied to the author's own
cluster): it looked correct (and does correctly keep real MQTT traffic
working), but running `verdict` against it found it would *also* silently
break Prometheus's `:8123` scrape and kubelet's health check on the same
port — both confirmed via the Kubernetes API, not guessed.
`examples/homeassistant-merge-ready.yaml` is the corrected version that
allows all three.

The same lesson, one level up: `examples/ccnp-coredns-dns-only.yaml` is a
`CiliumClusterwideNetworkPolicy` that correctly restricts CoreDNS ingress to
DNS queries from any in-cluster pod (`fromEntities: cluster`, port 53) — but
running `verdict --all-namespaces --last 15000` against it found it would
*also* break kubelet's liveness/readiness probes (`reserved:host`, ports
8080/8181) and Prometheus's metrics scrape
(`observability/prometheus-toca-0`, port 9153) on all three CoreDNS pods.
`examples/ccnp-coredns-merge-ready.yaml` adds explicit rules for all three
and comes back with zero regressions on the same sample size. Note this one
needs `--all-namespaces`, not `-n kube-system` alone — the regression lives
in the *source* side (`observability`), which a namespace filter pinned to
the destination's own namespace wouldn't rule out seeing, but omitting it
is the safer default for any CCNP since you may not know its full blast
radius in advance.

## Build

Preferred, via [mise](https://mise.jdx.dev) (pins the exact Go and Node
toolchains and installs them if missing):

```
mise run build     # npm run build in ui/, then go build -o guardbee .
mise run check     # build + go vet + go test
mise run clean     # rm -f guardbee
mise run ui-dev    # frontend dev server with hot reload (proxies /api to a
                    # separately-running "guardbee ui" on :4747)
```

`mise run build` always rebuilds the frontend first — the Go binary embeds
whatever is currently in `ui/dist` via `go:embed` (see `embed.go`), so a stale
`ui/dist` would silently ship an outdated UI otherwise.

Or plain Go (after building the frontend yourself — `cd ui && npm install &&
npm run build`, needed at least once before this works since `go:embed`
requires `ui/dist` to exist):

```
go build -o guardbee .
```

Confirmed 2026-10-11: `github.com/cilium/cilium@v1.20.2` (pinned to the cluster's
exact Cilium version) — including the internal `pkg/policy` engine, not just the
generated clientset and Hubble's `observer` gRPC stubs — imports and builds cleanly
as a plain Go dependency. No eBPF/CGO/privileged build step required. This was the
biggest open risk in the design doc; it's resolved. The second biggest risk
(whether the RBAC manifest is actually sufficient) is also resolved — see above.

### Renaming the binary

The name (`guardbee`) lives in exactly one place: the `binName` constant
in `globals.go`. Usage text and every error message prefix reference it
directly, and `mise.toml`'s build/clean tasks plus `scripts/gen-completions.sh`
extract the same value out of `globals.go` via `sed`. To rename: change
`binName` in `globals.go`, then `mise run build && mise run completions`. No
other file needs touching except `.gitignore`, which still has to name the
build artifact literally.

## Shell completions

Generated from `globals.go`'s `binName` by `scripts/gen-completions.sh`
(`mise run completions` to regenerate after a rename or a flag/subcommand
change):

```
source completions/guardbee.bash              # bash, in ~/.bashrc
source completions/guardbee.fish               # fish: or copy to ~/.config/fish/completions/
cp completions/_guardbee ~/.zsh/completions/    # zsh: anywhere on your $fpath, then `compinit`
```

## Run

Needs a kubeconfig with read access to this cluster — either your own, or the
scoped `guardbee` ServiceAccount token (see
`apps/cilium-policy-simulator/rbac.yaml` in the `TOCA` repo) wired into a
dedicated context.

```
export KUBECONFIG=/path/to/kubeconfig
./guardbee policies -n testing
./guardbee flows -n testing --last 20
./guardbee policies --all-namespaces
./guardbee verdict -n myapp --last 50 your-candidate.yaml
./guardbee verdict --all-namespaces --last 15000 examples/ccnp-coredns-merge-ready.yaml
```

The `testing` namespace already has real `CiliumNetworkPolicy` objects — a
convenient target for a first `policies`/`flows` smoke test. The `examples/`
directory has five ready-to-run candidates, three `CiliumNetworkPolicy` and
two `CiliumClusterwideNetworkPolicy` (see the note above — these are real
catches from the author's own cluster, so they won't find matching traffic
on a different one; swap in your own candidate and namespace/`--all-namespaces`
instead).

## Next steps

1. Live-validate `verdict` further against real candidates in other namespaces —
   initial runs against `homeassistant` found a real would-be regression
   (restricting ingress to mosquitto-only would also break Prometheus's `:8123`
   scrape), confirming the tool catches things a human wouldn't necessarily think
   of.
2. Consider egress-side evaluation, not just ingress-at-destination (currently
   an explicit v1 simplification).
