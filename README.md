# GuardBee

<p align="center">
  <img src="docs/branding/guardbee-logo.png" alt="GuardBee Logo" width="140" />
</p>

<h3 align="center">Ship the policy. Not the outage.</h3>

<p align="center">
  Test a CiliumNetworkPolicy against what's actually happening on your cluster —
  before it merges, not after it pages someone.
</p>

<p align="center">
  <a href="#build">Build</a> ·
  <a href="#run">Run</a> ·
  <a href="#roadmap">Roadmap</a> ·
  <a href="LICENSE">License</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
</p>

---

## The problem

A CiliumNetworkPolicy that looks correct in review can still silently break
production: a forgotten `reserved:host` entity drops kubelet's liveness
probe, a scoped-too-narrow selector drops an observability sidecar's
scrape, DNS egress gets missed. None of that shows up in code review or CI
— every one of those rules is syntactically valid YAML. The first signal is
usually a page, not a diff.

## The solution

GuardBee diffs a candidate `CiliumNetworkPolicy`/`CiliumClusterwideNetworkPolicy`
against **real recent traffic** from your cluster, judged by **Cilium's own
policy engine** (`pkg/policy` — the same code your cluster actually runs,
embedded directly, not reimplemented). The result is a verdict: which real
flows would newly break, which would newly be allowed, and which stay
unchanged — before you merge, not after.

No in-cluster agent, no persisted flow store, no new cluster footprint:
GuardBee runs locally with your own kubeconfig and read-only RBAC.

## What's here today

- **`guardbee policies [-n <namespace>|-A]`** — lists live `CiliumNetworkPolicy`
  in a namespace (or every namespace, `--all-namespaces`/`-A`) plus
  cluster-wide `CiliumClusterwideNetworkPolicy`, via the generated Cilium
  clientset.
- **`guardbee flows [-n <namespace>|-A] [--last N] [-f]`** — port-forwards to
  the cluster's `hubble-relay` pod (`cilium-system`) and streams real flows
  touching that namespace (or cluster-wide), via Hubble's `Observer.GetFlows`
  gRPC API. `--follow`/`-f` keeps tailing new flows until Ctrl+C instead of
  stopping after `--last`.
- **`guardbee verdict [-n <namespace>|-A] [--last N] [-f] <candidate.yaml>`** —
  the actual verdict engine: diffs a candidate policy against today's live
  policy state, judging real recent Hubble flows against both. `-n`/
  `--namespace` is always right for a CNP candidate (it can only ever affect
  its own namespace); for a CCNP candidate, which can span several
  namespaces or all of them, use `--all-namespaces`/`-A` instead so flow
  sampling covers its full blast radius. Prints `NEWLY_DROPPED`/
  `NEWLY_ALLOWED` rows (each with a one-line plain-English reason) and, by
  default, just an `UNCHANGED` count — pass `--show-unchanged` to also print
  those rows. `--follow`/`-f` keeps judging new flows live until Ctrl+C.
- **`guardbee ui [--addr host:port]`** — a local web UI: pick a namespace,
  drop in (or visually build) a candidate policy, and see the same verdict
  as a readable graph instead of terminal rows. Same access model as every
  other subcommand — your own kubeconfig, no remote hosting, no auth (a
  stated future direction, not today). The JSON API is built from the exact
  same `computeVerdict`/`fetchFlows` functions the CLI itself calls — never
  a parallel implementation, so the UI and the CLI can't compute different
  answers for the same input. The frontend (React/TypeScript, Vite +
  Tailwind + [`@xyflow/react`](https://reactflow.dev/)) is embedded directly
  into the binary via `go:embed` — the same packaging pattern Argo CD's own
  UI uses — so the shipped artifact is one executable, no separate frontend
  server or Node runtime at runtime.

All four are read-only against the cluster.

### How `verdict` works

Every sampled flow is judged twice — once against the real baseline
CNPs/CCNPs, once against baseline+candidate — using Cilium's own
`pkg/policy` engine (the same `.Parse()` conversion the real agent uses, not
a reimplementation). Flow identities come directly from Hubble's own
resolved `Endpoint.Identity`, so no separate `CiliumIdentity` lookup is
needed.

Known v1 simplifications (documented in code, not silent):

- Only ingress-at-destination is evaluated — the common "does my new CNP
  break traffic into this workload" case, not full bidirectional
  ingress+egress correctness.
- L7/FQDN-decided flows are counted as `not simulated` rather than guessed —
  those verdicts live in Envoy/the DNS proxy, not the policy map this engine
  computes.
- Reply packets of an already-established connection are skipped (`reply
  (skipped)` in the summary) — connection tracking always allows those
  regardless of CNP ingress rules, which only gate new connections.
- A flow's identities must already be real and currently allocated. Candidate
  labels with no matching live pod are simply never exercised by any sampled
  flow — GuardBee never invents a fake identity.
- Hubble's flow buffer is a small recent-flow ring, not a persisted history. A
  `0 newly dropped` result can mean "nothing in the sample touched the port
  you changed," not "nothing would break" — re-run or raise `--last` if a
  result looks too clean. For the same reason, `--last` is a ceiling, not a
  guarantee: `verdict` reports "using N of up to `--last` requested flows"
  when Hubble's buffer holds fewer matching flows than asked for — that's the
  buffer being exhausted, not a bug. Use `--follow` to keep accumulating
  flows over time instead of raising `--last` further.

A blank source/destination in the output (e.g. `reserved:host`) is a non-pod
peer, not a bug — most commonly kubelet's TCP liveness/readiness probe.
That's exactly what `examples/homeassistant-allow-mosquitto.yaml` catches:
it looks correct (and does correctly keep real MQTT traffic working), but
running `verdict` against it finds it would *also* silently break a
Prometheus `:8123` scrape and kubelet's health check on the same port — both
confirmed via the Kubernetes API, not guessed.
`examples/homeassistant-merge-ready.yaml` is the corrected version that
allows all three — same candidate, corrected, re-run against the real
cluster:

<p align="center">
  <img src="docs/images/04-verdict-regression.png" width="46%" alt="Verdict tab showing 8 NEWLY_DROPPED flows after running the looks-correct candidate policy" />
  &nbsp;&nbsp;
  <img src="docs/images/06-verdict-clean.png" width="46%" alt="Verdict tab showing the corrected policy: zero newly dropped, zero newly allowed" />
</p>
<p align="center"><sub>Left: looks correct, isn't. Right: same candidate, fixed — every real flow unchanged.</sub></p>

The same lesson, one level up: `examples/ccnp-coredns-dns-only.yaml` is a
`CiliumClusterwideNetworkPolicy` that correctly restricts CoreDNS ingress to
DNS queries from any in-cluster pod — but running
`verdict --all-namespaces --last 15000` against it finds it would *also*
break kubelet's liveness/readiness probes and the observability namespace's
Prometheus scrape, across all CoreDNS pods.
`examples/ccnp-coredns-merge-ready.yaml` adds explicit rules for all three
and comes back with zero regressions on the same sample size. Note this one
needs `--all-namespaces`, not a single namespace — the regression lives on
the *source* side, which a namespace filter pinned to the destination's own
namespace wouldn't rule out, and you may not know a CCNP's full blast radius
in advance anyway.

## Build

<a name="build"></a>

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

Built against `github.com/cilium/cilium@v1.20.2` as a plain Go dependency —
including the internal `pkg/policy` engine, not just the generated clientset
and Hubble's `observer` gRPC stubs. No eBPF/CGO/privileged build step
required.

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

<a name="run"></a>

Needs a kubeconfig with read access to your cluster — either your own, or a
dedicated service account scoped with `kubernetes/rbac.yaml` (this repo):
`get`/`list`/`watch` on CNPs, CCNPs, `CiliumIdentity`, `CiliumEndpoint`, and
namespaces, plus a `cilium-system`-scoped role to port-forward to
`hubble-relay`. Nothing GuardBee does writes to the cluster.

```
export KUBECONFIG=/path/to/kubeconfig
./guardbee policies -n your-namespace
./guardbee flows -n your-namespace --last 20
./guardbee policies --all-namespaces
./guardbee verdict -n your-namespace --last 50 your-candidate.yaml
./guardbee ui
```

`examples/*.yaml` are real catches from the author's own homelab cluster, so
they won't find matching traffic on a *different* cluster — they're there to
show the kind of regression GuardBee catches, not to run as-is against your
own. Point `verdict -n <your-namespace>` (or `--all-namespaces` for a CCNP)
at your own candidate and namespace instead.

Flag naming follows [hubble CLI](https://github.com/cilium/cilium/tree/main/hubble)'s
own conventions (`--namespace`/`-n`, `--all-namespaces`/`-A`, `--follow`/`-f`,
`--last`) wherever this tool overlaps with it, so anyone who already knows
hubble doesn't have to relearn a different style here.

## Roadmap

<a name="roadmap"></a>

- [x] CLI verdict engine
- [x] Web UI with a graph-based policy editor
- [ ] Egress-side evaluation (today: ingress-at-destination only, an
      explicit v1 simplification)
- [ ] Natural-language policy authoring — describe the intent in plain
      English, GuardBee drafts and validates the candidate (exploring)

## Contributing

Issues and PRs welcome. See `AGENTS.md` for the project's architecture
principles, known engine gotchas, and house style before making non-trivial
changes to the verdict engine (`verdict.go`).

## License

[Apache License 2.0](LICENSE).
