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
  <a href="https://tchellomello.github.io/guardbee/">Live demo</a> ·
  <a href="https://tchellomello.github.io/guardbee/guide/index.html">Docs</a> ·
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

No in-cluster agent or persisted flow store: GuardBee runs locally with your
own kubeconfig and read-only RBAC by default. Explicitly enabled TCP/UDP connectivity tests
are the exception: they append retained ephemeral-container entries to Pods
and require optional additional RBAC.

## What's here today

Five subcommands — `policies`, `flows`, `blame`, `verdict`, and a local
`ui` — all read-only against the cluster by default. Only the UI's explicitly
enabled connectivity endpoint mutates Pods (see below). `verdict` is the actual engine:
it diffs a candidate `CiliumNetworkPolicy`/`CiliumClusterwideNetworkPolicy`
against today's live policy state, judging real recent Hubble flows against
both, using Cilium's own `pkg/policy` engine. `blame` is for day-2
debugging: for a pod or namespace, which live policy (or default deny)
allowed or dropped each real flow, as Cilium itself attributed it. See the
**[full command reference](https://tchellomello.github.io/guardbee/guide/commands.html)**
and **[how verdict works](https://tchellomello.github.io/guardbee/guide/how-it-works.html)**
for flag-by-flag detail, known v1 simplifications, and two real
regressions it caught.

## Install

- **Release binary**: Linux and macOS tarballs on the
  [releases page](https://github.com/tchellomello/guardbee/releases).
- **Nix / NixOS**: the repo is a flake. Try `nix run github:tchellomello/guardbee -- version`,
  or add it as an input to your system flake. See
  **[Install](https://tchellomello.github.io/guardbee/guide/install.html)**
  for NixOS, Home Manager and `nix profile`.
- **From source**: `mise run build` (see below).

## Quickstart

```
mise run build
export KUBECONFIG=/path/to/kubeconfig
./guardbee verdict -n your-namespace --last 50 your-candidate.yaml
./guardbee blame your-namespace/your-pod --verdict DROPPED
./guardbee ui
```

Needs a kubeconfig with read access to your cluster — either your own, or
the read-only service account in `kubernetes/rbac.yaml`. Full build options
(plain Go, shell completions) and run details (RBAC,
flag conventions) are in the
**[Build](https://tchellomello.github.io/guardbee/guide/build.html)** and
**[Run](https://tchellomello.github.io/guardbee/guide/run.html)** guide
pages.

## Versioning

Releases are tagged `v<cilium-version>-<n>`. The first part is the Cilium version whose `pkg/policy` engine and CRD schema GuardBee embeds (`go.mod`'s `github.com/cilium/cilium`). The second part counts GuardBee releases on that engine: `v1.20.4-1` is the first release built on Cilium v1.20.4, and `v1.20.4-2` the next one without a Cilium bump. A Cilium bump starts again at `-1`. You can see which Cilium a release judges with just from its tag.

The engine version and your cluster's version can still differ. `guardbee version` prints both:

```
cilium engine 1.20.4 (pinned)
cilium cluster 1.20.4 (context: my-cluster)
```

`policies`, `flows`, `verdict` and the UI also warn when the two differ at major.minor ([#2](https://github.com/tchellomello/guardbee/issues/2)).

Releases before this scheme were `v0.0.1`–`v0.0.7`. To Go's module tooling the `-<n>` suffix marks a pre-release, so install from the [releases page](https://github.com/tchellomello/guardbee/releases) or the [Nix flake](https://tchellomello.github.io/guardbee/guide/install.html), not `go install …@latest`.

## Roadmap

<a name="roadmap"></a>

- [x] CLI verdict engine
- [x] Web UI with a graph-based policy editor
- [x] Egress-side evaluation (identity/CIDR/entity/port rules; FQDN egress
      stays `not simulated`)
- [ ] `fromNodes`/`toNodes` policies — today a live policy using them is
      skipped and named in the UI banner / CLI warning, not simulated
      (Hubble flows carry no node labels to match them against)
- [ ] Natural-language policy authoring — describe the intent in plain
      English, GuardBee drafts and validates the candidate (exploring)

## Contributing

Issues and PRs welcome. See `AGENTS.md` for the project's architecture
principles, known engine gotchas, and house style before making non-trivial
changes to the verdict engine (`verdict.go`).

## License

[Apache License 2.0](LICENSE).
## Optional active connectivity tests

The UI's default remains read-only. `guardbee ui --enable-probes --probe-image
<repository:tag-or-digest>` explicitly enables a
cluster-mutating TCP/UDP test using a restricted ephemeral container in a selected
running Pod. It requires numeric-loopback serving and additional optional RBAC.
Each terminated ephemeral entry is immutable and remains until the Pod is
replaced; GuardBee never removes/restarts the Pod. Cancellation stops capture
but does not kill an injected container; the image's `timeout` bounds
its command runtime. Hostnames resolve inside the Pod; flow attribution is best-effort, not
proof that a packet came from the probe. CIDR-group identity injection is
unverified and FQDN/L7 proxy semantics are not reproduced, so those policies
suppress probe simulation instead of producing a reassuring verdict.
Authentication, named ports, agent-resolved services, Kubernetes NetworkPolicy
inventory, and incomplete/lost capture likewise withhold probe predictions.
Candidate decisions use the shared real Cilium engine; `UNCHANGED` can be still
denied, so verdict JSON explicitly includes `baselineAllowed`/`candidateAllowed`.
UDP requires Python 3 and sends one fixed `guardbee-connectivity-probe`
marker, never an arbitrary payload. Confirm this unexpected application payload
and selected operator-owned target before sending. UDP `generated` means only
that `sendto` returned, not reachability or policy allowance; unresolved captured
endpoints are not simulated. The legacy TCP API is retained.
See [connectivity safety, image requirements, and API](docs/guide/tcp-probes.md).
