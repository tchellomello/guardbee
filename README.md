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

No in-cluster agent, no persisted flow store, no new cluster footprint:
GuardBee runs locally with your own kubeconfig and read-only RBAC.

## What's here today

Four subcommands — `policies`, `flows`, `verdict`, and a local `ui` — all
read-only against the cluster. `verdict` is the actual engine: it diffs a
candidate `CiliumNetworkPolicy`/`CiliumClusterwideNetworkPolicy` against
today's live policy state, judging real recent Hubble flows against both,
using Cilium's own `pkg/policy` engine. See the
**[full command reference](https://tchellomello.github.io/guardbee/guide/commands.html)**
and **[how verdict works](https://tchellomello.github.io/guardbee/guide/how-it-works.html)**
for flag-by-flag detail, known v1 simplifications, and two real
regressions it caught.

## Quickstart

```
mise run build
export KUBECONFIG=/path/to/kubeconfig
./guardbee verdict -n your-namespace --last 50 your-candidate.yaml
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

GuardBee's own version tracks the Cilium version it embeds
(`go.mod`'s `github.com/cilium/cilium`) directly — e.g. `v1.20.2` means built
against and validated against Cilium v1.20.2's actual `pkg/policy` engine and
CRD schema. A GuardBee-only change with no Cilium bump appends a trailing
qualifier instead of a new Cilium version number (`v1.20.2-1`, `v1.20.2-2`, …).
This makes compatibility legible at a glance instead of two independent
version numbers that drift apart — see
[#2](https://github.com/tchellomello/guardbee/issues/2) for the open problem
of also detecting the *cluster's* real Cilium version at runtime, since the
two can still differ from each other even with this scheme.

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
