---
layout: doc
title: FAQ
description: How GuardBee differs from hubble observe, kubectl dry-run and Cilium's audit mode, what it can't judge, and what it touches.
---

# FAQ

## How is this different from…

| Tool | What it tells you | What GuardBee adds |
|---|---|---|
| `hubble observe` | What happened to traffic under the policies that are live **now** | What would happen to that same traffic under a policy that **isn't live yet**. `flows` and `blame` overlap with hubble on purpose and use its flag names; `blame` shows the policy attribution you'd otherwise dig out of `hubble observe --type policy-verdict -o json` with `jq` |
| `kubectl apply --dry-run=server` | Whether the API server would accept the object: schema, admission | Which real flows it would allow or block. A policy can pass dry-run and still drop your health checks |
| Cilium's policy audit mode | What a policy *applied to the cluster* would deny, logged as `AUDIT` instead of enforced, as traffic arrives | An answer before anything is applied, from traffic Hubble has already seen. The two complement each other: GuardBee in the PR, audit mode as a rollout step |
| Visual policy editors | What a policy says, drawn as a graph | What it does to the traffic actually running on your cluster |
| Policy linters | Whether the YAML follows rules someone wrote down | Whether it breaks something real. Every policy in the [Quickstart](quickstart.html) is valid YAML; one of them drops 17 real flows |

---

## Can I trust the verdict?

The verdict comes from Cilium's own policy engine (`pkg/policy`), embedded in the binary and pinned to an exact Cilium release, the one in the release tag (`v1.20.4-6` judges with Cilium 1.20.4). It is not a reimplementation that could drift from what your cluster enforces.

What GuardBee adds around the engine is documented, not hidden: the [known simplifications](how-it-works.html#known-v1-simplifications) say exactly where a result rests on GuardBee's own logic (for example HTTP request matching, marked "matched by GuardBee, not Envoy" on every row it applies to), and anything it can't judge faithfully is reported as not judged rather than guessed.

## What can't it judge?

- **Kubernetes `NetworkPolicy`** in a candidate file: named under "Not judged", not simulated.
- **Live policies using `fromNodes`/`toNodes`:** skipped and named in a warning; Hubble flows carry no node labels to match them against.
- **Flows with no destination port** (port 0): counted as not simulated.
- **A new `toFQDNs` selector** when the source pod's DNS doesn't go through Cilium's DNS proxy: Hubble has no names to match, so a flow it would drop is not simulated.
- **HTTP rules outside the modelled subset** (deny or tiered rules, listeners, SNI, secret-backed headers), or when Hubble redacts URL queries.
- **Constructs a newer Cilium removed** or deprecated, such as `fromRequires`: the candidate is rejected. `guardbee compat` lists them.

## Which Cilium versions does it support?

The engine is pinned to one version per release (the release tag names it), and is meant to stay usable against clusters running somewhat older versions too, currently 1.18–1.20. When your cluster differs from the engine at major.minor, the CLI and UI warn about the skew, and `guardbee version` prints both.

---

## Does it change anything in my cluster?

No. Every command reads the cluster and changes nothing: no agent to install, no CRDs, no flow database. The one exception is opt-in: the UI's [connectivity tests](tcp-probes.html), enabled with `--enable-probes` and extra RBAC, append an ephemeral container to a Pod you pick. They never apply the candidate policy.

## What leaves my machine?

GuardBee talks to your cluster's API server, and to Hubble Relay through it (or directly, with `--hubble-addr`). It sends nothing anywhere else. The web UI runs on `127.0.0.1` and keeps drafts and saved policies in your browser; like this site, it loads its fonts from Google Fonts.

## Why did I get fewer flows than `--last`?

`--last` is a ceiling. Hubble keeps a small ring buffer of recent flows for the whole cluster, not per namespace, so a quiet namespace may have few flows in it at any moment. Use `--follow` to collect more over time, and filters (`--to-port`, `--to-label`, …) to spend the sample on the traffic you care about.

## Why did a "clean" verdict miss something?

A verdict covers the flows in the sample. Traffic that didn't happen recently, such as a nightly backup or a monthly cron job, isn't there to judge. `0 newly dropped` can mean "nothing in the sample touched what you changed". In CI, set `--min-flows` so a thin sample fails as inconclusive instead of passing; see [Gate PRs in CI](ci.html#what-a-pass-means).
