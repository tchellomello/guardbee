---
layout: doc
title: How verdict Works
description: The verdict engine's mechanics, known v1 simplifications, and two real regressions it caught.
---

# How `verdict` works

Every sampled flow is judged twice — once against the real baseline
CNPs/CCNPs, once against baseline+candidate — using Cilium's own
`pkg/policy` engine (the same `.Parse()` conversion the real agent uses, not
a reimplementation). Flow identities come directly from Hubble's own
resolved `Endpoint.Identity`, so no separate `CiliumIdentity` lookup is
needed.

---

## Known v1 simplifications

Documented in code, not silent:

| Simplification | What it means |
|---|---|
| Ingress only | Only ingress-at-destination is evaluated — not full bidirectional ingress+egress correctness. |
| L7/FQDN flows | Counted as `not simulated` rather than guessed — those verdicts live in Envoy/the DNS proxy, not the policy map this engine computes. |
| Reply packets | Skipped (`reply (skipped)` in the summary) — connection tracking always allows those regardless of CNP ingress rules. |
| Real identities only | Candidate labels with no matching live pod are never exercised by any sampled flow — GuardBee never invents a fake identity. |
| `--last` is a ceiling | Hubble's flow buffer is a small recent-flow ring, not persisted history — it may hold fewer flows than requested. Use `--follow` to accumulate more over time instead of raising `--last` further. |

> A `0 newly dropped` result can mean "nothing in the sample touched the port
> you changed," not "nothing would break" — re-run, raise `--last`, or use
> `--follow` if a result looks too clean.

---

## Two regressions it caught

Both are real runs against the self-paced [Lab](lab.html)'s own cluster —
not synthetic fixtures, and reproducible on your own machine.

### Scoped-too-narrow Postgres allow

A `CiliumNetworkPolicy` that correctly allows an app's traffic to its
database — and looks completely reasonable — but silently breaks a
Prometheus scrape and kubelet's own health probe on the same pod. The
[Lab](lab.html) walks through this exact candidate end to end:

<p class="img-row">
  <img src="../images/lab-04-verdict-regression.png" alt="Verdict tab showing 12 NEWLY_DROPPED flows for the looks-correct candidate, with red dashed edges on the flow graph" />
  <img src="../images/lab-06-verdict-clean.png" alt="Verdict tab showing the corrected policy: zero newly dropped, zero newly allowed" />
</p>

> Left: looks correct, isn't. Right: same candidate, fixed — every real
> flow unchanged. `examples/postgres-wrong-port.yaml` is a variation on
> the same mistake (a typo'd port instead of a forgotten peer), and
> `examples/postgres-deny-all.yaml` is the maximal version (nothing
> allowed at all) — both runnable against the Lab the same way.

### Cluster-wide lockdown

The same lesson, one level up: `examples/ccnp-postgres-lockdown.yaml` is
the `CiliumClusterwideNetworkPolicy` version of the same story —

```
guardbee verdict --all-namespaces --last 50 \
  examples/ccnp-postgres-lockdown.yaml
```

— needing `--all-namespaces` instead of `-n postgres` to simulate
correctly. A namespace filter pinned to one destination namespace can
miss a CCNP's true blast radius, and you may not know it in advance
anyway.
