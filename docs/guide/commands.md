---
layout: doc
title: Commands
description: GuardBee's subcommands — policies, flows, verdict, ui, and version.
---

# Commands

Every one of these except `version` is read-only against the cluster.

## `policies`

Lists live policies touching a namespace.

```
guardbee policies [-n <namespace>|-A]
```

| Flag | Meaning |
|---|---|
| `-n`, `--namespace` | One namespace's CNPs |
| `-A`, `--all-namespaces` | Every namespace's CNPs, plus cluster-wide CCNPs |

> Uses the generated Cilium clientset — a direct read, nothing hand-parsed.

---

## `flows`

Streams real traffic from Hubble.

```
guardbee flows [-n <namespace>|-A] [--last N] [-f]
```

| Flag | Meaning |
|---|---|
| `-n`, `--namespace` / `-A`, `--all-namespaces` | Scope flows to one namespace or every namespace |
| `--last N` | Ceiling on flows fetched — Hubble's ring buffer may hold fewer |
| `-f`, `--follow` | Keep tailing new flows until Ctrl+C, instead of stopping after `--last` |

> Port-forwards to the cluster's `hubble-relay` pod (`cilium-system`) and streams via Hubble's `Observer.GetFlows` gRPC API.

---

## `verdict`

The engine. Diffs a candidate policy against live traffic — judged once against today's policy, once with the candidate added.

```
guardbee verdict [-n <namespace>|-A] [--last N] [-f] <candidate.yaml>
```

| Flag | Meaning |
|---|---|
| `-n`, `--namespace` | Right for a CNP candidate — it can only ever affect its own namespace |
| `-A`, `--all-namespaces` | Right for a CCNP candidate — it can span namespaces, so sampling needs to as well |
| `--last N` / `-f`, `--follow` | Same as `flows` |
| `--show-unchanged` | Also print `UNCHANGED` rows (default: just a count) |

> Output is three buckets: `NEWLY_DROPPED` and `NEWLY_ALLOWED` (each with a one-line plain-English reason), and `UNCHANGED`. See [how verdict works](how-it-works.html) for the engine mechanics.

---

## `ui`

A local web UI for the same engine — pick a namespace, build or paste a candidate, see the verdict as a graph.

```
guardbee ui [--addr host:port]
```

> Calls the exact same `computeVerdict`/`fetchFlows` functions the CLI uses — never a parallel implementation, so the UI and CLI can't disagree on an answer for the same input. The React/TypeScript frontend is embedded into the binary via `go:embed` (the same pattern Argo CD's own UI uses), so the shipped artifact is one executable — no separate frontend server or Node runtime at runtime.

---

## `version`

Prints the version this binary was built from — never touches the cluster.

```
guardbee version
```

| Build | Output |
|---|---|
| A released binary | the published tag, e.g. `v0.3.0` |
| `mise run build` | `dev-<short-sha>`, plus `-dirty` if the working tree has uncommitted changes |
| Plain `go build` (no `-ldflags`) | `dev-unknown` |
