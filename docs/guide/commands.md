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
guardbee flows [-n <namespace>|-A] [--to-pod|--to-service|--to-label|--to-port ...] [--last N] [-f]
```

| Flag | Meaning |
|---|---|
| `-n`, `--namespace` / `-A`, `--all-namespaces` | Scope flows to one namespace or every namespace |
| `--last N` | Ceiling on flows fetched — Hubble's ring buffer may hold fewer |
| `-f`, `--follow` | Keep tailing new flows until Ctrl+C, instead of stopping after `--last` |
| `--to-pod`, `--to-service`, `--to-label`, `--to-port` | Only flows going to that destination, with `hubble observe`'s own semantics. Repeatable; repeats of one flag are ORed, different flags ANDed. A bare pod/service name means the `-n` namespace |

> Port-forwards to the cluster's `hubble-relay` pod (`cilium-system`) and streams via Hubble's `Observer.GetFlows` gRPC API.

---

## `verdict`

The engine. Diffs a candidate policy against live traffic — judged once against today's policy, once with the candidate added.

```
guardbee verdict [-n <namespace>|-A] [--to-pod|--to-service|--to-label|--to-port ...] [--last N] [-f] <candidate.yaml>
```

| Flag | Meaning |
|---|---|
| `-n`, `--namespace` | Right for a CNP candidate — it can only ever affect its own namespace |
| `-A`, `--all-namespaces` | Right for a CCNP candidate — it can span namespaces, so sampling needs to as well |
| `--last N` / `-f`, `--follow` | Same as `flows` |
| `--to-pod`, `--to-service`, `--to-label`, `--to-port` | Same as `flows`: judge only flows going to that destination |
| `--show-unchanged` | Also print `UNCHANGED` rows (default: just a count) |

> Output is three buckets: `NEWLY_DROPPED` and `NEWLY_ALLOWED` (each with a one-line plain-English reason), and `UNCHANGED`. See [how verdict works](how-it-works.html) for the engine mechanics.

`<candidate.yaml>` may hold several `---`-separated policies, like a file for `kubectl apply -f`; they're judged together as one candidate. In the UI, a row's **Allow / Deny** button uses this: it shows the affected workload's detected identity labels, and appends a separate exception policy scoped to the labels you pick (with `enableDefaultDeny` off for that direction, so it never default-denies anything on its own). Then it re-runs the verdict.

The `--to-*` filters are applied in Hubble's query, not to the results, so all `--last` flows go to that destination instead of a quiet destination getting a handful of the cluster-wide buffer. For example, `guardbee verdict -n myapp --to-label reserved:kube-apiserver --to-port 443 candidate.yaml`. The UI's **Destination filter** (under Scope) does the same, and each run card shows the filter it ran with. Its fields suggest destinations seen in earlier runs: workload pod prefixes, Services, labels and ports, most-seen first. Flows to other destinations aren't judged at all, so a filtered run is for investigating one path, not for signing off on a policy.

---

## `ui`

A local web UI for the same engine — pick a namespace, build or paste a candidate, see the verdict as a graph.

```
guardbee ui [--addr host:port]
```

> Calls the exact same `computeVerdict`/`fetchFlows` functions the CLI uses — never a parallel implementation, so the UI and CLI can't disagree on an answer for the same input. The React/TypeScript frontend is embedded into the binary via `go:embed` (the same pattern Argo CD's own UI uses), so the shipped artifact is one executable — no separate frontend server or Node runtime at runtime.

Your work in progress is kept in the browser (localStorage), never sent to the cluster. The Policy Editor draft and the Verdict tab's candidate, namespace and scope auto-save, so a reload restores them. Verdict results aren't restored: they're snapshots of live traffic. **💾 Save** (Verdict candidate box or Policy Editor output) adds a named entry to **Saved policies** (header icon). From there you can reopen an entry in Verdict or the Editor, rename, duplicate or delete it, or download it as `.yaml`.

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
