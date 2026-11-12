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
| `--replace-existing` | Judge the candidate as replacing a live policy with the same kind, namespace and name, instead of adding it on top |
| `--fail-on-dropped` | Exit `2` if any sampled flow is `NEWLY_DROPPED` |
| `--min-flows N` | Exit `3` if fewer than N flows were judged (replies and not-simulated flows don't count) |
| `--format table\|json\|markdown` | Output format; `json` and `markdown` are one-shot only |

> Output is three buckets: `NEWLY_DROPPED` and `NEWLY_ALLOWED` (each with a one-line plain-English reason), and `UNCHANGED`. See [how verdict works](how-it-works.html) for the engine mechanics.

`<candidate.yaml>` may hold several `---`-separated policies, like a file for `kubectl apply -f`; they're judged together as one candidate. In the UI, a row's **Allow / Deny** button uses this: it shows the affected workload's detected identity labels, and appends a separate exception policy scoped to the labels you pick (with `enableDefaultDeny` off for that direction, so it never default-denies anything on its own). Then it re-runs the verdict.

The `--to-*` filters are applied in Hubble's query, not to the results, so all `--last` flows go to that destination instead of a quiet destination getting a handful of the cluster-wide buffer. For example, `guardbee verdict -n myapp --to-label reserved:kube-apiserver --to-port 443 candidate.yaml`. The UI's **Destination filter** (under Scope) does the same, and each run card shows the filter it ran with. Its fields suggest destinations seen in earlier runs: workload pod prefixes, Services, labels and ports, most-seen first. Flows to other destinations aren't judged at all, so a filtered run is for investigating one path, not for signing off on a policy.

### Editing an existing policy

By default the candidate is added on top of the live policy set, including a live policy with the same name. When the candidate is an edit of a live policy, pass `--replace-existing`: the live copy is left out of the candidate side, which is what applying the edit does. Without it, rules the edit removes or narrows still allow traffic, and the regression is not reported. Matching uses the policy labels Cilium's own parser attaches (kind, namespace, name), so a same-name policy in another namespace is never replaced.

### CI mode

For a pull-request check:

```
guardbee verdict -n myapp --replace-existing --fail-on-dropped --min-flows 20 --format markdown candidate.yaml
```

| Exit code | Meaning |
|---|---|
| `0` | No gate tripped |
| `1` | Error (cluster, Hubble or candidate) |
| `2` | `--fail-on-dropped`: at least one sampled flow is `NEWLY_DROPPED` |
| `3` | `--min-flows`: too few flows judged to call it a pass (a dropped flow outranks this) |

`--format json` prints the same object as the UI's `POST /api/verdict`, plus `candidate`, `replacedPolicies`, `judgedFlows`, `minFlows`, `result` (`pass`, `dropped` or `insufficient-flows`) and `exitCode`. `--format markdown` prints a summary ready to post as a PR comment: a status line, the counts, a table of changed rows, and unchanged rows in a collapsed section.

A pass only covers flows that were in Hubble's buffer at run time. Use `--min-flows` so a quiet namespace reads as inconclusive, not clean.

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
