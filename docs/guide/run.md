---
layout: doc
title: Run
description: RBAC, kubeconfig, and running GuardBee's subcommands against a real cluster.
---

# Run

Needs a kubeconfig with read access to your cluster — either your own, or
a dedicated service account scoped with `kubernetes/rbac.yaml` (this
repo):

| Scope | Access |
|---|---|
| CNPs, CCNPs, `CiliumIdentity`, `CiliumEndpoint`, namespaces | `get`/`list`/`watch` |
| `cilium-system` (for `hubble-relay`) | pod `get`/`list` + port-forward |

> Nothing GuardBee does writes to the cluster.

---

## Commands

```
export KUBECONFIG=/path/to/kubeconfig
./guardbee policies -n your-namespace
./guardbee flows -n your-namespace --last 20
./guardbee policies --all-namespaces
./guardbee verdict -n your-namespace --last 50 your-candidate.yaml
./guardbee ui
```

> `examples/*.yaml` are real catches from the author's own homelab cluster
> — they won't find matching traffic on a *different* cluster. They're
> there to show the kind of regression GuardBee catches, not to run as-is
> against your own. Point `verdict` at your own namespace and candidate
> instead.

---

## Flag conventions

Flag naming follows [hubble CLI](https://github.com/cilium/cilium/tree/main/hubble)'s
own conventions wherever this tool overlaps with it, so anyone who already
knows hubble doesn't have to relearn a different style here:

| Flag | Meaning |
|---|---|
| `-n`, `--namespace` | One namespace |
| `-A`, `--all-namespaces` | Every namespace |
| `-f`, `--follow` | Keep tailing until Ctrl+C |
| `--last` | Ceiling on flows fetched |
