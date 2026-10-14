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

> Most of `examples/*.yaml` are real catches, not made-up fixtures — but a
> real catch only means something on the cluster it came from. Run one as
> is anywhere else and it'll find nothing, not because the tool is broken,
> but because that exact regression doesn't exist on your traffic. They're
> here to show the *kind* of thing GuardBee catches — point `verdict` at
> your own namespace and candidate to see it catch one of yours.
>
> The `postgres-*.yaml` and `ccnp-postgres-*.yaml` ones are the
> exception: they're built against the [Lab](lab.html)'s own scenario, so
> they're guaranteed to match if you're running it —
> `guardbee verdict -n postgres examples/postgres-wrong-port.yaml` works
> as-is.

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
