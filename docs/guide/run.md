---
layout: doc
title: Run on your cluster
description: RBAC, kubeconfig, and running GuardBee's subcommands against a real cluster.
---

# Run on your cluster

## Before you start

- **Hubble and Hubble Relay enabled.** `flows`, `blame` and `verdict` read real traffic from Hubble Relay. GuardBee port-forwards to its pods (label `k8s-app=hubble-relay`, gRPC port 4245) in the namespace Cilium is installed in: **`kube-system`** by default, Cilium's own default.
- **Cilium in another namespace** (`cilium-system` is common)? Pass `--hubble-namespace`. It also tells GuardBee where to read `cilium-config`:

  ```
  guardbee verdict -n myapp --hubble-namespace cilium-system candidate.yaml
  ```

  Every command that reaches Relay takes it, including `policies`, `ui` and `version`, which use it for the version-skew check. If you apply `kubernetes/rbac.yaml`, change its two `namespace: kube-system` lines to match.

- **A kubeconfig with read access** to your cluster — either your own, or
  a dedicated service account scoped with `kubernetes/rbac.yaml` (this
  repo):

| Scope | Access |
|---|---|
| CNPs, CCNPs, `CiliumIdentity`, `CiliumEndpoint`, namespaces | `get`/`list`/`watch` |
| Services (all namespaces) | `get` (connectivity tests resolve a Service target) + `list` (the test's Host suggestions; without it the UI suggests Services seen in flows) |
| Kubernetes `NetworkPolicy` inventory (all namespaces) | `list` for connectivity simulation completeness checks |
| Cilium's namespace, `kube-system` by default (for `hubble-relay`) | pod `get`/`list` + port-forward. In `kube-system` that reaches every pod there; to avoid it, reach Relay's Service with `--hubble-addr` instead and drop these two rules |
| `cilium-config` ConfigMap only, in Cilium's namespace | `get`, read when judging HTTP requests, to check whether Hubble redacts URL queries (without it, HTTP requests are left unjudged) |

<div class="guarantee" markdown="1">

Default GuardBee commands do not change workload or policy objects. The optional connectivity-test
backend is a deliberate exception, disabled unless the UI is started with
`--enable-probes` and given additional RBAC.

</div>

---

## Commands

```
export KUBECONFIG=/path/to/kubeconfig
./guardbee policies -n your-namespace
./guardbee flows -n your-namespace --last 20
./guardbee policies --all-namespaces
./guardbee blame your-namespace/your-pod --verdict DROPPED
./guardbee verdict -n your-namespace --last 50 your-candidate.yaml
./guardbee ui
./guardbee compat
```

### Optional connectivity tests in Verdict

```sh
./guardbee ui --addr 127.0.0.1:4747 --enable-probes
```

The UI offers the built-in vetted probe images (netshoot for TCP and UDP,
BusyBox for TCP) to pick from; `--probe-images-file` replaces that list, and
`--probe-image` offers exactly one image. Read [connectivity-test safety and image requirements](tcp-probes.html) first.
Load the candidate in Verdict, then expand **Connectivity tests** to generate
TCP traffic or one fixed UDP datagram from a selected workload Pod. The headline
compares baseline and candidate decisions; traffic-generation outcomes are
supporting evidence, not policy predictions. A UDP send is not reachability.
`kubernetes/probes-rbac.yaml` provides a separately reviewed namespace-scoped
optional grant, not part of the default read-only RBAC. Each probe adds an
immutable ephemeral entry to an existing running Pod; it cannot be removed or
restarted, and remains until that Pod is replaced. GuardBee never deletes or
restarts Pods. Writes require numeric-loopback binding, same-origin JSON POST,
and explicit per-request UI confirmation; no arbitrary command or shell API
is exposed. An nc failure is not itself a policy deny.

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
