---
layout: doc
title: Zero-trust walkthrough
description: Build an accumulative least-privilege CiliumNetworkPolicy from deny-all up in the Lab, proving each layer with Verdict and Connectivity Tests.
---

# Zero-trust walkthrough (accumulative policy)

The [Lab](lab.html) covers hardening an existing database without causing an
outage (`NEWLY_DROPPED`). This companion walkthrough covers the opposite
workflow: **starting a brand-new workload from full Default Deny (ingress +
egress)** and **accumulating least-privilege allow rules one layer at a time**,
verifying every layer with `NEWLY_ALLOWED` verdicts and live TCP/UDP
connectivity tests before applying it.

<section id="video" class="video-anchor">

<div class="demo-player" data-anchor="video">
  <div class="demo-player-bar">
    <span class="demo-player-dot"></span>
    <span class="demo-player-dot"></span>
    <span class="demo-player-dot"></span>
    <span class="demo-player-title">guardbee-zero-trust · accumulative policy &amp; probes</span>
  </div>
  <video class="demo-video" controls playsinline preload="metadata" poster="../assets/guardbee-zero-trust-poster.png">
    <source src="https://github.com/tchellomello/guardbee/releases/download/docs-media/guardbee-zero-trust.mp4" type="video/mp4">
    Your browser does not support the video tag.
  </video>
</div>

Direct link to this video: [Videos → Zero-trust](videos.html#zero-trust) or `#video` on this page.

</section>

## Prerequisites

Bring up the disposable Lab cluster (see [Lab Step 1](lab.html#step-1--bring-the-lab-up))
and start the web UI with connectivity tests enabled:

```
mise run lab-up
guardbee ui --enable-probes
```

All manifests for this walkthrough live in `lab/zero-trust/`.

---

## Step 1 — Deploy a new Pod and inspect its real traffic

Deploy `worker` (in its own `worker` namespace) alongside a small caller in
`webapp`:

```
kubectl apply -f lab/zero-trust/worker.yaml
kubectl -n worker rollout status deployment/worker
kubectl -n webapp rollout status deployment/worker-caller
```

`worker` connects to `postgres.postgres.svc.cluster.local:5432` every 4 seconds
and serves HTTP on `:8080`, while `worker-caller` hits `worker:8080` every 5
seconds. Deliberately, `worker` has no network `readinessProbe` so it remains
`Ready` during the deny-all lockdown and stays eligible as a Connectivity Test
source Pod.

Open **Flows**, set **Namespace** to `worker` and **Last** to `40`, and click
**Fetch flows** (or run `guardbee flows -n worker --last 40`). You'll see three
real paths:

- `worker → kube-system/coredns` on `UDP:53` (egress DNS)
- `worker → postgres/postgres` on `TCP:5432` (egress database)
- `webapp/worker-caller → worker` on `TCP:8080` (ingress HTTP)

---

## Step 2 — Lock it down with Default Deny (Ingress + Egress)

In **Policy Editor**, open **Presets & Starters ▾ → Default Deny (Isolation)**
(or load `lab/zero-trust/01-deny-all.yaml`), set the namespace to `worker`, and
select `app=worker` using **Pick From Cluster**.

Cilium enforces ingress and egress independently — blocking both directions
requires explicit `ingressDeny: - {}` and `egressDeny: - {}` rules, which the
preset generates for you.

Click **Test in Verdict Simulator** and run **Verdict** on namespace `worker`:
every observed path (`UDP:53`, `TCP:5432`, `TCP:8080`) reports `NEWLY_DROPPED`.

Now apply the lockdown live on this disposable Lab:

```
kubectl apply -f lab/zero-trust/01-deny-all.yaml
```

Verify isolation in the **Flows** tab: expand **Filters**, click the **Policy
drops** quick filter, and click **Fetch flows**. Hubble now reports live
`DROPPED` flows attributed to `CNP:worker/worker-policy`, and the **Policies**
tab lists `worker-policy` as enforced.

---

## Step 3 — Layer 1: Allow DNS egress (+ UDP connectivity probe)

> **Why DNS comes first:** When egress is completely denied, any connection or
> TCP probe targeting a Kubernetes Service hostname fails DNS lookup before
> emitting a TCP SYN. Open CoreDNS first so subsequent Service-name probes can
> resolve cleanly.

In **Verdict**, set **Namespace** to `worker`, keep **Replace matching live
policies** checked, expand **Filters** and click **Dropped** (asking: *which
currently blocked flows will this candidate newly allow?*), paste
`lab/zero-trust/02-allow-dns.yaml`, and click **Run verdict**.

<div class="expect" markdown="1">
<div class="expect-titlebar"><span class="expect-dot red"></span><span class="expect-dot yellow"></span><span class="expect-dot green"></span><span class="expect-label">Expected result</span></div>
<div class="expect-body" markdown="1">

```
NEWLY_ALLOWED  worker/worker-… -> kube-system/coredns-…  UDP:53
```

Ingress `:8080` stays untouched and blocked.

</div>
</div>

Prove it on demand with a **UDP Connectivity Test** inside the run card:

1. Expand **Connectivity tests** and keep **netshoot** selected (supports UDP).
2. Pick the `worker-…` **Source Pod**.
3. Set **Host or IP** to a CoreDNS backend Pod IP (from
   `kubectl -n kube-system get pod -l k8s-app=kube-dns -o jsonpath='{.items[0].status.podIP}'` —
   using a direct Pod IP skips DNS lookup while egress is denied and avoids
   Cilium socket-LB translating a raw ClusterIP before Hubble sees the flow),
   **Port** `53`, **Protocol** `UDP`.
4. Click **Review & run connection test** and confirm.

The path diagram shows **Baseline `BLOCKED` → Candidate `ALLOWED`** (`The
candidate would newly ALLOW this connection`). Apply Layer 1 live:

```
kubectl apply -f lab/zero-trust/02-allow-dns.yaml
```

---

## Step 4 — Layer 2: Accumulate Postgres egress (+ BusyBox TCP probe)

With DNS live, `worker` now resolves `postgres.postgres.svc.cluster.local` —
and Cilium drops its `TCP:5432` connections. Paste
`lab/zero-trust/03-allow-postgres.yaml` into **Verdict** (still filtered to
`Dropped`) and click **Run verdict**: only `worker → postgres TCP:5432` reports
`NEWLY_ALLOWED`.

Prove it with a **TCP Connectivity Test** on the run card:

1. Pick **BusyBox 1.37** (minimal ~2 MB digest-pinned image).
2. Pick the `worker-…` **Source Pod**.
3. **Host or IP:** `postgres.postgres.svc.cluster.local`, **Port:** `5432`, **Protocol:** `TCP`.
4. Click **Review & run connection test** and confirm.

The path diagram flips from red (`BLOCKED` today) to green (`ALLOWED` with the
candidate). Apply Layer 2 live:

```
kubectl apply -f lab/zero-trust/03-allow-postgres.yaml
```

---

## Step 5 — Layer 3: Accumulate Ingress on `:8080` (+ cross-pod probe)

Load `lab/zero-trust/04-allow-ingress.yaml` in **Verdict**, tick **All
namespaces**, filter **To → Label / entity** to `k8s:app=worker` (keeping
**Dropped** active), and click **Run verdict**: only
`webapp/worker-caller → worker TCP:8080` reports `NEWLY_ALLOWED`.

Prove cross-namespace ingress with a **Connectivity Test** from `webapp`:

1. Pick **BusyBox 1.37**.
2. **Source namespace:** `webapp`, **Source Pod:** `webapp-…`.
3. **Host or IP:** `worker.worker.svc.cluster.local`, **Port:** `8080`, **Protocol:** `TCP`.
4. Click **Review & run connection test** and confirm → **Baseline `BLOCKED` → Candidate `ALLOWED`**.

Apply the final policy live:

```
kubectl apply -f lab/zero-trust/04-allow-ingress.yaml
```

---

## Step 6 — Final audit and cleanup

Return to **Flows** (`worker`), click **Clear** on Filters, then click the
**Policy verdicts** quick filter and **Fetch flows**. All three expected paths
now show `FORWARDED` with `Decided by: allowed by CNP:worker/worker-policy`,
while every unlisted peer and port remains denied.

Clean up the extra workload when finished (or tear down the whole Lab with
`mise run lab-down`):

```
kubectl delete -f lab/zero-trust/worker.yaml
```
