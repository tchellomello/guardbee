---
layout: doc
title: Videos
description: Direct-linkable GuardBee walkthrough videos — full feature overview and the accumulative zero-trust policy lab.
---

# Videos

Shareable browser-ready walkthroughs recorded live against the self-paced
[Lab](lab.html) cluster (Cilium `v1.20.4` + Hubble Relay). Every player below
has a stable `#hash` anchor and a **Copy link** button in its title bar so you
can send someone straight to a specific video without making them click around.

- **[Full GuardBee walkthrough](#overview)** — Light → Dark themes, Flows & filtering, Policy Editor, Verdict regressions, Connectivity tests, L7 HTTP/DNS, and `toFQDNs`.
- **[Accumulative zero-trust policy walkthrough](#zero-trust)** — Deploy a new Pod, lock down all ingress + egress with Default Deny, verify `Policy drops`, and incrementally allow DNS (UDP probe), Postgres (TCP probe), and Ingress (cross-pod TCP probe).

---

<section id="overview" class="video-anchor">

## Full GuardBee walkthrough

Reproduces the [Lab](lab.html) scenario end to end: observing live traffic in
**Flows**, switching between Light and Dark themes, filtering in Hubble Relay,
authoring in **Policy Editor** with cluster-grounded labels, catching silent
`NEWLY_DROPPED` regressions in **Verdict**, proving a scrape with an opt-in
**Connectivity test**, repairing with one-click `+ Add to Policy`, and judging
**L7 HTTP**, **L7 DNS**, and **`toFQDNs`** rules.

<div class="demo-player" data-anchor="overview">
  <div class="demo-player-bar">
    <span class="demo-player-dot"></span>
    <span class="demo-player-dot"></span>
    <span class="demo-player-dot"></span>
    <span class="demo-player-title">guardbee-demo · full lab walkthrough</span>
  </div>
  <video class="demo-video" controls playsinline preload="metadata" poster="../assets/guardbee-demo-poster.png">
    <source src="https://github.com/tchellomello/guardbee/releases/download/docs-media/guardbee-demo.mp4" type="video/mp4">
    <source src="https://github.com/tchellomello/guardbee/releases/download/docs-media/guardbee-demo.webm" type="video/webm">
    Your browser does not support the video tag.
  </video>
</div>

Follow along locally with [Lab](lab.html).

</section>

---

<section id="zero-trust" class="video-anchor">

## Building an accumulative zero-trust policy

Walks through locking down a brand-new `worker` Pod from **Default Deny
(ingress + egress)** up, proving each allowed layer before applying it live:
inspecting baseline flows, verifying isolation with **Policy drops**, allowing
**DNS egress** first (proved with a `netshoot` **UDP** probe), accumulating
**Postgres egress** (`BusyBox 1.37` **TCP** probe), opening explicit **Ingress**
on `:8080` (cross-pod **TCP** probe), and auditing the final **Policy verdicts**.

<div class="demo-player" data-anchor="zero-trust">
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

Follow along step by step in the [Zero-trust walkthrough](zero-trust-walkthrough.html).

</section>
