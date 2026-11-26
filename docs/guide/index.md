---
layout: doc
title: Guide
description: GuardBee documentation — quickstart, running against your cluster, gating pull requests in CI, commands, and how the verdict engine works.
---

# GuardBee docs

GuardBee tells you which real flows on your cluster a CiliumNetworkPolicy would break or newly allow, before it merges — judged by Cilium's own policy engine, against traffic Hubble actually saw.

## Start here

<div class="guide-grid">
<a class="guide-card" href="quickstart.html"><strong>Quickstart</strong><span>Watch it catch a real regression on a disposable local cluster. About ten minutes, no cluster of your own needed.</span><em>Try it →</em></a>
<a class="guide-card" href="run.html"><strong>Run on your cluster</strong><span>Prerequisites, read-only RBAC, and your first verdict against real traffic.</span><em>Set up →</em></a>
<a class="guide-card" href="ci.html"><strong>Gate PRs in CI</strong><span>Fail a pull request when a policy change would break real flows, and post the verdict as a comment.</span><em>Automate →</em></a>
</div>

## All pages

| Get started | Use it | Understand it |
|---|---|---|
| [Quickstart](quickstart.html) | [Run on your cluster](run.html) | [How it works](how-it-works.html) |
| [Install](install.html) | [Gate PRs in CI](ci.html) | [FAQ](faq.html) |
| [Lab](lab.html) · [Lab extras](lab-extras.html) | [Connectivity tests](tcp-probes.html) | [Commands](commands.html) |
| [Zero-trust walkthrough](zero-trust-walkthrough.html) | | [Build from source](build.html) |
| [Videos](videos.html) | | |

> New to it? The [Quickstart](quickstart.html) and the [Videos](videos.html) show the whole idea in a few minutes. Deciding whether it fits your team? Start with [How it works](how-it-works.html) and the [FAQ](faq.html).
