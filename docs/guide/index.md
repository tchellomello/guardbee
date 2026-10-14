---
layout: doc
title: Guide
description: GuardBee documentation — commands, the verdict engine, building, and running against a real cluster.
---

# Guide

- **[Commands](commands.html)** — what `policies`, `flows`, `verdict`, `ui`,
  and `version` each do.
- **[How verdict works](how-it-works.html)** — the engine mechanics, known v1
  simplifications, and two real regressions it caught.
- **[Build](build.html)** — building with `mise` or plain Go.
- **[Run](run.html)** — RBAC, kubeconfig, and running each subcommand against
  a real cluster.
- **[Lab](lab.html)** — a self-paced, copy-paste lab that reproduces a real
  catch end-to-end on your own machine, no homelab cluster required.

See the repo's [`AGENTS.md`](https://github.com/tchellomello/guardbee/blob/main/AGENTS.md)
for architecture principles, known engine gotchas, and house style before
changing the verdict engine itself.
