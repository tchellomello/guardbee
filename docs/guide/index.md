---
layout: doc
title: Guide
description: GuardBee documentation — commands, the verdict engine, building, and running against a real cluster.
---

# Guide

- **[Install](install.html)** — release binaries, or the Nix flake for NixOS,
  Home Manager and `nix profile`.
- **[Commands](commands.html)** — what `policies`, `flows`, `blame`,
  `verdict`, `ui`, `version` and `compat` each do.
- **[How verdict works](how-it-works.html)** — the engine mechanics, known v1
  simplifications, and two real regressions it caught.
- **[Build](build.html)** — building with `mise` or plain Go.
- **[Run](run.html)** — RBAC, kubeconfig, and running each subcommand against
  a real cluster.
- **[Connectivity tests](tcp-probes.html)** — explicitly authorized, bounded traffic
  generation through an ephemeral container in an existing workload Pod.
- **[Lab](lab.html)** — a self-paced, copy-paste lab that reproduces a real
  catch end-to-end on your own machine, no cluster of your own required.
- **[Zero-trust walkthrough](zero-trust-walkthrough.html)** — build an
  accumulative least-privilege policy from full Default Deny up in the Lab,
  proving every layer with `NEWLY_ALLOWED` verdicts and live TCP/UDP probes.
- **[Videos](videos.html)** — direct-linkable showcase videos (full Lab
  walkthrough and zero-trust accumulative walkthrough).
