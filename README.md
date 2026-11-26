<p align="center">
  <img src="docs/branding/guardbee-logo.png" alt="GuardBee" width="132" />
</p>

<h1 align="center">GuardBee</h1>

<p align="center">
  <b>Ship the policy. Not the outage.</b><br/>
  See which real flows a Cilium network policy would break <i>before</i> it merges.
</p>

<p align="center">
  <a href="https://github.com/tchellomello/guardbee/actions/workflows/ci.yml"><img src="https://github.com/tchellomello/guardbee/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/tchellomello/guardbee/releases/latest"><img src="https://img.shields.io/github/v/release/tchellomello/guardbee?label=release" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
</p>

<p align="center">
  <a href="https://tchellomello.github.io/guardbee/guide/lab.html"><b>Try the Lab</b></a> ·
  <a href="https://tchellomello.github.io/guardbee/guide/videos.html">Watch the demo</a> ·
  <a href="https://tchellomello.github.io/guardbee/guide/index.html">Docs</a> ·
  <a href="https://tchellomello.github.io/guardbee/">Website</a>
</p>

<p align="center">
  <a href="https://tchellomello.github.io/guardbee/guide/videos.html">
    <img src="docs/images/lab-04-verdict-regression.png" alt="GuardBee's Verdict view: a candidate policy that allows webapp but would silently drop Prometheus's scrape and kubelet's health probe, shown as red dashed edges" width="860" />
  </a>
</p>

---

A `CiliumNetworkPolicy` can pass review, pass CI and still take down
production. It might lock a database down to "just the app" and forget the
metrics exporter, or forget the kubelet health probe (`reserved:host`), or
DNS. Every one of those is valid YAML. Usually the first sign is a page.

**GuardBee replays your cluster's real recent traffic through Cilium's own
policy engine twice: once with today's policies, once with your
candidate added. Then it tells you what changes.**

```console
$ guardbee verdict -n postgres --last 50 looks-correct.yaml

NEWLY_DROPPED  observability/prometheus-xxxxx -> postgres/postgres-xxxxx
  TCP:9187  (currently allowed; this candidate would start blocking it)

NEWLY_DROPPED  reserved:host -> postgres/postgres-xxxxx
  TCP:5432  (currently allowed; this candidate would start blocking it)

50 flows sampled: 15 unchanged, 17 newly dropped, 0 newly allowed, ...

17 real flow(s) would BREAK if this candidate merged as-is —
review the NEWLY_DROPPED rows above before shipping it.
```

The candidate was never applied. GuardBee reads it as a file.

## Why you can trust the verdict

- **It runs Cilium's code, not a reimplementation.** GuardBee embeds Cilium's
  own `pkg/policy` engine, pinned to an exact Cilium release. The release tag
  names it, e.g. `v1.20.4-6`.
- **It judges real traffic.** The flows come straight from Hubble, from your
  own cluster. Nothing is synthetic.
- **It stays out of your cluster.** It's a single local binary that uses your
  kubeconfig. There's no in-cluster agent and no flow database, and it's
  read-only by default.
- **It tells you what it can't judge.** Anything it can't simulate faithfully
  is named, never guessed. For example, live policies using
  `fromNodes`/`toNodes` are skipped with a warning (Hubble flows carry no node
  labels), and a Kubernetes `NetworkPolicy` in a candidate file is listed
  under "Not judged" (only CNP and CCNP are judged). [Known limits →](https://tchellomello.github.io/guardbee/guide/how-it-works.html)

## Get started

**1. Install:** grab a [release binary](https://github.com/tchellomello/guardbee/releases/latest) (Linux and macOS, amd64 and arm64), or use Nix:

```sh
nix run github:tchellomello/guardbee -- version
```

**2. No cluster handy?** The [Lab](https://tchellomello.github.io/guardbee/guide/lab.html)
brings up a local kind cluster with Cilium and reproduces the regression
above, step by step:

```sh
git clone https://github.com/tchellomello/guardbee && cd guardbee
mise run lab-up
```

**3. On your own cluster** (Hubble Relay enabled, read-only RBAC in
[`kubernetes/rbac.yaml`](kubernetes/rbac.yaml)):

```sh
guardbee verdict -n my-app my-candidate.yaml   # what would this break?
guardbee ui                                     # same engine, in the browser
```

## What's in the box

| Command | What it answers |
|---|---|
| [`verdict`](https://tchellomello.github.io/guardbee/guide/commands.html#verdict) | Which real flows would this candidate newly drop or newly allow? |
| [`blame`](https://tchellomello.github.io/guardbee/guide/commands.html#blame) | Which live policy (or default deny) allowed or dropped this pod's traffic? |
| [`flows`](https://tchellomello.github.io/guardbee/guide/commands.html#flows) | What traffic is actually hitting this namespace? Filters follow hubble's flag names. |
| [`policies`](https://tchellomello.github.io/guardbee/guide/commands.html#policies) | Which CNPs and CCNPs are live right now? |
| [`ui`](https://tchellomello.github.io/guardbee/guide/commands.html#ui) | All of the above in a local web UI with a graph-based policy editor. It calls the exact same functions as the CLI. |

`verdict` also handles L7 rules: it judges each DNS query and HTTP request
Hubble recorded, and it handles `toFQDNs` candidates before they're live.
`guardbee ui --enable-probes` adds opt-in, bounded
[TCP/UDP connectivity tests](https://tchellomello.github.io/guardbee/guide/tcp-probes.html).
That flag is the only feature that changes anything in the cluster.

### Gate pull requests in CI

```sh
guardbee verdict -n my-app --fail-on-dropped --min-flows 20 --format markdown candidate.yaml
```

The command exits non-zero if a real flow would break, and `--format markdown`
prints a summary you can post as a PR comment.
[A ready-made GitHub Actions workflow →](https://tchellomello.github.io/guardbee/guide/ci.html) · [Exit codes and JSON output →](https://tchellomello.github.io/guardbee/guide/commands.html#ci-mode)

## Documentation

| | |
|---|---|
| [Quickstart](https://tchellomello.github.io/guardbee/guide/quickstart.html) | Catch a real regression on a local kind cluster in about ten minutes |
| [Install](https://tchellomello.github.io/guardbee/guide/install.html) | Release binaries, Nix flake (NixOS, Home Manager), versioning |
| [Run on your cluster](https://tchellomello.github.io/guardbee/guide/run.html) | Prerequisites, read-only RBAC, kubeconfig |
| [Gate PRs in CI](https://tchellomello.github.io/guardbee/guide/ci.html) | A copy-paste GitHub Actions workflow that comments and fails on regressions |
| [Lab](https://tchellomello.github.io/guardbee/guide/lab.html) · [Lab extras](https://tchellomello.github.io/guardbee/guide/lab-extras.html) · [Zero-trust walkthrough](https://tchellomello.github.io/guardbee/guide/zero-trust-walkthrough.html) | Hands-on: the full regression story, then connectivity tests, L7 rules, `toFQDNs`, and least privilege from default deny |
| [Commands](https://tchellomello.github.io/guardbee/guide/commands.html) | Every subcommand and flag |
| [How it works](https://tchellomello.github.io/guardbee/guide/how-it-works.html) · [FAQ](https://tchellomello.github.io/guardbee/guide/faq.html) | The engine, its known limits, how it differs from hubble, dry-run and audit mode |
| [Build from source](https://tchellomello.github.io/guardbee/guide/build.html) | `mise` or plain Go |

## Contributing

Issues and PRs are welcome. Before you make a non-trivial change to the engine
(`verdict.go`), read [`AGENTS.md`](AGENTS.md) for the architecture
principles, the known Cilium-internals gotchas and the house style.

## License

[Apache License 2.0](LICENSE)
