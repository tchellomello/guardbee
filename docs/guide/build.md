---
layout: doc
title: Build
description: Building GuardBee with mise or plain Go.
---

# Build

## Quickstart (mise)

[mise](https://mise.jdx.dev) pins the exact Go and Node toolchains and
installs them if missing:

```
mise run build     # npm run build in ui/, then go build -o guardbee .
mise run check     # build + go vet + go test
mise run clean     # rm -f guardbee
mise run ui-dev    # frontend dev server, hot reload (proxies /api to
                    # a separately-running "guardbee ui" on :4747)
```

> `mise run build` always rebuilds the frontend first — the Go binary
> embeds whatever is currently in `ui/dist` via `go:embed` (see
> `embed.go`), so a stale `ui/dist` would silently ship an outdated UI
> otherwise.

---

## Plain Go

Build the frontend yourself once — `go:embed` requires `ui/dist` to
exist — then a plain `go build` works:

```
cd ui && npm install && npm run build
cd .. && go build -o guardbee .
```

> Built against `github.com/cilium/cilium@v1.20.2` as a plain Go
> dependency — including the internal `pkg/policy` engine, not just the
> generated clientset and Hubble's `observer` gRPC stubs. No eBPF/CGO/
> privileged build step required.

---

## Shell completions

Generated from `globals.go`'s `binName` by `scripts/gen-completions.sh`
(`mise run completions` to regenerate after a rename or a flag/subcommand
change):

```
# bash, in ~/.bashrc
source completions/guardbee.bash

# fish: or copy to ~/.config/fish/completions/
source completions/guardbee.fish

# zsh: anywhere on your $fpath, then `compinit`
cp completions/_guardbee ~/.zsh/completions/
```
