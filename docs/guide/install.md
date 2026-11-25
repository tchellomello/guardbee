---
layout: doc
title: Install
description: Installing GuardBee from a release binary or with Nix (NixOS, Home Manager, nix profile).
---

# Install

GuardBee is a single static binary, and the web UI is embedded in it. Pick one way to install it:

- [Release binary](#release-binary): Linux or macOS, nothing to build.
- [Nix flake](#nix-flake): NixOS, Home Manager, or any machine with Nix.
- [From source](build.html): `mise` or plain Go.

Every option gives you the same binary. Check it with:

```
guardbee version
```

---

## Release binary

Each [release](https://github.com/tchellomello/guardbee/releases) has tarballs for `linux` and `darwin` on `amd64` and `arm64`, plus a `SHA256SUMS` file:

```
VERSION=v1.20.4-1   # see the releases page for the latest
OS=linux ARCH=amd64 # or darwin / arm64
curl -LO https://github.com/tchellomello/guardbee/releases/download/${VERSION}/guardbee_${VERSION}_${OS}_${ARCH}.tar.gz
curl -LO https://github.com/tchellomello/guardbee/releases/download/${VERSION}/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf guardbee_${VERSION}_${OS}_${ARCH}.tar.gz
install -m 0755 guardbee-${OS}-${ARCH} ~/.local/bin/guardbee
```

Each tarball also has a signed build provenance attestation, proving it was built by this repo's release workflow. With the [GitHub CLI](https://cli.github.com):

```
gh attestation verify guardbee_${VERSION}_${OS}_${ARCH}.tar.gz --repo tchellomello/guardbee
```

The tarball also contains shell completions in `completions/`. Install the one for your shell:

```
# fish
install -Dm0644 completions/guardbee.fish ~/.config/fish/completions/guardbee.fish
# bash
install -Dm0644 completions/guardbee.bash ~/.local/share/bash-completion/completions/guardbee
# zsh: any directory on your $fpath, then run compinit
install -Dm0644 completions/_guardbee ~/.zsh/completions/_guardbee
```

The tarballs of `v1.20.4-1` and earlier don't include completions. For those, take the files from the repo instead (see [Build → Shell completions](build.html#shell-completions)).

---

## Nix flake

The repository is a flake. It builds GuardBee from source, including the embedded UI, and installs the binary along with its bash, fish and zsh completions. The first install compiles for a few minutes because there is no binary cache.

### Try it without installing

```
nix run github:tchellomello/guardbee -- version
```

### NixOS

Add the flake as an input to your system flake, then add the package:

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    guardbee = {
      url = "github:tchellomello/guardbee";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, guardbee, ... }: {
    nixosConfigurations.my-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./configuration.nix
        ({ pkgs, ... }: {
          environment.systemPackages = [
            guardbee.packages.${pkgs.stdenv.hostPlatform.system}.default
          ];
        })
      ];
    };
  };
}
```

Then run `sudo nixos-rebuild switch --flake .#my-host`.

You can also use the overlay, which makes the package available as `pkgs.guardbee`:

```nix
nixpkgs.overlays = [ guardbee.overlays.default ];
environment.systemPackages = [ pkgs.guardbee ];
```

### Home Manager

Use the same input as above, and add the package to `home.packages`:

```nix
home.packages = [ inputs.guardbee.packages.${pkgs.stdenv.hostPlatform.system}.default ];
```

### nix profile (no system config)

```
nix profile install github:tchellomello/guardbee
nix profile upgrade guardbee    # later, to update
```

### Latest `main` or a release

The input URL decides what you get:

| `url =` | You get |
|---|---|
| `github:tchellomello/guardbee` | The latest `main`, which updates on `nix flake update guardbee` |
| `github:tchellomello/guardbee/v1.20.4-1` | Exactly that release, which never changes until you edit the URL |

To update after that, run:

```
nix flake update guardbee
sudo nixos-rebuild switch --flake .#my-host
```

A flake sees the commit, not the tag name. So a Nix build reports `dev-<commit>` for `guardbee version`, even when the input is pinned to a release tag. The `cilium engine` line is the same as for a release binary.

### About `inputs.nixpkgs.follows`

With `follows`, GuardBee builds with your system's Go and Node instead of downloading a second nixpkgs. This works as long as your nixpkgs' Go is at least the `go` version in [`go.mod`](https://github.com/tchellomello/guardbee/blob/main/go.mod). If an older nixpkgs (for example, an older stable release) fails to build with a Go version error, remove the `follows` line. GuardBee then builds with the nixpkgs it pins in its own `flake.lock`.
