{
  description = "GuardBee — Cilium policy pre-flight simulator";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      # Matches `mise run build`'s dev-<short-sha>[-dirty] — a flake only
      # sees the commit, never the tag name, so a pinned release
      # (github:tchellomello/guardbee/v1.20.4-1) reports its commit too.
      version = "dev-${self.shortRev or self.dirtyShortRev or "unknown"}";
      guardbeeFor = pkgs: pkgs.callPackage ./nix/package.nix { inherit version; };
    in
    {
      packages = forAllSystems (pkgs: rec {
        guardbee = guardbeeFor pkgs;
        default = guardbee;
      });

      overlays.default = final: _prev: { guardbee = guardbeeFor final; };

      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}
