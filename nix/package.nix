# GuardBee built from source — the Nix equivalent of `mise run build`:
# the React UI first (ui/dist), then the Go binary that go:embeds it
# (embed.go). Same order and same reason as mise.toml's build task: a
# missing ui/dist fails the Go build outright, a stale one silently ships
# an outdated UI.
#
# The two hashes below pin the dependency sets Nix downloads ahead of the
# sandboxed (offline) build. They change whenever go.mod/go.sum or
# ui/package-lock.json do. `mise run nix-hashes` recomputes both;
# `mise run bump-cilium` runs it for you, and CI's "nix" job fails a PR
# whose hashes are stale — so a broken hash never reaches a user's
# `nixos-rebuild`.
{
  lib,
  buildGoModule,
  buildNpmPackage,
  nodejs_24,
  installShellFiles,
  version,
}:
let
  ui = buildNpmPackage {
    pname = "guardbee-ui";
    inherit version;
    src = lib.cleanSource ../ui;
    nodejs = nodejs_24;
    npmDepsHash = "sha256-el8ePqmxYZo8CCq6EtdYD0pBQ3/qINI8ygs/zfUN3bI=";
    installPhase = ''
      runHook preInstall
      cp -r dist $out
      runHook postInstall
    '';
  };
in
buildGoModule {
  pname = "guardbee";
  inherit version;
  src = lib.cleanSource ../.;

  vendorHash = "sha256-9DUp9HHV1+LGm9ZdzRGOn5N2MVhy1cq30bjsBJ0E3Fw=";

  subPackages = [ "." ];
  # Same as the release workflow: none of the embedded Cilium packages
  # need cgo, and a static binary has no runtime closure beyond itself.
  env.CGO_ENABLED = 0;
  ldflags = [
    "-s"
    "-w"
    "-X main.version=${version}"
  ];

  preBuild = ''
    rm -rf ui/dist
    cp -r ${ui} ui/dist
  '';

  # The test suite compiles Cilium's pkg/policy a second time for little
  # gain here — CI's "check" job already runs it on every PR, against the
  # exact same source.
  doCheck = false;

  nativeBuildInputs = [ installShellFiles ];
  postInstall = ''
    installShellCompletion --cmd guardbee \
      --bash completions/guardbee.bash \
      --fish completions/guardbee.fish \
      --zsh completions/_guardbee
  '';

  passthru = { inherit ui; };

  meta = {
    description = "Cilium policy pre-flight simulator: which real flows would a CiliumNetworkPolicy break or newly allow";
    homepage = "https://github.com/tchellomello/guardbee";
    license = lib.licenses.asl20;
    mainProgram = "guardbee";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
