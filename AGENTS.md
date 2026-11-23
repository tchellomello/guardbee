# GuardBee

Cilium policy pre-flight simulator. Answers one question before a
`CiliumNetworkPolicy`/`CiliumClusterwideNetworkPolicy` merges: **which real
flows on this cluster would it break or newly allow?**

Go CLI + embedded local web UI. No in-cluster agent, no persisted flow store.

This file covers code-level facts: architecture, known engine gotchas, build/
test, and house style. If a `AGENTS.local.md` exists next to this file
(gitignored — personal notes, not published), read that too.

## What this actually is

- `guardbee policies [-n <ns>|-A]` — lists live CNPs (namespaced) + CCNPs
  (cluster-wide) via the generated Cilium clientset. Pure read, proves RBAC.
- `guardbee flows [-n <ns>|-A] [filters] [--last N] [-f]` — port-forwards to
  `hubble-relay` (`cilium-system` namespace) and streams real flows via
  Hubble's `Observer.GetFlows` gRPC API. Filters (`--pod`/`--from-*`/
  `--to-*`/`--verdict`/`--drop-reason-desc`/`--type`, hubble's names) are
  `flowFilter` in `flows.go`, shared by `blame`, `verdict` and the UI, and
  applied in Hubble's query.
- `guardbee blame [[ns/]pod] [-n <ns>|-A] [filters] [--last N] [-f]` — which
  live policy allowed or denied real flows. `flows` defaulted to
  `--type policy-verdict`, plus the attribution Cilium's agent attached
  (`flowAttribution` in `blame.go`, also on every UI Flows row). Read off
  Hubble, not computed by the embedded engine — see v1 simplifications.
- `guardbee verdict [-n <ns>|-A] [--last N] [-f] <candidate.yaml>` — the
  actual engine. Judges real recent flows twice (baseline live policy vs.
  baseline+candidate) using **Cilium's own `pkg/policy` engine** — not a
  reimplementation — and prints `NEWLY_DROPPED`/`NEWLY_ALLOWED`/`UNCHANGED`.
- `guardbee ui [--addr host:port]` — milestone 1 web UI: a local HTTP server
  exposing the exact same `computeVerdictWithMode`/`fetchFlows`/`flowAttribution` functions the CLI
  calls, over JSON, for a React/TS frontend. No parallel implementation —
  UI and CLI can't disagree on a verdict for the same input, only present it
  differently.

All five are read-only against the cluster by default. The UI's explicit
`--enable-probes` opt-in is the exception (images come from a server-side
catalog — built-in `probes/images.yaml`, `--probe-images-file`, or one
`--probe-image` — that the browser picks from by id, never by reference):
bounded TCP/UDP connectivity tests in Verdict append a restricted ephemeral
container to an existing Pod. UDP emission alone never proves reachability.
They never change workload labels, apply a candidate, or delete/restart Pods.
Terminated entries remain until normal Pod replacement. See
`docs/guide/tcp-probes.md` and the separate `kubernetes/probes-rbac.yaml`.
Probe simulation must withhold conclusions for unverified agent-side semantics
or incomplete capture; do not replace Cilium's engine with a custom matcher.

## Architecture principle that overrides convenience

**The whole trust model rests on embedding Cilium's actual `pkg/policy`
engine** (`ResolvePolicy`/`DistillPolicy`/`EndpointPolicy.Lookup`, plus the
generated `.Parse()` conversions for CNP/CCNP), pinned to the cluster's exact
Cilium version (`go.mod`: `github.com/cilium/cilium v1.20.4`). A verdict from
this tool must be a verdict from Cilium's own code, never this project's
guess at Cilium's semantics.

Consequences that follow directly from this, non-negotiably:
- Never hand-roll policy-matching logic that duplicates what `pkg/policy`
  already does — call the real engine, even when it's less convenient.
- The internal Go packages this embeds (`pkg/policy`, `pkg/identity`, etc.)
  carry **no stability guarantee** across Cilium versions — they're agent
  implementation details, not a public API. Real bugs have already come
  from exactly this (see "Gotchas already hit" below). Any Cilium version
  bump needs the full `mise run check` pass plus live re-validation against
  the real cluster, not just `go get` — and before touching `go.mod`, run
  `mise run compat-scan <old-pin> <new-pin>` (see `compat.go`) to find any
  CRD-schema-level divergence (removed/deprecated fields) the new pin would
  otherwise silently stop detecting or start silently dropping. It's a
  report, not a generator — read each finding against the real source and
  add a `featureGates` entry with a real "why" for anything genuine.
  `mise run bump-cilium <vX.Y.Z>` does the mechanical part (compat-scan
  report, go.mod + `pinnedCiliumVersion` + lab `CILIUM_VERSION`, then
  `check`); `--lab` adds `mise run lab-validate` (fresh lab, asserts the
  lab candidates' known exit codes, tears it down). The gate review and a
  verdict against the real cluster stay manual.
  `pin_test.go` fails if those three pins ever disagree.
- The engine is pinned to one Cilium version (`pinnedCiliumVersion`,
  `globals.go`), but is meant to stay usable against clusters running
  somewhat older versions too (currently targeting 1.18–1.20). The cluster's
  actual running version is detected at runtime (`clusterversion.go`, over
  the existing hubble-relay connection) and surfaced two ways: a skew
  warning (CLI stderr / UI banner) when it differs from the pin, and
  `compat.go`'s `featureGates` table, which hard-rejects a candidate using a
  construct that's deprecated-or-removed as of the pin rather than silently
  computing a verdict that misrepresents what it does. `GET /api/compat` /
  `guardbee compat` / the UI's Compatibility modal (header icon, next to
  GitHub/homepage/theme) list the table itself, so
  "why was this rejected" doesn't have to be reverse-engineered from the
  error text.

### Gotchas already hit (don't rediscover these)

- **Dual selector-cache gotcha.** `policy.Repository` has *two separate*
  selector caches — `GetSelectorCache()` (peer matching: `FromEndpoints`/
  `ToEndpoints` against remote identities) and an internal
  `subjectSelectorCache` (matching a rule's own `EndpointSelector` against
  the identity being resolved). Both must be told about identities
  independently. Missing the second call doesn't error — it silently makes
  every rule's `EndpointSelector` fail to match anything, so the rule has
  zero effect and `DistillPolicy` falls back to
  default-deny-with-reserved-identity-exceptions, which *looks* like a
  working result but is wrong.
- **`Get`-vs-default-allow bug.** A naive `epp.Get(key)` check treats "no
  explicit MapState entry" as always-deny. Wrong for the overwhelmingly
  common case — a workload with *no* CNP at all is fully default-allow, not
  default-deny. Fixed via `isAllowed()` falling back to
  `epp.SelectorPolicy.IngressPolicyEnabled`.
- **No proxy ports = no L7 entries.** `DistillPolicy` with an empty
  redirects map silently omits the MapState entry of every L7-ruled port
  (nothing to redirect to), so `isAllowed` read HTTP/DNS-ruled traffic as
  default-deny → false `NEWLY_DROPPED`. `distillFor` passes one placeholder
  `policy.FallbackRedirectID` port so those entries come back as
  allow + `IsRedirectEntry()`. Regression suite: `verdict_l7_test.go`.
- **Identity minimum.** Hand-picked numeric identities must be
  `>= identity.MinimalNumericIdentity` (256) — lower values are reserved for
  Cilium's own special identities.
- **Node-scoped identities collide cluster-wide.** Local-scope (CIDR/world,
  `1<<24`+) and remote-node-scope identity numbers are allocated per node's
  agent, and hubble-relay merges all nodes' flows — the same number can be
  the kube-apiserver on one node and a plain CIDR on another. Keying the
  engine by number (first-seen labels win) made verdicts depend on which
  nodes' flows were sampled (`--all-namespaces` showed 0 dropped while `-n`
  showed the drop). `engineNID` in `verdict.go` gives these a synthetic
  number per label set; global/reserved ones keep their real number.
- **Hubble buffer semantics.** `GetFlows` samples a shared, cluster-wide
  bounded ring buffer, not a per-namespace one — counts drift run-to-run;
  this is what the `--last`-is-a-ceiling behavior above is actually about.
- **Relay's `Number` is per node.** hubble-relay forwards
  `GetFlowsRequest.Number` to every node and merges the replies, so
  `--last 50` on a 4-node cluster came back with up to 200 flows ("200/50
  flows sampled"). `fetchFlows` keeps the newest N (`newestFlows`);
  `--follow`'s initial backlog can't be trimmed the same way and may be
  up to N per node.

## Known v1 simplifications (intentional, documented in code — don't "fix" silently)

- A flow must be allowed by **both** the destination's ingress policy and the
  source's egress policy. Egress is judged on identities/CIDRs/entities/ports.
  Cilium's name manager adds `fqdn:<selector>` labels only for selectors
  already in a LIVE policy, so `withFQDNLabels` (`fqdnverdict.go`) labels the
  engine's copy of a world/CIDR destination for every baseline or candidate
  selector whose `FQDNSelector.ToRegex()` matches one of the flow's
  `destination_names`: namemanager's `deriveLabelsForName` loop, with
  Cilium's own regex and `IdentityLabel()`. A labelled `reserved:world` gets
  a local-scope engine number per label set (`engineNID`), so two names
  behind identity 2 never share labels. `destination_names` are the SOURCE
  endpoint's DNS history (the name manager uses every endpoint's); and they
  exist only when the source's DNS goes through the DNS proxy, so a flow
  without them that a `toFQDNs` candidate would drop on egress is
  `NOT_SIMULATED`, not a guessed drop. Regression suite:
  `fqdnverdict_test.go`; live: `lab/fqdn/` in `lab-validate.sh`.
- A live baseline policy using `fromNodes`/`toNodes` is **skipped**, named in
  the UI banner / CLI stderr warning, not simulated (`fetchBaselineRules`).
  Cilium's `Parse()` rejects it unless the process-global
  `enable-node-selector-labels` is set; setting it would parse the policy but
  make it match nothing, since Hubble flows carry no node labels — a quietly
  wrong verdict. Verdicts therefore ignore those rules. `Parse()` flattens
  that error to a string, so it is matched by message, not `errors.Is`.
- **DNS queries and HTTP requests are judged per request.** A Hubble DNS request
  record behind the DNS proxy on either side is judged per query name like
  the DNS proxy would (`dnsverdict.go`), yielding NEWLY_DROPPED/
  NEWLY_ALLOWED/UNCHANGED with the query named. `pkg/fqdn/dnsproxy` itself
  can't be imported (Linux-only datapath code breaks the darwin release
  builds), so the pattern semantics come from Cilium's portable
  `pkg/fqdn/matchpattern` and only `GeneratePattern` + `CheckAllowed`'s loop
  are ported; `dnsverdict_conformance_test.go` (Linux build tag) compares the
  port against the real dnsproxy, so keep it passing on every Cilium bump.
  A Hubble HTTP request record is judged against the exact Envoy rules
  Cilium's translator produced (`PerSelectorPolicy.EnvoyHTTPRules()`), but
  the matching is GuardBee's (`httpverdict.go`, following Envoy v1.37.5's
  header_utility and cilium/proxy's network_policy.cc, since both are C++),
  so those rows are marked "matched by GuardBee, not Envoy" and carry
  `l7Judge: "guardbee"` in JSON. Outside the modelled subset (deny/pass or
  mixed-precedence rules, listeners, SNI, secret-backed headerMatches, a
  redacted header the rule reads) a request is not judged and the row says
  so. Hubble's `hubble-redact-http-urlquery` removes queries without a
  trace and Cilium's path rules match the query, so `newHTTPGate` reads
  `cilium-config` once (RBAC: get on that one ConfigMap) and turns HTTP
  judging off when query redaction is on or the ConfigMap is unreadable.
  Cilium's translator comment says its "secret fetch failed" matcher (exact
  "" inverted) never matches; in Envoy 1.37.5 it matches any non-empty
  value, one reason secret rules are never judged.
  Any other flow behind the proxy (a connection-level flow without an L7
  record) is only compared on its rules: allowed at L4 on both sides under
  different L7 rules → `L7_CHANGED`, naming both rule sets (`l7RulesFor`).
  Response records count as replies.
- A flow's identities must already be real and currently allocated (resolved
  directly off Hubble's `Endpoint.Identity`). Candidate labels with no
  matching live pod are simply never exercised — this tool never invents a
  fake identity.
- Reply packets of established connections are skipped — connection
  tracking always allows those regardless of CNP ingress rules.
- `--last` is a **ceiling, not a guarantee**: Hubble relay's flow buffer is
  a small, fixed-size ring for the *whole cluster*, not scoped to one
  namespace. Getting fewer flows than requested is expected, not a bug.
  `--follow`/`-f` is the real lever for more volume over time, not raising
  `--last`.
- `blame`'s attribution is **Hubble's, not the embedded engine's**: it's
  the rule labels the agent's own `pkg/policy/correlation` attached to a
  policy-verdict event, read back exactly as that code writes them
  (`flowAttribution`). Correlation can silently fail (no port, endpoint
  gone, correlation disabled), so a missing attribution is shown as "not
  attributed", never guessed: an unattributed `POLICY_DENY` is still a deny
  rule (not default deny), an unattributed allow is not "no policy selects
  it". Computing attribution from the engine (`epp.Lookup`'s rule metadata)
  for flows Hubble didn't attribute is a possible follow-up, not done.
- `--pod` may be combined with `--from-pod`/`--to-pod`/`--to-ip`, which
  hubble observe rejects as conflicting; every field simply ANDs.
- A TCP/UDP flow with **destination port 0** is `NOT_SIMULATED`, not judged.
  `isAllowed`'s `policy.Key` query must have a non-wildcard port (Cilium's
  own `mapState.lookup()` doc comment says so explicitly) — querying with
  port 0 doesn't error, but the ancestor-LPM walk then only matches other
  full-wildcard-port entries, silently missing any specific-port rule. Seen
  on real clusters for UDP flows Hubble reports with `DestinationPort` 0.

## Repo layout

```
main.go           entry point, subcommand dispatch, --help text
globals.go        binName (single source of truth for the binary's name — see below)
kube.go           shared flags (--namespace/-n, --all-namespaces/-A, --kubeconfig), clientset wiring
policies.go       `policies` subcommand
flows.go          `flows` subcommand (hubble-relay port-forward + GetFlows) and `flowFilter`, the filter flags shared with `blame`/`verdict`/the UI
blame.go          `blame` subcommand, `flowAttribution` (Hubble's policy attribution, read the way pkg/policy/correlation writes it) and `flowOut`, the flow row shared with the UI
verdict.go        `verdict` subcommand — the core engine (690 lines, read this first for engine changes)
templates.go      Policy Editor "preset" templates, loaded from templates/*.yaml, not hardcoded data
ui.go             `ui` subcommand — local HTTP/JSON API over the same verdict/flows functions
embed.go          go:embed of ui/dist (Argo CD's own UI packaging pattern)
colors.go         ANSI color helpers (NO_COLOR-aware, terminal-detecting)
clusterversion.go runtime Cilium-version detection + skew warning (CLI stderr / GET /api/version)
compat.go         `compat` subcommand + version-gated policy construct table (GET /api/compat)
scripts/compat-scan.sh  manual discovery aid for new compat.go gates — diffs Cilium versions, see AGENTS.md above
flake.nix, nix/package.nix  Nix flake users install from (docs/guide/install.md); package.nix's npmDepsHash/vendorHash go stale on any go.sum or ui/package-lock.json change — `mise run nix-hashes` (bump-cilium runs it), CI "nix" job fails a stale one
kubernetes/rbac.yaml  read-only ServiceAccount/ClusterRole for the CLI's own access, validated live
templates/        generic/ingress/egress CiliumNetworkPolicy YAML presets (real, standalone CNPs)
examples/         ready-to-run candidate policies matching the self-paced Lab's scenario, plus generic patterns
probes/images.yaml  built-in vetted probe image catalog (probeimages.go embeds it; --probe-images-file replaces it). List only protocols an image passed live
ui/               React + TypeScript + Vite + Tailwind + @xyflow/react frontend (milestone 1 web UI)
```

### Renaming the binary

The name (`guardbee`) lives in **exactly one place**: `binName` in
`globals.go`. `mise.toml`'s build/clean tasks and `scripts/gen-completions.sh`
extract it via `sed`. To rename: change `binName`, then
`mise run build && mise run completions`. Nothing else needs touching except
`.gitignore` (lists prior names literally: `cilium-policy-simulator`,
`cilium-network-editor-live`, `guardbee`).

This project has been renamed before (most recently to **GuardBee**) — the
`.gitignore` entries above are the trace of that. If you're working from a
fork or clone where that history matters, check `AGENTS.local.md` or the
git log rather than assuming the current name is the first one.

## Build & test

Preferred, via [mise](https://mise.jdx.dev) (pins exact Go/Node toolchains):

```
mise run build     # npm run build in ui/, then go build -o guardbee .
mise run check     # build + go vet + go test, in that order
mise run test      # engine-spike + verdict-engine regression tests only
mise run clean
mise run ui-dev     # frontend dev server, proxies /api to a separately-running "guardbee ui" on :4747
mise run completions  # regenerate shell completions after a rename or flag/subcommand change
mise run compat-scan <from-version> <to-version>  # discover new compat.go gate candidates; manual, see above
mise run e2e       # end-to-end UI tests in a real browser (ui/e2e, Playwright); args go to playwright, e.g. -- flows
mise run coverage  # coverage ratchet: fails if Go or UI unit coverage drops below coverage-baseline.json
mise run docs-screenshots  # regenerate docs/images (light theme) from the mocked Lab scenario; review before committing
```

`mise run build` **always rebuilds the frontend first** — the Go binary
embeds whatever's currently in `ui/dist` via `go:embed`, so a stale
`ui/dist` would silently ship an outdated UI. Node is deliberately *not*
pinned via mise (no NixOS prebuilt → triggers a 20-60min from-source build);
on NixOS pin Node through the system's own Nix config instead.

Go tests follow Cilium's own testing pattern for exercising the policy
engine standalone (`engine_spike_test.go` mirrors Cilium's
`distillery_test.go` approach — no live agent, no datapath, no cluster
connection needed to run `go test ./...`). `verdict_test.go` holds the
regression suite (e.g. `TestVerdictEngineNewlyDroppedOnDefaultDenyFlip`) —
anything touching `pkg/policy` usage in `verdict.go` should have a
regression test here before being trusted.

### UI changes need an end-to-end spec

Unit tests (vitest) cover `ui/src/shared/` and `policy.ts` only — there's
no DOM in them by design. Everything a user does in the browser is covered
by `ui/e2e/*.e2e.ts` (Playwright): the real built binary serving the
embedded UI, with only the endpoints that need a cluster mocked
(`e2e/fixtures/test.ts`, data from the Lab scenario in `fixtures/lab.ts`).
Policy parse/validate, templates, compat and version run for real.

- **A UI feature or UI bug fix lands with an e2e spec.** Every UI bug
  found so far (focus lost mid-keystroke, typed text rewritten under the
  cursor, a button turning into a submit button mid-click, a section
  collapsing under the cursor, a phone screen scrolling sideways) was
  invisible to unit tests.
- **A bug fix's spec must fail without the fix.** Build the pre-fix
  commit and run the spec against it:
  `GUARDBEE_BIN=/path/to/old/guardbee mise run e2e -- -g "<spec title>"`.
  A spec that passes either way protects nothing.
- Type like a person (`typeSlowly`, per-key delays and pauses longer than
  the 150ms parse debounce), not `fill()`, whenever typing is the thing
  under test. Tabs stay mounted when hidden, so scope locators to visible
  elements (`visibleForm`, `:visible`).
- On NixOS the browsers come from nixpkgs via this repo's `flake.lock`;
  `@playwright/test` in `ui/package.json` must stay pinned to that exact
  playwright version (scripts/e2e.sh checks). Elsewhere and in CI,
  `npx playwright install chromium` provides them.

`mise run coverage` is a ratchet, not a target: CI fails a PR that lowers
Go or UI unit coverage below `coverage-baseline.json`; after adding tests,
`mise run coverage -- --update` raises the baseline (commit it).

## Running against a real cluster

Needs a kubeconfig with read access — either the user's own, or the scoped
`guardbee` ServiceAccount (`kubernetes/rbac.yaml`), validated live against
the actual cluster (not admin credentials — no RBAC gaps found). RBAC is a
ClusterRole (get/list/watch on CNP/CCNP/CiliumIdentity/CiliumEndpoint/
namespaces) plus a `cilium-system`-scoped Role (pods get/list +
pods/portforward create — required because `kubectl port-forward
svc/hubble-relay` resolves to a backing pod client-side, so RBAC can't be
scoped tighter than the Service's selector — plus get on the one
`cilium-config` ConfigMap, read only when HTTP requests are judged, to know
whether Hubble redacts URL queries). Hubble relay itself listens on
containerPort 4245 in `cilium-system`. Give the ServiceAccount its own
namespace rather than reusing `default` — it's a credential/identity, not a
disposable workload. **Never commit a kubeconfig holding a live SA bearer
token** (one was generated and briefly left around during RBAC smoke
testing — delete it after use, don't let it linger as a tracked file).

```
export KUBECONFIG=/path/to/kubeconfig
./guardbee verdict -n myapp --last 50 your-candidate.yaml
```

`-n`/`--namespace` is always correct for a CNP candidate (can only ever
affect its own namespace). For a CCNP candidate, use `--all-namespaces`/`-A`
instead — it can span multiple namespaces and a namespace filter could miss
a real regression elsewhere in its blast radius. Flag naming deliberately
follows [hubble CLI](https://github.com/cilium/cilium/tree/main/hubble)'s own
conventions (`-n`, `-A`, `-f`, `--last`) everywhere this tool overlaps with
it.

For a first smoke test without a cluster of your own, spin up the
self-paced Lab (`mise run lab-up` — see `docs/guide/lab.md`):
`examples/postgres-*.yaml` and `examples/ccnp-postgres-*.yaml` are built
to match its scenario exactly. The rest of `examples/*.yaml` are generic
patterns (deny-all, egress-only) demonstrating real Cilium policy
mistakes, not tied to any one cluster; point `verdict` at your own
namespace/candidate for anything beyond what's there.

## House style in this codebase (match it, don't "improve" it)

- Comments explain **why**, especially non-obvious Cilium-internal-API
  subtleties, version-coupling caveats, or a design decision's rationale —
  not what the code visibly does. Follow this density; don't strip comments
  down to the project's or your own default style, and don't add
  what-explaining comments either.
- Flag names/semantics mirror hubble CLI's own conventions wherever this
  tool overlaps with it — check hubble's actual flags before inventing a
  different convention for something hubble already named.
- "Known v1 simplifications" are stated explicitly in both code comments and
  the README, never silently assumed — if you add a new one, document it the
  same way, in both places.
- UI and CLI must stay provably the same engine (`ui.go` calls the exact
  functions `verdict.go`/`flows.go` define) — never fork logic between them.
