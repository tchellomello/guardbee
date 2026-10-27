package main

// CLI-wide configuration — currently just the binary's own name, with room
// for future settings as the tool grows. Shell tooling (mise.toml,
// scripts/gen-completions.sh) extracts binName straight out of this file via
// sed, so this stays the single place to edit on a rename — no Go source
// elsewhere, no separate file to keep in sync.
const binName = "guardbee"

// pinnedCiliumVersion is the exact Cilium version go.mod pins
// (github.com/cilium/cilium) — the version whose actual pkg/policy engine
// code this tool embeds and whose semantics every verdict is a verdict
// from (see CLAUDE.md's "Architecture principle that overrides
// convenience"). go.mod isn't readable at runtime, so this is the one
// place that number is duplicated; bump it by hand alongside go.mod on a
// Cilium version upgrade — clusterversion.go's detection and compat.go's
// feature gates both key off this constant whenever the live cluster's own
// version can't be determined.
const pinnedCiliumVersion = "1.20.2"

// numberFlagHelp explains --last's actual semantics, shared verbatim by
// every subcommand's -h screen that takes it (flows, verdict) so the two
// never drift out of sync. --last is a request ceiling against Hubble's
// GetFlows, not a sampling target the tool can force: Hubble relay's buffer
// is a small, fixed-size ring holding recent flows for the WHOLE cluster,
// not scoped to any one namespace, so a namespace filter can only ever
// return however many of that shared buffer's contents happen to match right
// now. Asking for more than that returns fewer, and that is expected, not a
// bug — raising --last past the buffer's actual contents is a no-op; --follow
// (accumulate over wall-clock time) is the real lever for more volume.
const numberFlagHelp = `--last is a ceiling, not a guarantee. Hubble's flow buffer is a small,
fixed-size ring holding recent flows for the WHOLE cluster, not scoped to any
one namespace — so "-n myapp --last 1000" does not mean "find me 1000 myapp
flows." It means "scan the buffer and return up to 1000 flows that also
match myapp," and the buffer may hold far fewer matches than that at any
moment, especially for a low-traffic namespace. Getting fewer flows than
requested is expected, not a bug, and raising --last further won't change it
once the buffer is exhausted. Use --follow to accumulate more flows over
time instead.`
