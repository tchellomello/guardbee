package main

import "embed"

// uiAssets embeds the "ui" subcommand's frontend production build
// (React/Vite, see ui/) directly into this binary — the same packaging
// pattern Argo CD's own UI uses (its React/TypeScript ui/ is built
// separately, then copied into the Go build stage), confirmed against
// Argo CD's actual architecture during this feature's office-hours
// session rather than assumed. Run "npm run build" in ui/ before building
// this binary (mise run build does both, in order — see mise.toml).
//
//go:embed all:ui/dist
var uiAssets embed.FS
