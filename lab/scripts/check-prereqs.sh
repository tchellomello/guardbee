#!/usr/bin/env bash
# Checked, never installed — this lab never touches anything outside its
# own disposable kind cluster. docker/kind/helm/kubectl are the reader's
# own tools to install; this script only tells them what's missing.
set -euo pipefail

missing=()
for bin in docker kind helm kubectl; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    missing+=("$bin")
  fi
done

if [ "${#missing[@]}" -gt 0 ]; then
  echo "guardbee lab: missing required tool(s): ${missing[*]}" >&2
  echo "" >&2
  echo "Install them yourself, then re-run \"mise run lab-up\":" >&2
  echo "  docker:  https://docs.docker.com/engine/install/" >&2
  echo "  kind:    https://kind.sigs.k8s.io/docs/user/quick-start/#installation" >&2
  echo "  helm:    https://helm.sh/docs/intro/install/" >&2
  echo "  kubectl: https://kubernetes.io/docs/tasks/tools/#kubectl" >&2
  exit 1
fi
