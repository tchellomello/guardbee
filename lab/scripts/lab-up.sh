#!/usr/bin/env bash
# Spins up a disposable kind+Cilium cluster for the self-paced lab in
# docs/guide/lab.md. Everything this touches lives inside the
# "guardbee-lab" kind cluster it creates — see lab-down.sh for the one
# thing it deletes.
set -euo pipefail

CILIUM_VERSION="1.20.2" # must match go.mod's github.com/cilium/cilium version — see AGENTS.md
CLUSTER_NAME="guardbee-lab"
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash "$LAB_DIR/scripts/check-prereqs.sh"

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  echo "guardbee lab: cluster \"$CLUSTER_NAME\" already exists — reusing it (run \"mise run lab-down\" first for a clean start)."
else
  echo "guardbee lab: creating kind cluster \"$CLUSTER_NAME\"..."
  kind create cluster --name "$CLUSTER_NAME" --config "$LAB_DIR/kind-config.yaml"
fi

kubectl config use-context "kind-$CLUSTER_NAME" >/dev/null

echo "guardbee lab: installing Cilium $CILIUM_VERSION into cilium-system (hubble-relay is what \"guardbee flows\"/\"verdict\" port-forward to)..."
helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
helm repo update cilium >/dev/null
helm upgrade --install cilium cilium/cilium \
  --version "$CILIUM_VERSION" \
  --namespace cilium-system \
  --create-namespace \
  --values "$LAB_DIR/cilium-values.yaml" \
  --wait

echo "guardbee lab: waiting for Cilium and hubble-relay to report ready..."
kubectl -n cilium-system wait --for=condition=ready pod -l k8s-app=cilium --timeout=300s
kubectl -n cilium-system wait --for=condition=ready pod -l k8s-app=hubble-relay --timeout=300s

echo "guardbee lab: deploying webapp / postgres / observability workloads..."
kubectl apply -f "$LAB_DIR/manifests/00-namespaces.yaml"
kubectl apply -f "$LAB_DIR/manifests/10-postgres.yaml"
kubectl apply -f "$LAB_DIR/manifests/20-webapp.yaml"
kubectl apply -f "$LAB_DIR/manifests/30-observability.yaml"

kubectl -n postgres wait --for=condition=ready pod -l app=postgres --timeout=180s
kubectl -n webapp wait --for=condition=ready pod -l app=webapp --timeout=180s
kubectl -n observability wait --for=condition=ready pod -l app=prometheus --timeout=180s

echo ""
current_context="$(kubectl config current-context 2>/dev/null || echo "(none)")"
if [ "$current_context" = "kind-$CLUSTER_NAME" ]; then
  echo "guardbee lab is up. kubeconfig context: $current_context (already active)."
else
  # A context-switching tool (direnv, a cluster-safety wrapper, etc.) can
  # reassert a different context after this script's own "kubectl config
  # use-context" call above — asserting the name here instead of checking
  # it would silently lie in exactly that case.
  echo "guardbee lab is up, but your active kubectl context is"
  echo "\"$current_context\", not \"kind-$CLUSTER_NAME\" — run:"
  echo "  kubectl config use-context kind-$CLUSTER_NAME"
  echo "before the next steps, or they'll hit the wrong cluster."
fi
echo "Next: docs/guide/lab.md, or run \"guardbee flows -n postgres --last 20\" directly."
