#!/usr/bin/env bash
# Deletes only the disposable "guardbee-lab" kind cluster lab-up.sh
# created. Nothing else on the machine is touched.
set -euo pipefail
kind delete cluster --name guardbee-lab
