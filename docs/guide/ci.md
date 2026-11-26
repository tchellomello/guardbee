---
layout: doc
title: Gate PRs in CI
description: Fail a pull request when a CiliumNetworkPolicy change would break real traffic, and post the verdict as a PR comment.
---

# Gate PRs in CI

Run `verdict` on every pull request that touches a policy. The job posts what the change would break as a PR comment, and fails when a real flow would be newly dropped.

```
guardbee verdict -n myapp --replace-existing --fail-on-dropped --min-flows 20 --format markdown policies/myapp/*.yaml
```

| Flag | Why it's here |
|---|---|
| `--replace-existing` | A PR usually *edits* a live policy. Without this, the old rules stay in effect next to the new ones, and anything the edit removes or narrows is never reported |
| `--fail-on-dropped` | Exit `2` when any real flow would be `NEWLY_DROPPED` |
| `--min-flows 20` | Exit `3` when too few flows were judged to call it a pass, so a quiet namespace or a wrong `-n` can't read as green |
| `--format markdown` | A summary ready to post: status line, counts, a table of changed rows, unchanged rows collapsed |

The Markdown is written to stdout even when the exit code is non-zero, and warnings go to stderr, so the job can post the comment and still fail. Every exit code is listed under [CI mode](commands.html#ci-mode).

---

## GitHub Actions

{% raw %}

```yaml
name: Policy verdict

on:
  pull_request:
    paths:
      - "policies/myapp/**"

permissions:
  contents: read
  pull-requests: write   # to post the comment

jobs:
  verdict:
    runs-on: ubuntu-latest
    env:
      # Pin a release: its tag is also the Cilium engine it judges with
      # (v<cilium>-<n>), so pick one that matches your cluster.
      GUARDBEE_VERSION: v1.20.4-6
    steps:
      - uses: actions/checkout@v4

      - name: Install GuardBee
        run: |
          cd "$RUNNER_TEMP"
          base="https://github.com/tchellomello/guardbee/releases/download/${GUARDBEE_VERSION}"
          curl -fsSLO "${base}/guardbee_${GUARDBEE_VERSION}_linux_amd64.tar.gz"
          curl -fsSLO "${base}/SHA256SUMS"
          sha256sum --ignore-missing -c SHA256SUMS
          tar -xzf "guardbee_${GUARDBEE_VERSION}_linux_amd64.tar.gz"
          sudo install -m 0755 guardbee-linux-amd64 /usr/local/bin/guardbee

      - name: Judge the change against real traffic
        id: verdict
        env:
          KUBECONFIG_DATA: ${{ secrets.GUARDBEE_KUBECONFIG }}
        run: |
          export KUBECONFIG="$RUNNER_TEMP/kubeconfig"
          printf '%s' "$KUBECONFIG_DATA" > "$KUBECONFIG"
          set +e
          guardbee verdict -n myapp --replace-existing --fail-on-dropped --min-flows 20 \
            --format markdown policies/myapp/*.yaml > verdict.md
          echo "exit=$?" >> "$GITHUB_OUTPUT"

      - name: Post the verdict on the pull request
        if: always()
        env:
          GH_TOKEN: ${{ github.token }}
          PR: ${{ github.event.pull_request.number }}
        run: |
          # Empty when verdict itself errored (exit 1); the reason is in this job's log.
          if [ -s verdict.md ]; then
            gh pr comment "$PR" --body-file verdict.md
          fi

      - name: Fail on regressions
        if: steps.verdict.outputs.exit != '0'
        env:
          CODE: ${{ steps.verdict.outputs.exit }}
        run: exit "$CODE"
```

{% endraw %}

> **Pin `GUARDBEE_VERSION`** rather than fetching the latest release: the tag names the Cilium version GuardBee's engine embeds, and a CI gate should not change behaviour on its own. See [versioning](install.html#versioning).

### Several policies in one file

For rendered output (kustomize, Helm), judge each policy on its own and fail with the worst result:

```
kustomize build overlays/prod | guardbee verdict -n myapp --per-policy --replace-existing --fail-on-dropped --min-flows 20 --format markdown -
```

Documents that aren't CNPs or CCNPs are skipped and named under **Not judged** in the comment, including a Kubernetes `NetworkPolicy`, which Cilium enforces but GuardBee doesn't simulate. A `CiliumClusterwideNetworkPolicy` needs `-A` instead of `-n`, so the sample covers every namespace it can touch.

---

## Cluster access

The job judges against a live cluster, so it needs a kubeconfig.

- **Use the read-only ServiceAccount** in [`kubernetes/rbac.yaml`](https://github.com/tchellomello/guardbee/blob/main/kubernetes/rbac.yaml), not admin credentials. Store its kubeconfig as the `GUARDBEE_KUBECONFIG` secret; never commit it.
- **Network:** by default GuardBee port-forwards to Hubble Relay *through the Kubernetes API server*, so the runner only needs to reach the API server. That needs `pods/portforward` in `cilium-system`, which the ServiceAccount includes.
- **A runner inside the cluster** (a self-hosted runner, or Actions Runner Controller) can dial Relay's Service directly with `--hubble-addr hubble-relay.cilium-system.svc:80`, which needs no `pods` or `pods/portforward` RBAC at all.
- **Cilium in `kube-system`?** See [Run on your cluster](run.html) for the `--hubble-addr` workaround.

> GitHub doesn't pass secrets to workflows triggered by pull requests from forks, so this gate suits repositories where policy changes come from branches, not forks.

---

## What a pass means

A pass covers the flows Hubble had in its buffer when the job ran: a small, cluster-wide window of recent traffic, not history. A cron job or nightly backup that didn't run recently isn't in the sample, so a change that breaks it can still pass.

- **Keep `--min-flows`** so an empty or tiny sample fails as inconclusive (exit `3`) instead of passing.
- **Read the comment's counts**, not just the status: "20 judged" and "2,000 judged" are different levels of confidence.
- See [How it works](how-it-works.html) for every known limit, and the [FAQ](faq.html) for what GuardBee can't judge.
