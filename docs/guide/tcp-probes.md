---
layout: doc
title: TCP probes
description: Opt-in ephemeral-container TCP probes, image approval, RBAC, and evidence limitations.
---

# Opt-in TCP probes (ephemeral containers)

GuardBee remains read-only by default. TCP probes are an explicit exception:
each confirmed request appends a restricted ephemeral container to the chosen
**existing running Linux Pod**. The candidate policy is never applied.

```sh
guardbee ui --addr 127.0.0.1:4747 --enable-probes \
  --probe-image 'YOUR_APPROVED_REGISTRY/probe@sha256:YOUR_APPROVED_64_HEX_DIGEST'
```

The digest above is a placeholder, not an approved image. The operator must
approve a real image with compatible **`timeout` and `nc` binaries on PATH**.
It must support this exact direct argv (no shell):

```text
timeout -k 1s 8s nc -n -z -v -w 5 <unicast-IP-literal> <port>
timeout -k 1s 8s nc -z -v -w 5 <DNS-hostname> <port>
```

Use GNU-compatible timeout (`-k`, duration suffixes), and OpenBSD-compatible
netcat (`-n -z -v -w`). Verify those binaries under UID/GID 65532, no capabilities,
read-only root filesystem, and RuntimeDefault seccomp before enabling probes.
Startup validates digest pinning, not image provenance or binary behavior.
Do not choose an unreviewed image or repoint an approved image reference.

## Safety and permissions

- The writable server binds **only a numeric loopback address**. Open it using
  that exact IP address, not `localhost` or another hostname. POST checks JSON
  content type and exact same-origin Origin/Host, rejects DNS hosts and
  cross-site fetches; this prevents DNS rebinding and cross-origin browser
  writes. It is not remote hosting or multi-user authentication.
- Existing read-only RBAC is unchanged. `kubernetes/probes-rbac.yaml` is an
  optional namespace-scoped grant for `pods` get/list,
  `pods/ephemeralcontainers` **update**, and `pods/log` get. Change its namespace
  and subject before applying it yourself. Standard Kubernetes authenticated
  discovery access must also allow SelfSubjectAccessReview creation.
- Each request checks authorization on the exact Pod name and subresources,
  verifies its UID, then re-reads it after capture readiness and submits UID
  plus resourceVersion on the ephemeral-container PUT. Conflicts are not retried.
- No exec into an application container; no labels, ServiceAccount, mounts,
  capabilities, or other workload fields are changed. The injected container
  has no mounts/environment/token, runs nonroot, drops ALL capabilities,
  disables privilege escalation, and uses a read-only filesystem and seccomp.
  Host-network/PID/IPC, shared process namespace, mirror/static, terminating,
  unready, and Windows Pods are excluded. `kube-*`, `cilium-system`, and
  `hubble-system` namespaces are excluded. Other namespaces are constrained
  by the operator's namespace-scoped RBAC and admission policy, not a new CLI
  namespace allowlist. Admission must enforce any further workload/image
  restrictions; GuardBee cannot verify every cluster-specific safety rule.
- At most two requests globally, one per Pod, eight GuardBee entries per Pod,
  and 32 total ephemeral entries. JSON bodies are capped at 256 KiB. Status,
  logs (4 KiB), capture (256 flows), and API calls share a 30-second request
  deadline; Pod enumeration has a 10-second deadline.
- **Ephemeral entries cannot be removed or restarted.** They remain after
  termination until the Pod is replaced by its normal owner. GuardBee never
  deletes/restarts Pods to clean them up. Every attempt consumes one entry.
- HTTP cancellation cancels Kubernetes reads and Hubble capture, but cannot
  kill an already injected container without additional mutation privileges.
  The image's timeout independently stops nc after 8 seconds and force-kills
  after at most one more second. Image pull/scheduling delays are outside that
  command-runtime bound; Kubernetes can start the container after the request
  ends. Probe containers have no resource guarantees, so use carefully on
  sensitive workloads.

## API contract

- `GET /api/probes/capabilities`: `{ "enabled": false }` by default.
- `GET /api/probes/pods?namespace=app`: `{ "pods": [{"name":"client","uid":"…"}] }`.
  Requires probes enabled; only eligible running Pods are returned.
- `POST /api/probes/tcp`, after explicit per-request UI confirmation:
  `{ "namespace":"app", "pod":"client", "uid":"…", "host":"192.0.2.2", "port":443, "candidateYAML":"optional CNP/CCNP YAML" }`.
  DNS hostnames (case-insensitive, optional trailing dot) resolve inside the
  Pod, never server-side. Hostname flow correlation requires exact normalized
  Hubble destination names, never just the port. Missing names/aliases/mesh
  interception make policy evidence inconclusive, even when nc connects.
  Operator network/admission controls must constrain DNS-resolved targets;
  the server cannot safely resolve them in the Pod's DNS context. Loopback, link-local,
  multicast, unspecified, and limited-broadcast targets are rejected because
  they do not provide the intended normal network-policy path.

The result contains `namespace`, `pod`, `host`, `port`, `outcome` (`connected`,
`failed`, `inconclusive`), `message`, optional `containerName`, `flows` (the
existing `flowOut` API shape), optional `simulation` (existing
`verdictResponse`), and `warnings` (always an array). Invalid inputs return
400; disabled/authorization/origin failures 403; stale/ineligible Pods or
entry limits 409; concurrency limits 429. A capture startup failure produces
an inconclusive result and **does not inject** a container. An uncertain
ephemeral update reports its generated name; inspect the Pod before retrying.

## Evidence, not policy sign-off

Capture starts before injection and waits for GetFlows headers and the source
node's NODE_CONNECTED event as a relay availability health gate. This is not
an acknowledgement that the source-node collector has subscribed: relay marks
nodes connected before the collector's GetFlows goroutine runs. This race is
best-effort, and missing evidence is explicitly inconclusive. Capture correlates
outgoing TCP flows by exact namespace/Pod, destination IP or normalized Hubble
destination DNS name, port, and attempt window, excluding replies.
**Attribution remains best-effort:** Hubble does not identify the ephemeral
container, and the nc source port is not known. Concurrent application traffic
to the same destination can appear in the result. Service DNAT, clock skew,
relay buffering, dropped events, or unavailable nodes can also hide evidence.

An nc failure alone never means POLICY_DENY. Connection refusal, routing,
timeouts, image/admission failures, and missing status can all differ from a
policy drop. Only Hubble's own attribution/drop reason supplies a live policy
decision. A successful connection is not an application health check.

Simulation uses the same real pinned Cilium engine (`judgeFlow`, shared
`buildVerdictEnginesWith` rule-construction core, `toVerdictResponse`), with
the **full cluster-wide CNP/CCNP inventory** so a destination in another
namespace retains its ingress policy. The inspected inventory is the one
used for engine construction, not a second potentially changed list. Candidate
semantics replace live policies with the same kind, namespace, and name;
the original baseline remains unchanged and replaced names are disclosed.
Any Kubernetes NetworkPolicy object, or inability to read that full inventory,
suppresses simulation because those policies are not part of this engine
baseline. Optional simulation therefore requires cluster-wide NetworkPolicy
list access in addition to existing CNP/CCNP reads.

`cidrGroupRef` or `cidrGroupSelector` in any baseline/candidate suppresses simulation with an explicit
**unverified** warning. Cilium's real agent injects CIDR-group labels through
IPcache; existing Hubble identities may already carry those labels and the
engine can select them. What is not reproduced/verified here is membership and
new candidate identity injection. GuardBee does not manually translate groups
to CIDRs or issue a reassuring result from incomplete context. FQDN/L7 proxy
semantics and baseline parse errors likewise suppress probe simulation.
Authentication requirements (including test-always-fail), agent-resolved
`toServices`, and named ports also suppress simulation: the standalone
endpoint owner does not provide those agent-side mechanisms. Deprecated raw
baseline fields are checked before Parse can silently discard them.
Lost-event notifications, capture errors, overflow, or deadline cancellation
suppress simulation while preserving actual observed flows and TCP outcome.
The bounded relay drain is two seconds, outside the attempt's correlation
window; collector readiness and relay delivery still remain best-effort.
Missing or unresolved flow evidence is never a pass.
