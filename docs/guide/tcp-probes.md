---
layout: doc
title: Connectivity tests
description: Opt-in TCP/UDP generated traffic, candidate policy decisions, image requirements, RBAC, and evidence limitations.
---

# Opt-in connectivity tests (ephemeral containers)

GuardBee remains read-only by default. TCP/UDP connectivity tests are an explicit exception:
each confirmed request appends a restricted ephemeral container to the chosen
**existing running Linux Pod**. The candidate policy is never applied.

Start with a candidate policy and a selected source Pod and operator-owned
destination. The useful answer is the **candidate's predicted allow/deny** for
real captured traffic, not just whether generating traffic succeeded. The API
also permits diagnostics without a candidate; those requests have no candidate
prediction. No synthetic endpoints or identities are introduced.

```sh
guardbee ui --addr 127.0.0.1:4747 --enable-probes \
  --probe-image '<your-image:tag>'
```

Choose your own image using `repository:tag` or `repository@sha256:digest`.
Tagged images use `imagePullPolicy: Always`; digest references use
`IfNotPresent`. GuardBee does not prescribe an image. It needs compatible
**`timeout` and `nc` binaries on PATH** for
TCP. UDP additionally requires **Python 3 with its standard library**, including
`socket` and `ipaddress`; no dependencies are installed at runtime. It must
support these exact direct argv patterns (no shell):

```text
timeout -k 1s 8s nc -n -z -v -w 5 <unicast-IP-literal> <port>
timeout -k 1s 8s nc -z -v -w 5 <DNS-hostname> <port>
timeout -k 1s 8s python3 -I -c <fixed-GuardBee-UDP-program> <host> <port>
```

Use GNU-compatible timeout (`-k`, duration suffixes), and OpenBSD-compatible
netcat (`-n -z -v -w`). Verify those binaries under UID/GID 65532, no capabilities,
read-only root filesystem, and RuntimeDefault seccomp before enabling probes.
Startup validates reference syntax, not binary availability. The test reports
runtime failures explicitly if a required executable is missing.

The UDP program uses `getaddrinfo(AF_UNSPEC, SOCK_DGRAM)`, validates the first
resolved IPv4/IPv6 address, and calls `sendto` **exactly once** with the fixed
27-byte UTF-8/ASCII marker `guardbee-connectivity-probe`. It waits for no reply,
performs no retry, and never permits an arbitrary payload. Unlike `nc -uz`, it
actually generates a datagram. Host and port are separate argv values, never
interpolated into the program. The socket has a five-second timeout; external
`timeout` also bounds DNS resolution. Unsafe resolved addresses (loopback,
link-local, multicast, unspecified, scoped IPv6, and limited broadcast, including
IPv4-mapped IPv6) fail before sending.

**Confirm each request explicitly before submitting it.** For UDP, confirmation
must disclose the selected target/port, one packet, and the exact marker above.
An unexpected marker may be rejected, logged, or interpreted by the target's
application; it is not an application-protocol health check and is not safe to
send blindly to arbitrary database or other endpoints. Choose a target you own
and have approved for this traffic. Missing Python or incompatible executables
produce a failed/inconclusive attempt, not evidence that traffic was generated.

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
- The existing `guardbee-read` ClusterRole in `kubernetes/rbac.yaml` includes
  `list` on `networking.k8s.io/networkpolicies` across namespaces for the
  simulation completeness check. Both manifests bind the example ServiceAccount
  `guardbee/guardbee`; personal kubeconfig users use their own existing grants
  or an administrator-managed User/Group binding. GuardBee uses client-go directly,
  not a kubectl subprocess, and never applies or grants RBAC itself.
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
   The image's timeout independently stops nc/Python after 8 seconds and force-kills
  after at most one more second. Image pull/scheduling delays are outside that
  command-runtime bound; Kubernetes can start the container after the request
  ends. Probe containers have no resource guarantees, so use carefully on
  sensitive workloads.

## API contract

- `GET /api/probes/capabilities`: `{ "enabled": false }` by default.
- `GET /api/probes/pods?namespace=app`: `{ "pods": [{"name":"client","uid":"…"}] }`.
  Requires probes enabled; only eligible running Pods are returned. Optional
  `excluded` maps ineligibility reasons to counts, so an empty picker can explain
  unready Pods, unsupported network/process settings, or an earlier pending test.
- `POST /api/probes/connection`, after explicit per-request UI confirmation:
  `{ "namespace":"app", "pod":"client", "uid":"…", "host":"192.0.2.2", "port":443, "protocol":"TCP", "candidateYAML":"CNP/CCNP YAML" }`.
  `protocol` is required and must be exactly uppercase `TCP` or `UDP`.
  `candidateYAML` is optional for API diagnostics; omit it only when no candidate
  prediction is needed. A supplied candidate is validated before injection.
  `candidateNamespace` defaults independently of the source Pod: omitted uses
  the source namespace for backward compatibility; explicit `""` requires a CNP
  to declare its namespace. `replaceExisting` defaults to true for probes; the
  Web UI always supplies its shared simulation-mode setting.
- `POST /api/probes/tcp` is the compatibility alias: old requests without
  `protocol` default to TCP and keep optional `candidateYAML`. Explicit TCP is
  accepted; UDP is rejected on this legacy endpoint.
  DNS hostnames (case-insensitive, optional trailing dot) resolve inside the
  Pod, never server-side. Hostname flow correlation requires exact normalized
  Hubble destination names, never just the port. Missing names/aliases/mesh
   interception make policy evidence inconclusive, even when traffic generation succeeds.
  Operator network/admission controls must constrain DNS-resolved targets;
  the server cannot safely resolve them in the Pod's DNS context. Loopback, link-local,
  multicast, unspecified, and limited-broadcast targets are rejected because
  they do not provide the intended normal network-policy path.

The result contains `namespace`, `pod`, `host`, `port`, `protocol`, `outcome`
(`connected` for TCP, `generated` for UDP, `failed`, `inconclusive`), `message`, optional `containerName`, `flows` (the
existing `flowOut` API shape), optional `simulation` (existing
`verdictResponse`), and `warnings` (always an array). Invalid inputs return
400; disabled/authorization/origin failures 403; stale/ineligible Pods or
entry limits 409; concurrency limits 429. A capture startup failure produces
an inconclusive result and **does not inject** a container. An uncertain
ephemeral update reports its generated name; inspect the Pod before retrying.

Simulation rows add optional `baselineAllowed` and `candidateAllowed` booleans
to the shared verdict JSON shape. Both are derived directly from the engine's
combined source egress and destination ingress decisions. In particular,
`UNCHANGED` with both `false` means **still denied**, not allowed. Both `true`
means still allowed. `NEWLY_DROPPED` is `true` → `false`, and `NEWLY_ALLOWED`
is `false` → `true`. Omitted decisions/unresolved flows mean no prediction;
do not infer a candidate allow from a delta, an empty sample, or runtime outcome.

## Evidence, not policy sign-off

Capture starts before injection and waits for GetFlows headers and the source
node's NODE_CONNECTED event as a relay availability health gate. This is not
an acknowledgement that the source-node collector has subscribed: relay marks
nodes connected before the collector's GetFlows goroutine runs. This race is
best-effort, and missing evidence is explicitly inconclusive. Capture correlates
outgoing TCP/UDP flows by exact namespace/Pod, protocol, destination IP or normalized Hubble
destination DNS name, port, and attempt window, excluding replies.
**Attribution remains best-effort:** Hubble does not identify the ephemeral
container, and the generated source port is not known. Concurrent application traffic
to the same destination can appear in the result. Service DNAT, clock skew,
relay buffering, dropped events, or unavailable nodes can also hide evidence.

An nc failure alone never means POLICY_DENY. Connection refusal, routing,
timeouts, image/admission failures, and missing status can all differ from a
policy drop. Only Hubble's own attribution/drop reason supplies a live policy
decision. A successful connection is not an application health check.

UDP `generated` means only that the fixed program's `sendto` returned. It does
**not** mean delivered, reachable, listening, healthy, or allowed by policy.
UDP may send successfully even if the datapath drops the packet. Use actual
Hubble evidence and the candidate's engine decision as separate signals.

Simulation uses the same real pinned Cilium engine (`judgeFlow`, shared
`buildVerdictEnginesWith` rule-construction core, `toVerdictResponse`), with
the **full cluster-wide CNP/CCNP inventory** so a destination in another
namespace retains its ingress policy. The inspected inventory is the one
used for engine construction, not a second potentially changed list. Candidate
semantics follow Verdict's shared **Replace matching live policies** setting.
Replacement removes policies with the same kind, namespace, and name only from
the candidate engine; the original baseline remains unchanged. Turning the
setting off explicitly selects additive simulation, which can retain permissions
removed by an edited candidate. The submitted snapshot records the chosen mode.
Any Kubernetes NetworkPolicy object, or inability to read that full inventory,
suppresses simulation because those policies are not part of this engine
baseline. Optional simulation therefore requires cluster-wide NetworkPolicy
list access in addition to existing CNP/CCNP reads; the shipped read ClusterRole
now grants this inventory read. This grant resolves authorization only: existing
NetworkPolicy objects still make simulation inconclusive until the engine
supports them.

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
suppress simulation while preserving actual observed flows and TCP/UDP runtime outcome.
The bounded relay drain is two seconds, outside the attempt's correlation
window; collector readiness and relay delivery still remain best-effort.
Missing or unresolved flow evidence is never a pass.

## Reviewing and diagnosing a test

The Verdict tab's **Connectivity tests** section inherits the loaded candidate
and scope. Its headline compares the **baseline model** with the candidate;
actual Hubble observations and traffic-generation status are separate evidence.
Editing the candidate or scope marks older results stale without rewriting the
submitted snapshot. **Download test report (JSON)** preserves the exact request,
candidate, response, cluster context, configured image reference, Pod UID, and timing for review.
In all-namespaces mode, choosing a source namespace does not supply a missing
candidate namespace: a namespaced CNP must declare its own `metadata.namespace`.

A previous GuardBee container that is still pending or running blocks another
test on that Pod, including after a client disconnect or server restart. Inspect
the named container; do not restart the workload just to retry. Image-pull and
container-creation errors are surfaced explicitly. Missing executables or an
unverified runtime cannot yield a prediction from unrelated workload traffic.
