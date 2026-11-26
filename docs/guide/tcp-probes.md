---
layout: doc
title: Connectivity tests
description: Opt-in TCP/UDP generated traffic, candidate policy decisions, image requirements, RBAC, and evidence limitations.
---

# Connectivity tests

Prove one connection before you merge: GuardBee sends real TCP or UDP traffic from an existing Pod, captures what Hubble saw, and shows whether the **candidate** policy would allow it. The candidate policy is never applied.

<div class="shot">
<div class="shot-titlebar"><span class="shot-dot red"></span><span class="shot-dot yellow"></span><span class="shot-dot green"></span><span class="shot-label">guardbee ui · verdict — connectivity test</span></div>
<img src="../images/ui-connectivity-test.png" alt="Connectivity test from prometheus to postgres:9187 with the BusyBox image: every stage done, a red banner saying the connection would break, and the path diagram with the baseline lane flowing through the policy gate and the candidate lane stopped at a cross" />
</div>

<div class="guarantee" markdown="1">

Off by default. GuardBee stays read-only unless the UI is started with `--enable-probes`.

</div>

---

## Quickstart

```sh
guardbee ui --addr 127.0.0.1:4747 --enable-probes
```

1. **Open `http://127.0.0.1:4747`,** the numeric address. A page opened on `localhost` is redirected to it.
2. **Run a verdict** with your candidate. Each run's card has its own **Connectivity tests** section.
3. **Pick** the source Pod, the operator-owned destination (an IP, or an in-cluster Service name) and port, the protocol, and a probe image from the catalog.
4. **Confirm** the request. Every request is confirmed explicitly; for UDP the confirmation shows the target, the port, one packet, and the exact marker it sends.
5. **Read the result:** the live baseline and the candidate side by side, drawn as the path the traffic took.

> The useful answer is the **candidate's predicted allow/deny** for real captured traffic, not just whether generating traffic succeeded. The API also permits diagnostics without a candidate; those requests have no candidate prediction. No synthetic endpoints or identities are introduced.

---

## What a test changes

Each confirmed request appends one restricted ephemeral container to the chosen **existing running Linux Pod**. That is the only change.

| A test does | A test never does |
|---|---|
| Append one ephemeral container per attempt | Apply the candidate policy |
| Generate one TCP connection or one UDP datagram from it | Exec into an application container |
| Read Pods, logs, Services and EndpointSlices to correlate the flow | Change labels, ServiceAccount, mounts, capabilities, or other workload fields |
| | Delete or restart a Pod, or grant RBAC |

> **Ephemeral entries cannot be removed or restarted.** They remain after termination until the Pod is replaced by its normal owner, and every attempt consumes one entry. GuardBee never deletes or restarts Pods to clean them up.

---

## Reading a result

### Outcome

| Outcome | Means | Does not mean |
|---|---|---|
| `connected` | TCP: `nc` connected | An application health check passed |
| `generated` | UDP: the fixed program's `sendto` returned | Delivered, reachable, listening, healthy, or allowed by policy. UDP may send successfully even if the datapath drops the packet |
| `failed` | Traffic generation failed: the probe command exited with an error, for example a refused connection | A policy drop. Refusal and routing problems look the same as a deny here; only Hubble's own attribution or drop reason supplies a live policy decision |
| `inconclusive` | No usable result: the command timed out or was killed, a required executable was missing, its status was unavailable, or capture couldn't start | A pass. Missing or unresolved flow evidence is never a pass |

### Baseline vs candidate

The headline compares the **baseline model** with the candidate. Each simulation row carries both decisions, taken straight from the engine's combined source egress and destination ingress decisions:

| `baselineAllowed` | `candidateAllowed` | Reads as |
|---|---|---|
| `true` | `true` | `UNCHANGED`, still allowed |
| `false` | `false` | `UNCHANGED`, **still denied** |
| `true` | `false` | `NEWLY_DROPPED` |
| `false` | `true` | `NEWLY_ALLOWED` |

> Omitted decisions or unresolved flows mean **no prediction**. Do not infer a candidate allow from a delta, an empty sample, or the runtime outcome. Use actual Hubble evidence and the candidate's engine decision as separate signals.

### Evidence & limitations

Under every result, **Evidence & limitations** shows what the verdict rests on:

- the Hubble flows observed under current policy, one connection's trace events folded into a row with a count, plus who Hubble says decided it;
- the candidate simulation rows with both decisions;
- the test's notes, each a short title that opens to the full explanation.

<div class="shot">
<div class="shot-titlebar"><span class="shot-dot red"></span><span class="shot-dot yellow"></span><span class="shot-dot green"></span><span class="shot-label">guardbee ui · verdict — connectivity test evidence</span></div>
<img src="../images/ui-connectivity-evidence.png" alt="Evidence and limitations expanded: the observed Hubble flows table (one connection's trace events folded into rows with a count), the candidate simulation row turning allowed into blocked, and the test notes, one opened to show its full text" />
</div>

---

## Probe images

The web UI offers a **catalog** of probe images as cards, each showing which protocols it can test and whether it is pinned by digest. The browser sends only the chosen entry's id: it can never type or send an image reference, so what runs inside a workload is always something the server was started with. `--enable-probes` is still required either way.

| Startup flags | Images offered |
|---|---|
| `--enable-probes` | The built-in vetted catalog, [`probes/images.yaml`](https://github.com/tchellomello/guardbee/blob/main/probes/images.yaml) |
| `--enable-probes --probe-images-file my-images.yaml` | Your catalog instead (YAML or JSON, same format) |
| `--enable-probes --probe-image <repository:tag-or-digest>` | Exactly that one image, as before |

The built-in catalog ships two images, each checked against a live cluster under the exact restricted context below with GuardBee's own commands:

| Id | Image | Protocols | Why |
|---|---|---|---|
| `netshoot` | `docker.io/nicolaka/netshoot@sha256:…` | TCP, UDP | Widely used network troubleshooting toolbox: OpenBSD `nc`, Python 3. Larger pull. |
| `busybox` | `docker.io/library/busybox:1.37@sha256:…` | TCP | Official, ~2 MB, `nc` and `timeout`. No Python, so no UDP. |

Your own catalog uses the same format. Unknown fields are rejected at startup, so a typo fails loudly instead of offering a broken entry:

```yaml
images:
  - id: netshoot-mirror          # lowercase DNS label, unique; what the browser sends
    name: netshoot (corp mirror) # card title, 1-64 characters
    image: registry.corp.example/netshoot@sha256:<64 hex digits>
    protocols: [TCP, UDP]        # only what the image passed; UDP needs Python 3
    description: Mirrored from docker.io for air-gapped clusters.
```

- **Prefer digests.** GuardBee pulls a tag-only image on **every** test (`imagePullPolicy: Always`; digests use `IfNotPresent`), so a moving tag can run different code between two tests. The UI marks such entries ⚠.
- **Private or air-gapped clusters** can't pull the built-in Docker Hub references: mirror them and point `--probe-images-file` at the mirror.
- The UI won't offer a protocol the chosen image doesn't list.

### Image requirements

| Protocol | Needs on `PATH` |
|---|---|
| TCP | GNU-compatible `timeout` (`-k`, duration suffixes) and OpenBSD-compatible `nc` (`-n -z -v -w`) |
| UDP | Additionally, **Python 3 with its standard library**, including `socket` and `ipaddress`; no dependencies are installed at runtime |

The image must support these exact direct argv patterns (no shell):

```text
timeout -k 1s 8s nc -n -z -v -w 5 <unicast-IP-literal> <port>
timeout -k 1s 8s nc -z -v -w 5 <DNS-hostname> <port>
timeout -k 1s 8s python3 -I -c <fixed-GuardBee-UDP-program> <host> <port>
```

> Verify those binaries under UID/GID 65532, no capabilities, read-only root filesystem, and RuntimeDefault seccomp before enabling probes. Startup validates the catalog and reference syntax, not binary availability. A test reports runtime failures explicitly if a required executable is missing, and missing Python or incompatible executables produce a failed/inconclusive attempt, not evidence that traffic was generated.

### What the UDP program sends

- It calls `getaddrinfo(AF_UNSPEC, SOCK_DGRAM)` and validates the first resolved IPv4/IPv6 address.
- It refuses unsafe resolved addresses before sending: loopback, link-local, multicast, unspecified, scoped IPv6, and limited broadcast, including IPv4-mapped IPv6.
- It calls `sendto` **exactly once** with the fixed 27-byte UTF-8/ASCII marker `guardbee-connectivity-probe`. Unlike `nc -uz`, it actually generates a datagram.
- It waits for no reply, performs no retry, and never permits an arbitrary payload. Host and port are separate argv values, never interpolated into the program.
- The socket has a five-second timeout; the external `timeout` also bounds DNS resolution.

The TCP path (`nc`) does not re-check the address a hostname resolves to inside the Pod; it relies on the hostname naming a readable Service in the cluster domain (see [targets](#targets-ips-and-hostnames)).

> **Choose a target you own and have approved for this traffic.** An unexpected marker may be rejected, logged, or interpreted by the target's application. It is not an application-protocol health check and is not safe to send blindly to arbitrary database or other endpoints.

---

## Safety and permissions

### Who can reach the server

The writable server binds **only a numeric loopback address**. Open it using that exact IP address, not `localhost` or another hostname (a page opened on `localhost` is redirected to the numeric address). POST checks JSON content type and exact same-origin Origin/Host, and rejects DNS hosts and cross-site fetches. This prevents DNS rebinding and cross-origin browser writes. It is not remote hosting or multi-user authentication.

### RBAC

- **Existing read-only RBAC is unchanged.** `kubernetes/probes-rbac.yaml` is an optional namespace-scoped grant for `pods` get/list, `pods/ephemeralcontainers` **update**, and `pods/log` get. Change its namespace and subject before applying it yourself. Standard Kubernetes authenticated discovery access must also allow SelfSubjectAccessReview creation.
- **The `guardbee-read` ClusterRole** in `kubernetes/rbac.yaml` includes `list` on `networking.k8s.io/networkpolicies` across namespaces for the simulation completeness check, plus the Service and EndpointSlice reads.
- Both manifests bind the example ServiceAccount `guardbee/guardbee`; personal kubeconfig users use their own existing grants or an administrator-managed User/Group binding. GuardBee uses client-go directly, not a kubectl subprocess, and never applies or grants RBAC itself.
- **Each request** checks authorization on the exact Pod name and subresources, verifies its UID, then re-reads it after capture readiness and submits UID plus resourceVersion on the ephemeral-container PUT. Conflicts are not retried.

### The injected container

- No mounts, environment or token. It runs nonroot, drops ALL capabilities, disables privilege escalation, and uses a read-only filesystem and seccomp.
- **Excluded Pods:** host-network/PID/IPC, shared process namespace, mirror/static, terminating, unready, and Windows Pods.
- **Excluded namespaces:** `kube-*`, `cilium-system`, and `hubble-system`. Other namespaces are constrained by the operator's namespace-scoped RBAC and admission policy, not a new CLI namespace allowlist.

> Admission must enforce any further workload/image restrictions; GuardBee cannot verify every cluster-specific safety rule. Probe containers have no resource guarantees, so use them carefully on sensitive workloads.

### Limits

| Limit | Value |
|---|---|
| Concurrent requests | 2 globally, 1 per Pod |
| GuardBee ephemeral entries | 8 per Pod, 32 total |
| JSON request body | 256 KiB |
| Probe logs read | 4 KiB |
| Flows captured | 256 |
| Request deadline (status, logs, capture, API calls) | 30 seconds |
| Pod enumeration deadline | 10 seconds |
| Probe command runtime | 8 seconds, force-killed after at most 1 more |

> HTTP cancellation cancels Kubernetes reads and Hubble capture, but cannot kill an already injected container without additional mutation privileges. The image's `timeout` stops `nc`/Python independently. Image pull and scheduling delays are outside that command-runtime bound: Kubernetes can start the container after the request ends.

---

## When simulation is withheld

Simulation uses the same real pinned Cilium engine as `verdict` (`judgeFlow`, the shared `buildVerdictEnginesWith` rule-construction core, `toVerdictResponse`), with the **full cluster-wide CNP/CCNP inventory**, so a destination in another namespace retains its ingress policy. The inspected inventory is the one used for engine construction, not a second potentially changed list.

Some things the standalone engine can't reproduce. Rather than give a reassuring answer from incomplete context, the test withholds its prediction:

| When | Then |
|---|---|
| A Kubernetes NetworkPolicy is in the correlated flow's source or destination namespace, or those namespaces' inventory can't be read | Simulation is suppressed: those policies are not part of this engine baseline. A NetworkPolicy's podSelector only selects Pods in its own namespace, so ones elsewhere in the cluster are ignored |
| A CNP in those namespaces, any CCNP, or the candidate uses FQDN/L7 proxy semantics, `toServices`, named ports, or authentication (including test-always-fail) | Simulation is suppressed: the standalone endpoint owner does not provide those agent-side mechanisms. Out-of-scope CNPs still go to the engine |
| Any baseline or candidate uses `cidrGroupRef` or `cidrGroupSelector` | Simulation is suppressed with an explicit **unverified** warning |
| A baseline policy fails to parse | Simulation is suppressed |
| Lost-event notifications, capture errors, overflow, or deadline cancellation | Simulation is suppressed; the observed flows and TCP/UDP runtime outcome are kept |
| A Hubble node is reported unavailable | The capture is incomplete only when it is the source Pod's node, or may be the destination's (a Pod destination with no destination-side events) |

Deprecated raw baseline fields are checked before Parse can silently discard them.

**Replace vs additive.** Candidate semantics follow Verdict's shared **Replace matching live policies** setting. Replacement removes policies with the same kind, namespace, and name only from the candidate engine; the original baseline remains unchanged. Turning the setting off explicitly selects additive simulation, which can retain permissions removed by an edited candidate. The submitted snapshot records the chosen mode.

<details markdown="1">
<summary>Why CIDR groups are marked unverified</summary>

Cilium's real agent injects CIDR-group labels through IPcache; existing Hubble identities may already carry those labels and the engine can select them. What is not reproduced or verified here is membership and new candidate identity injection. GuardBee does not manually translate groups to CIDRs or issue a reassuring result from incomplete context.

</details>

<details markdown="1">
<summary>How capture and correlation work</summary>

Capture starts before injection and waits for GetFlows headers and the source node's NODE_CONNECTED event as a relay availability health gate. This is not an acknowledgement that the source-node collector has subscribed: relay marks nodes connected before the collector's GetFlows goroutine runs. This race is best-effort, and missing evidence is explicitly inconclusive. A capture startup failure produces an inconclusive result and **does not inject** a container.

Capture correlates outgoing TCP/UDP flows by exact namespace/Pod, protocol, destination IP or normalized Hubble destination DNS name, port, and attempt window, excluding replies. The bounded relay drain is two seconds, outside the attempt's correlation window; collector readiness and relay delivery still remain best-effort.

**Attribution remains best-effort:** Hubble does not identify the ephemeral container, and the generated source port is not known. Concurrent application traffic to the same destination can appear in the result. Service DNAT, clock skew, relay buffering, dropped events, or unavailable nodes can also hide evidence.

</details>

---

## Reviewing and diagnosing a test

- **Each run tests its own frozen candidate.** A run card's **Connectivity tests** section uses that run's candidate, scope and replace/additive mode, so a result always belongs to the policy version that run judged; editing the Verdict form later doesn't touch it.
- **One test at a time** across all runs. A live-following run can't be tested until it stops, and while a test is in flight neither a new run nor removing that run's card is allowed (either could drop the result).
- **Stale results are marked:** changing the test's own inputs (Pod, host, port, image) marks an older result stale without rewriting the submitted snapshot.
- **Download test report (JSON)** preserves the exact request, candidate, response, cluster context, configured image reference, Pod UID, and timing for review.
- **All-namespaces mode:** choosing a source namespace does not supply a missing candidate namespace. A namespaced CNP must declare its own `metadata.namespace`.
- **A previous GuardBee container still pending or running** blocks another test on that Pod, including after a client disconnect or server restart. Inspect the named container; do not restart the workload just to retry. An uncertain ephemeral update reports its generated name; inspect the Pod before retrying.
- Image-pull and container-creation errors are surfaced explicitly. Missing executables or an unverified runtime cannot yield a prediction from unrelated workload traffic.

### Live progress

The UI reports each stage as the server reaches it. The stepper only shows stages the server reported, never a timer's guess; a stage never reached shows as skipped.

| Stage | What happens |
|---|---|
| `authorize` | RBAC and Pod checks |
| `capture` | Hubble capture starts, before anything is injected |
| `inject` | The ephemeral container is appended |
| `run` | The probe command runs |
| `collect` | Flows are collected and correlated |
| `simulate` | The candidate is judged (only when a candidate is simulated) |

The result is drawn as the path the traffic took: the source Pod, the policy gate, and the destination, with one lane for the live baseline and one for the candidate. An allowed lane flows end to end, a blocked lane stops at the gate, and an inconclusive lane is dashed with a "?".

### Troubleshooting an inconclusive test

Start the server with `--debug` (`guardbee ui --debug --enable-probes …`). For each test it logs, to stderr only:

- the Service a hostname resolved to (its address and port counts);
- the exact Hubble filter, and relay node state changes;
- the probe container's own output (for example `nc`'s resolved address);
- one line per captured flow with the reason it was or wasn't correlated (`destination IP differs`, `outside the probe container's run window`, …);
- which namespace's Kubernetes NetworkPolicy gated the simulation.

The UI shows the attempt's own problems as warnings; the standing caveats every test carries are under **Evidence & limitations → About this test**.

> **See TCP and UDP probes live:** the [Zero-trust walkthrough](zero-trust-walkthrough.html) (video: [Videos → Zero-trust](videos.html#zero-trust)) demonstrates both a `netshoot` **UDP** probe and `BusyBox 1.37` **TCP** probes flipping from `BLOCKED` to `ALLOWED` as each policy layer is added.

---

## API reference

For scripting against `guardbee ui --enable-probes`. The UI uses the same endpoints.

| Endpoint | Returns |
|---|---|
| `GET /api/probes/capabilities` | Whether probes are enabled, and the image catalog the UI picks from |
| `GET /api/probes/pods?namespace=app` | The eligible running Pods in a namespace (requires probes enabled) |
| `POST /api/probes/connection` | Runs a test, after explicit per-request UI confirmation, and answers with one JSON response |
| `POST /api/probes/connection/stream` | The same request, reported as [NDJSON stages](#live-progress) and one terminal line |

```json
// GET /api/probes/capabilities — "enabled": false by default; with probes enabled:
{ "enabled": true, …, "image": "…", "images": [{ "id": "…", "name": "…", "image": "…", "protocols": ["TCP", "UDP"], "description": "…", "pinned": true }] }

// GET /api/probes/pods?namespace=app
{ "pods": [{ "name": "client", "uid": "…" }], "excluded": { "<reason>": 2 } }
```

- **`images`** is the catalog; `pinned` means referenced by digest. The top-level `image` is the default (first) entry's reference.
- **`pods`** lists only eligible running Pods. The optional `excluded` maps ineligibility reasons to counts, so an empty picker can explain unready Pods, unsupported network/process settings, or an earlier pending test.

### Request

```json
{ "namespace": "app", "pod": "client", "uid": "…", "host": "192.0.2.2", "port": 443, "protocol": "TCP", "candidateYAML": "CNP/CCNP YAML" }
```

| Field | Rules |
|---|---|
| `namespace`, `pod`, `uid` | The source Pod; its UID is verified |
| `host`, `port` | The target: an IP literal or a DNS hostname, see [targets](#targets-ips-and-hostnames) |
| `protocol` | Required, exactly uppercase `TCP` or `UDP` |
| `candidateYAML` | Optional for API diagnostics; omit it only when no candidate prediction is needed. A supplied candidate is validated before injection |
| `candidateNamespace` | Defaults independently of the source Pod: omitted uses the source namespace for backward compatibility; explicit `""` requires a CNP to declare its namespace |
| `replaceExisting` | Defaults to `true` for probes; the Web UI always supplies its shared simulation-mode setting |
| `imageId` | Picks a catalog entry by id (omitted: the default entry). An unknown id, a protocol the entry doesn't list, or any raw `image` field is rejected with `400` before anything is injected |

### Response

| Field | Content |
|---|---|
| `namespace`, `pod`, `host`, `port`, `protocol` | Echo of the request |
| `outcome` | `connected` (TCP), `generated` (UDP), `failed`, or `inconclusive` |
| `message` | Human-readable summary |
| `containerName`, `image`, `imageId` | What was injected (optional) |
| `flows` | The existing `flowOut` API shape plus `count`: one connection's identical trace events are folded into one row |
| `simulation` | Optional; the existing `verdictResponse`, rows folded the same way the `verdict` command folds them, plus `baselineAllowed`/`candidateAllowed` per row |
| `warnings` | Always an array: this attempt's own problems |
| `notes` | Always an array of `{ "code", "text" }`: the standing caveats every attempt carries |

Note `code`s are stable: `ephemeral-entry`, `runtime-bound`, `best-effort-correlation`, `service-match`, `udp-marker`, `nodes-off-path`, `replace-mode`, `additive-mode`, `policy-replaced`. The UI titles notes by code, never by parsing `text`. Its downloaded test report is `schemaVersion: 2` since `notes` replaced the earlier `notices` string list.

### Status codes

| Status | When |
|---|---|
| `400` | Invalid inputs |
| `403` | Probes disabled, authorization or origin failures |
| `409` | Stale or ineligible Pods, entry limits |
| `422` | A hostname that can't be tied to a flow (see below) |
| `429` | Concurrency limits |

On the stream endpoint, each stage is one NDJSON line (`{"stage":"capture"}`), then exactly one terminal line: `{"result":{…}}` or `{"error":"…","status":409}`.

- A rejection before the first stage stays an ordinary HTTP status. A rejection after it keeps the same status in its error line, so "nothing was injected" means the same thing on both endpoints.
- A stream that ends with no terminal line is treated as uncertain: something may already have been injected.

### Targets: IPs and hostnames

Loopback, link-local, multicast, unspecified, and limited-broadcast targets are rejected because they do not provide the intended normal network-policy path. DNS hostnames (case-insensitive, optional trailing dot) resolve inside the Pod, never server-side.

| Hostname | Result |
|---|---|
| An in-cluster Service name: `<svc>`, `<svc>.<ns>`, `<svc>.<ns>.svc[.cluster.local]` | Runs; correlated through that Service's ClusterIPs and current EndpointSlice addresses |
| A Service-shaped name GuardBee may not read (`get` services forbidden) | Still runs, with a warning |
| Any other hostname: an external site such as `www.google.com`, a name the Service lookup doesn't find, or `<svc>.<ns>.svc.<anything-but-cluster.local>` | **Refused with `422` before anything is injected.** Target the IP instead (resolve it inside the Pod, for example with `nslookup`) |
| A legacy numeric form, every label a number in some `inet_aton` base (`127.1`, `2130706433`, `0177.0.0.1`, `0x7f.1`, `0x7f000001`) | Refused |

In the UI, the Host field suggests the cluster's Services (`list` services), and picking one fills its port; without that permission it suggests the Services seen in this session's verdict flows.

<details markdown="1">
<summary>Why hostnames are restricted this way</summary>

- **Numeric forms:** some resolvers and `nc` builds read a hostname like `127.1` as an IP that skipped the literal address checks. Names like `api-0`, `v1` or `0a.example` are unaffected.
- **External names:** without Hubble DNS visibility nothing on a flow ties it to that name, so the run could only end inconclusive. `<svc>.<ns>.svc.<anything-but-cluster.local>` is refused because `nc` would resolve it as an external name; a custom cluster domain is not supported yet.
- **Positive evidence only:** hostname flow correlation needs positive evidence, never just the port: an exact normalized Hubble destination name, the flow's destination Service, or, for an in-cluster Service name, a destination that is one of that Service's ClusterIPs or current EndpointSlice addresses, on the requested port or the target port it maps to.
- **Why the API read:** that last form is read from the API (`get` services, `list` endpointslices) because socket-level load balancing rewrites the ClusterIP before Hubble sees the packet, so most clusters report neither names nor a Service.
- Aliases and mesh interception stay inconclusive even when traffic generation succeeds.
- Operator network/admission controls must constrain DNS-resolved targets; the server cannot safely resolve them in the Pod's DNS context.

</details>
