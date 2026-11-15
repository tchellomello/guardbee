package main

// Checks flowWhitelist against Hubble's own server-side filter code
// (pkg/hubble/filters, what hubble-relay/the agent run on GetFlows), not
// against this file's idea of how Whitelist entries combine: the OR-across-
// entries / AND-within-an-entry rule, prefix matching and the "bare name
// means default namespace" behavior all come from there.

import (
	"context"
	"log/slog"
	"slices"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func testFlow(srcNs, srcPod, dstNs, dstPod string, dstLabels []string, dstSvc string, port uint32) *flowpb.Flow {
	f := &flowpb.Flow{
		Source:      &flowpb.Endpoint{Namespace: srcNs, PodName: srcPod},
		Destination: &flowpb.Endpoint{Namespace: dstNs, PodName: dstPod, Labels: dstLabels},
		L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: port}}},
		Verdict:     flowpb.Verdict_FORWARDED,
	}
	if dstSvc != "" {
		f.DestinationService = &flowpb.Service{Name: dstSvc, Namespace: dstNs}
	}
	return f
}

func TestFlowWhitelist(t *testing.T) {
	appToDB := testFlow("app", "web-1", "app", "db-0", []string{"k8s:app=db"}, "db", 5432)
	appToDB.Source.Labels = []string{"k8s:app=web"}
	appToDB.IP = &flowpb.IP{Source: "10.0.1.5", Destination: "10.0.1.9"}
	appToAPIServer := testFlow("app", "web-1", "", "", []string{"reserved:kube-apiserver"}, "", 443)
	appToAPIServer.IP = &flowpb.IP{Source: "10.0.1.5", Destination: "172.18.0.3"}
	appToOtherNs := testFlow("app", "web-1", "other", "cache-0", []string{"k8s:app=cache"}, "cache", 6379)
	appToOtherNs.Verdict = flowpb.Verdict_DROPPED
	appToOtherNs.DropReasonDesc = flowpb.DropReason_POLICY_DENIED
	otherToApp := testFlow("other", "cache-0", "app", "db-0", []string{"k8s:app=db"}, "db", 5432)
	otherToOther := testFlow("other", "a-0", "other", "cache-0", []string{"k8s:app=cache"}, "cache", 6379)
	worldToApp := testFlow("", "", "app", "web-1", []string{"k8s:app=web"}, "", 8080)
	worldToApp.Source.Labels = []string{"reserved:world"}
	worldToApp.IP = &flowpb.IP{Source: "203.0.113.7", Destination: "10.0.1.5"}
	worldToApp.Verdict = flowpb.Verdict_DROPPED
	worldToApp.DropReasonDesc = flowpb.DropReason_POLICY_DENY

	all := map[string]*flowpb.Flow{
		"appToDB": appToDB, "appToAPIServer": appToAPIServer, "appToOtherNs": appToOtherNs,
		"otherToApp": otherToApp, "otherToOther": otherToOther, "worldToApp": worldToApp,
	}

	cases := []struct {
		name      string
		namespace string
		filter    flowFilter
		want      []string
	}{
		{"namespace only", "app", flowFilter{}, []string{"appToDB", "appToAPIServer", "appToOtherNs", "otherToApp", "worldToApp"}},
		{"bare pod qualified with scope namespace", "app", flowFilter{toPods: []string{"db"}}, []string{"appToDB", "otherToApp"}},
		// The --to-pod is outside the scope namespace, so only flows *from*
		// the namespace can match; the "to namespace" half is dropped
		// rather than ORed into a filter that would match any pod in app.
		{"pod in another namespace", "app", flowFilter{toPods: []string{"other/cache"}}, []string{"appToOtherNs"}},
		{"label", "app", flowFilter{toLabels: []string{"reserved:kube-apiserver"}}, []string{"appToAPIServer"}},
		{"service", "app", flowFilter{toServices: []string{"db"}}, []string{"appToDB", "otherToApp"}},
		{"port", "app", flowFilter{toPorts: []string{"6379"}}, []string{"appToOtherNs"}},
		{"fields AND together", "app", flowFilter{toLabels: []string{"k8s:app=db"}, toPorts: []string{"443"}}, nil},
		{"values OR together", "app", flowFilter{toPorts: []string{"443", "6379"}}, []string{"appToAPIServer", "appToOtherNs"}},
		{"all namespaces unfiltered", "", flowFilter{}, []string{"appToDB", "appToAPIServer", "appToOtherNs", "otherToApp", "otherToOther", "worldToApp"}},
		{"all namespaces with label", "", flowFilter{toLabels: []string{"k8s:app=cache"}}, []string{"appToOtherNs", "otherToOther"}},

		// Source side, mirroring the destination cases above.
		{"from pod in the namespace", "app", flowFilter{fromPods: []string{"web"}}, []string{"appToDB", "appToAPIServer", "appToOtherNs"}},
		// --from-pod outside the namespace: only the "to namespace" half
		// can match, so it's flows from that pod into app.
		{"from pod in another namespace", "app", flowFilter{fromPods: []string{"other/cache"}}, []string{"otherToApp"}},
		{"from pod and to pod", "app", flowFilter{fromPods: []string{"web"}, toPods: []string{"db"}}, []string{"appToDB"}},
		{"from entity", "app", flowFilter{fromLabels: []string{"reserved:world"}}, []string{"worldToApp"}},
		{"from label", "app", flowFilter{fromLabels: []string{"k8s:app=web"}}, []string{"appToDB"}},

		// IPs and CIDRs, as hubble's own --from-ip/--to-ip accept.
		{"to ip exact", "app", flowFilter{toIPs: []string{"172.18.0.3"}}, []string{"appToAPIServer"}},
		{"from cidr", "app", flowFilter{fromIPs: []string{"203.0.113.0/24"}}, []string{"worldToApp"}},
		{"to cidr", "", flowFilter{toIPs: []string{"10.0.0.0/8"}}, []string{"appToDB", "worldToApp"}},

		// Verdict and drop reason, the observed (Hubble) verdict.
		{"dropped only", "app", flowFilter{verdicts: []flowpb.Verdict{flowpb.Verdict_DROPPED}}, []string{"appToOtherNs", "worldToApp"}},
		{"forwarded only", "app", flowFilter{verdicts: []flowpb.Verdict{flowpb.Verdict_FORWARDED}}, []string{"appToDB", "appToAPIServer", "otherToApp"}},
		{"drop reason", "app", flowFilter{dropReasons: []flowpb.DropReason{flowpb.DropReason_POLICY_DENIED}}, []string{"appToOtherNs"}},
		{"drop reasons OR together", "app", flowFilter{dropReasons: []flowpb.DropReason{flowpb.DropReason_POLICY_DENIED, flowpb.DropReason_POLICY_DENY}}, []string{"appToOtherNs", "worldToApp"}},
		{"dropped from world", "app", flowFilter{verdicts: []flowpb.Verdict{flowpb.Verdict_DROPPED}, fromLabels: []string{"reserved:world"}}, []string{"worldToApp"}},
	}

	logger := slog.New(slog.DiscardHandler)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			whitelist, err := flowWhitelist(tc.namespace, tc.filter)
			if err != nil {
				t.Fatalf("flowWhitelist: %v", err)
			}
			wl, err := filters.BuildFilterList(context.Background(), whitelist, filters.DefaultFilters(logger))
			if err != nil {
				t.Fatalf("Hubble rejected the whitelist: %v", err)
			}
			want := map[string]bool{}
			for _, n := range tc.want {
				want[n] = true
			}
			for name, f := range all {
				if got := filters.Apply(wl, nil, &v1.Event{Event: f}); got != want[name] {
					t.Errorf("%s: matched=%v, want %v", name, got, want[name])
				}
			}
		})
	}
}

// Both pods outside the namespace leave no half of the whitelist that can
// match. That must be an error: an empty Whitelist means "every flow" to
// Hubble, the opposite of what was asked.
func TestFlowWhitelistBothPodsOutsideNamespace(t *testing.T) {
	_, err := flowWhitelist("app", flowFilter{fromPods: []string{"other/a"}, toPods: []string{"other/b"}})
	if err == nil {
		t.Fatal("want an error, got a whitelist")
	}
}

// --verdict/--drop-reason-desc accept exactly Cilium's enum names, like
// hubble observe; anything else (including the UNKNOWN placeholders and
// lowercase) is rejected rather than silently matching nothing.
func TestFlowFilterFlagsParse(t *testing.T) {
	ok := flowFilterFlags{verdicts: []string{"DROPPED", "AUDIT"}, dropReasons: []string{"POLICY_DENIED"}}
	f, err := ok.parse()
	if err != nil {
		t.Fatalf("valid values: %v", err)
	}
	if len(f.verdicts) != 2 || f.dropReasons[0] != flowpb.DropReason_POLICY_DENIED {
		t.Fatalf("parsed %+v", f)
	}
	for _, bad := range []flowFilterFlags{
		{verdicts: []string{"dropped"}},
		{verdicts: []string{"VERDICT_UNKNOWN"}},
		{dropReasons: []string{"NOT_A_REASON"}},
		{dropReasons: []string{"DROP_REASON_UNKNOWN"}},
	} {
		if _, err := bad.parse(); err == nil {
			t.Errorf("%+v: want an error", bad)
		}
	}
	if got := (flowFilter{verdicts: []flowpb.Verdict{flowpb.Verdict_DROPPED}, fromIPs: []string{"10.0.0.0/8"}}).String(); got != "--from-ip 10.0.0.0/8 --verdict DROPPED" {
		t.Errorf("String() = %q", got)
	}
}

// hubble-relay asks each node for Number flows and merges them, so a
// multi-node cluster returns more than --last asked for, not necessarily in
// order. newestFlows must hand back the newest N, oldest first.
func TestNewestFlows(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(sec int, node string) *flowpb.Flow {
		return &flowpb.Flow{Time: timestamppb.New(base.Add(time.Duration(sec) * time.Second)), NodeName: node}
	}
	// Two nodes' replies to Number=3, interleaved out of order.
	merged := []*flowpb.Flow{at(5, "a"), at(1, "b"), at(6, "b"), at(2, "a"), at(4, "b"), at(3, "a")}

	got := newestFlows(merged, 3)
	var secs []int
	for _, f := range got {
		secs = append(secs, int(f.GetTime().AsTime().Sub(base).Seconds()))
	}
	if want := []int{4, 5, 6}; !slices.Equal(secs, want) {
		t.Fatalf("newestFlows kept %v, want %v", secs, want)
	}

	if got := newestFlows([]*flowpb.Flow{at(1, "a")}, 3); len(got) != 1 {
		t.Fatalf("fewer flows than requested should all be kept, got %d", len(got))
	}
}

// --pod (either side) and --type, against Hubble's own filters like
// TestFlowWhitelist. The scope namespace and --pod are each either-side
// constraints, so they combine into up to four Whitelist entries; these
// cases pin down that the combination still means "AND".
func TestFlowWhitelistPodAndType(t *testing.T) {
	pv := &flowpb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict}
	trace := &flowpb.CiliumEventType{Type: monitorAPI.MessageTypeTrace}
	mk := func(srcNs, srcPod, dstNs, dstPod, dstIP string, ev *flowpb.CiliumEventType) *flowpb.Flow {
		f := testFlow(srcNs, srcPod, dstNs, dstPod, nil, "", 443)
		f.IP = &flowpb.IP{Destination: dstIP}
		f.EventType = ev
		return f
	}
	all := map[string]*flowpb.Flow{
		"webEgressToIP":   mk("app", "web-1", "", "", "169.254.169.254", pv),
		"clientToWeb":     mk("app", "client-0", "app", "web-1", "10.0.1.5", pv),
		"webToDB":         mk("app", "web-1", "app", "db-0", "10.0.1.9", pv),
		"apiToDB":         mk("app", "api-0", "app", "db-0", "10.0.1.9", pv),
		"webTrace":        mk("app", "web-1", "", "", "169.254.169.254", trace),
		"otherNsToWeb":    mk("other", "cache-0", "app", "web-1", "10.0.1.5", pv),
		"otherNsInternal": mk("other", "a-0", "other", "web-9", "10.0.2.5", pv),
		"defaultWeb":      mk("default", "web-2", "", "", "1.1.1.1", pv),
	}
	cases := []struct {
		name      string
		namespace string
		filter    flowFilter
		want      []string
	}{
		{"pod either side", "app", flowFilter{pods: []string{"web"}},
			[]string{"webEgressToIP", "clientToWeb", "webToDB", "webTrace", "otherNsToWeb"}},
		{"pod and policy-verdict type", "app", flowFilter{pods: []string{"web"}, types: []string{"policy-verdict"}},
			[]string{"webEgressToIP", "clientToWeb", "webToDB", "otherNsToWeb"}},
		{"trace type only", "app", flowFilter{types: []string{"trace"}}, []string{"webTrace"}},
		// hubble rejects --pod with --to-ip; here they AND: web's own traffic to the IP.
		{"pod and to ip", "app", flowFilter{pods: []string{"web"}, toIPs: []string{"169.254.169.254"}, types: []string{"policy-verdict"}},
			[]string{"webEgressToIP"}},
		{"pod and to pod", "app", flowFilter{pods: []string{"web"}, toPods: []string{"db"}}, []string{"webToDB"}},
		{"pod and from pod", "app", flowFilter{pods: []string{"web"}, fromPods: []string{"client"}}, []string{"clientToWeb"}},
		// The pod is in another namespace: still only flows touching app.
		{"pod outside scope namespace", "app", flowFilter{pods: []string{"other/cache"}}, []string{"otherNsToWeb"}},
		{"cluster-wide pod", "", flowFilter{pods: []string{"app/web"}},
			[]string{"webEgressToIP", "clientToWeb", "webToDB", "webTrace", "otherNsToWeb"}},
		// A bare --pod with -A means the default namespace, as Hubble reads it.
		{"cluster-wide bare pod is default namespace", "", flowFilter{pods: []string{"web"}}, []string{"defaultWeb"}},
	}
	logger := slog.New(slog.DiscardHandler)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			whitelist, err := flowWhitelist(tc.namespace, tc.filter)
			if err != nil {
				t.Fatalf("flowWhitelist: %v", err)
			}
			wl, err := filters.BuildFilterList(context.Background(), whitelist, filters.DefaultFilters(logger))
			if err != nil {
				t.Fatalf("Hubble rejected the whitelist: %v", err)
			}
			want := map[string]bool{}
			for _, n := range tc.want {
				want[n] = true
			}
			for name, f := range all {
				if got := filters.Apply(wl, nil, &v1.Event{Event: f}); got != want[name] {
					t.Errorf("%s: matched=%v, want %v", name, got, want[name])
				}
			}
		})
	}

	if _, err := flowWhitelist("app", flowFilter{pods: []string{"web"}, fromPods: []string{"x/a"}, toPods: []string{"y/b"}}); err == nil {
		t.Error("--pod with --from-pod/--to-pod that can't all hold: want an error")
	}
}

// --type takes hubble's event type names only.
func TestFlowFilterFlagsParseType(t *testing.T) {
	if _, err := (&flowFilterFlags{f: flowFilter{types: []string{"policy-verdict", "drop"}}}).parse(); err != nil {
		t.Fatalf("valid types: %v", err)
	}
	for _, bad := range []string{"policy_verdict", "5", "trace:to-endpoint", ""} {
		if _, err := (&flowFilterFlags{f: flowFilter{types: []string{bad}}}).parse(); err == nil {
			t.Errorf("--type %q: want an error", bad)
		}
	}
	if got := (flowFilter{pods: []string{"app/web"}, types: []string{"policy-verdict"}}).String(); got != "--pod app/web --type policy-verdict" {
		t.Errorf("String() = %q", got)
	}
}
