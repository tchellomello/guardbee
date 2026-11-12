package main

// Checks flowWhitelist against Hubble's own server-side filter code
// (pkg/hubble/filters, what hubble-relay/the agent run on GetFlows), not
// against this file's idea of how Whitelist entries combine: the OR-across-
// entries / AND-within-an-entry rule, prefix matching and the "bare name
// means default namespace" behavior all come from there.

import (
	"context"
	"log/slog"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
)

func testFlow(srcNs, srcPod, dstNs, dstPod string, dstLabels []string, dstSvc string, port uint32) *flowpb.Flow {
	f := &flowpb.Flow{
		Source:      &flowpb.Endpoint{Namespace: srcNs, PodName: srcPod},
		Destination: &flowpb.Endpoint{Namespace: dstNs, PodName: dstPod, Labels: dstLabels},
		L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: port}}},
	}
	if dstSvc != "" {
		f.DestinationService = &flowpb.Service{Name: dstSvc, Namespace: dstNs}
	}
	return f
}

func TestFlowWhitelist(t *testing.T) {
	appToDB := testFlow("app", "web-1", "app", "db-0", []string{"k8s:app=db"}, "db", 5432)
	appToAPIServer := testFlow("app", "web-1", "", "", []string{"reserved:kube-apiserver"}, "", 443)
	appToOtherNs := testFlow("app", "web-1", "other", "cache-0", []string{"k8s:app=cache"}, "cache", 6379)
	otherToApp := testFlow("other", "cache-0", "app", "db-0", []string{"k8s:app=db"}, "db", 5432)
	otherToOther := testFlow("other", "a-0", "other", "cache-0", []string{"k8s:app=cache"}, "cache", 6379)

	all := map[string]*flowpb.Flow{
		"appToDB": appToDB, "appToAPIServer": appToAPIServer, "appToOtherNs": appToOtherNs,
		"otherToApp": otherToApp, "otherToOther": otherToOther,
	}

	cases := []struct {
		name      string
		namespace string
		dst       destinationFilter
		want      []string
	}{
		{"namespace only", "app", destinationFilter{}, []string{"appToDB", "appToAPIServer", "appToOtherNs", "otherToApp"}},
		{"bare pod qualified with scope namespace", "app", destinationFilter{pods: []string{"db"}}, []string{"appToDB", "otherToApp"}},
		// The --to-pod is outside the scope namespace, so only flows *from*
		// the namespace can match; the "to namespace" half is dropped
		// rather than ORed into a filter that would match any pod in app.
		{"pod in another namespace", "app", destinationFilter{pods: []string{"other/cache"}}, []string{"appToOtherNs"}},
		{"label", "app", destinationFilter{labels: []string{"reserved:kube-apiserver"}}, []string{"appToAPIServer"}},
		{"service", "app", destinationFilter{services: []string{"db"}}, []string{"appToDB", "otherToApp"}},
		{"port", "app", destinationFilter{ports: []string{"6379"}}, []string{"appToOtherNs"}},
		{"fields AND together", "app", destinationFilter{labels: []string{"k8s:app=db"}, ports: []string{"443"}}, nil},
		{"values OR together", "app", destinationFilter{ports: []string{"443", "6379"}}, []string{"appToAPIServer", "appToOtherNs"}},
		{"all namespaces unfiltered", "", destinationFilter{}, []string{"appToDB", "appToAPIServer", "appToOtherNs", "otherToApp", "otherToOther"}},
		{"all namespaces with label", "", destinationFilter{labels: []string{"k8s:app=cache"}}, []string{"appToOtherNs", "otherToOther"}},
	}

	logger := slog.New(slog.DiscardHandler)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wl, err := filters.BuildFilterList(context.Background(), flowWhitelist(tc.namespace, tc.dst), filters.DefaultFilters(logger))
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
