package main

// Phase 1 "engine spike" from the design doc: prove Cilium's own pkg/policy
// engine can be driven to a real ALLOW/DENY verdict standalone — no live
// agent, no datapath, no cluster connection. This is the pattern Cilium's own
// distillery_test.go uses to test the engine without a running endpoint.
//
// Scenario: one ingress rule allows "role=frontend" -> "role=backend" on
// TCP/80. We resolve policy for "backend" and assert:
//   - frontend -> backend:80/TCP is ALLOWED (matches the rule)
//   - frontend -> backend:81/TCP is DENIED (policy selects backend, so
//     anything not explicitly allowed is default-deny)

import (
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/u8proto"
)

// spikeOwner is a minimal policy.PolicyOwner stub — the engine needs an
// "endpoint" to distill policy for, but doesn't need a real one to compute
// the verdict.
type spikeOwner struct{}

func (spikeOwner) GetID() uint64                                                 { return 1 }
func (spikeOwner) GetIngressNamedPort(name string, proto u8proto.U8proto) uint16 { return 0 }
func (spikeOwner) PolicyDebug(msg string, attrs ...any)                          {}
func (spikeOwner) IsHost() bool                                                  { return false }
func (spikeOwner) PreviousMapStateSizes() policy.MapStateSizes                   { return policy.MapStateSizes{} }
func (spikeOwner) RegenerateIfAlive(_ *regeneration.ExternalRegenerationMetadata) <-chan bool {
	return nil
}

const (
	// Must be >= identity.MinimalNumericIdentity (256) — below that range is
	// reserved for Cilium's own special identities and is handled differently
	// by the policy engine.
	frontendNID identity.NumericIdentity = 1000
	backendNID  identity.NumericIdentity = 2000
)

func TestEngineSpike(t *testing.T) {
	logger := hivetest.Logger(t)

	frontendLabels := labels.ParseLabelArray("role=frontend")
	backendLabels := labels.ParseLabelArray("role=backend")

	backendIdentity := identity.NewIdentity(backendNID, backendLabels.Labels())

	initialIDs := identity.IdentityMap{
		frontendNID: frontendLabels,
		backendNID:  backendLabels,
	}

	idMgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(
		logger,
		nil,
		nil,
		envoypolicy.NewEnvoyL7RulesTranslator(logger, certificatemanager.NewMockSecretManagerInline()),
		idMgr,
		testpolicy.NewPolicyMetricsNoop(),
	)

	rule := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("role=backend")),
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseSelectLabel("role=frontend")),
					},
				},
				ToPorts: api.PortRules{
					{Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}}},
				},
			},
		},
	}

	wg := &sync.WaitGroup{}
	repo.GetSelectorCache().UpdateIdentities(initialIDs, nil, wg)
	wg.Wait()
	// Separate from the peer selector cache above — ComputeSelectorPolicy
	// reads subject-matching (rule.EndpointSelector) state from here, and it
	// must be updated too or rules never match any identity as their subject.
	repo.UpdateIdentities(initialIDs, nil)

	repo.MustAddList(api.Rules{&rule})

	sp, err := repo.ResolvePolicy(backendIdentity)
	if err != nil {
		t.Fatalf("ResolvePolicy: %v", err)
	}

	epp := sp.DistillPolicy(logger, spikeOwner{}, map[string]uint16{})
	if epp == nil {
		t.Fatal("DistillPolicy returned nil")
	}
	epp.Ready()
	defer epp.Detach(logger)

	allowedKey := policy.IngressKey().WithIdentity(frontendNID).WithTCPPort(80)
	deniedKey := policy.IngressKey().WithIdentity(frontendNID).WithTCPPort(81)

	if entry, ok := epp.Get(allowedKey); !ok || !entry.IsAllow() {
		t.Fatalf("expected frontend->backend:80/TCP to be ALLOWED, got ok=%v entry=%+v", ok, entry)
	}
	if entry, ok := epp.Get(deniedKey); ok && entry.IsAllow() {
		t.Fatalf("expected frontend->backend:81/TCP to be DENIED (default-deny), got allowed entry=%+v", entry)
	}

	t.Logf("engine spike PASS: real Cilium pkg/policy computed correct ALLOW/DENY verdicts standalone")
}
