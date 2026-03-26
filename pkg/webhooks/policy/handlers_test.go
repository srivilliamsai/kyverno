package policy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
	openapiv2 "github.com/google/gnostic-models/openapiv2"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/pkg/clients/dclient"
	"github.com/kyverno/kyverno/pkg/event"
	"github.com/kyverno/kyverno/pkg/webhooks/handlers"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	k8s_fake "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8s_testing "k8s.io/client-go/testing"
)

type mockEventGenerator struct {
	events []event.Info
}

func (m *mockEventGenerator) Add(infoList ...event.Info) {
	m.events = append(m.events, infoList...)
}

type mockDiscovery struct {
	cached discovery.CachedDiscoveryInterface
}

func (m *mockDiscovery) CachedDiscoveryInterface() discovery.CachedDiscoveryInterface {
	return m.cached
}

func (m *mockDiscovery) FindResources(group, version, kind, subresource string) (map[dclient.TopLevelApiDescription]metav1.APIResource, error) {
	return nil, nil
}

func (m *mockDiscovery) GetGVRFromGVK(gvk schema.GroupVersionKind) (schema.GroupVersionResource, error) {
	return schema.GroupVersionResource{}, nil
}

func (m *mockDiscovery) GetGVKFromGVR(gvr schema.GroupVersionResource) (schema.GroupVersionKind, error) {
	return schema.GroupVersionKind{}, nil
}

func (m *mockDiscovery) OpenAPISchema() (*openapiv2.Document, error) {
	return nil, nil
}

func (m *mockDiscovery) OnChanged(callback func()) {}

func TestValidate_WildcardWarning(t *testing.T) {
	bg := false
	policy := &kyvernov1.ClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "wildcard-policy",
		},
		Spec: kyvernov1.Spec{
			Background: &bg,
			Rules: []kyvernov1.Rule{
				{
					Name: "wildcard-rule",
					MatchResources: kyvernov1.MatchResources{
						ResourceDescription: kyvernov1.ResourceDescription{
							Kinds: []string{"*"},
						},
					},
					Validation: &kyvernov1.Validation{
						Message: "test",
						Deny:    &kyvernov1.Deny{},
					},
				},
			},
		},
	}

	policyBytes, err := json.Marshal(policy)
	assert.NoError(t, err)

	req := handlers.AdmissionRequest{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID: "123",
			Kind: metav1.GroupVersionKind{
				Group:   "kyverno.io",
				Version: "v1",
				Kind:    "ClusterPolicy",
			},
			Operation: admissionv1.Create,
			Object: runtime.RawExtension{
				Raw: policyBytes,
			},
		},
	}

	fakeDisco := &k8s_fake.FakeDiscovery{Fake: &k8s_testing.Fake{}}
	fakeDisco.Fake.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{
					Name:         "pods",
					SingularName: "pod",
					Namespaced:   true,
					Kind:         "Pod",
					Verbs:        []string{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"},
				},
			},
		},
	}
	cachedDisco := memory.NewMemCacheClient(fakeDisco)
	mockDisco := &mockDiscovery{cached: cachedDisco}

	scheme := runtime.NewScheme()
	fakeDyn := fake.NewSimpleDynamicClient(scheme)
	fakeKube := kubefake.NewSimpleClientset()

	client := dclient.NewFakeClientWithDisco(fakeDyn, fakeKube, mockDisco)

	eventGen := &mockEventGenerator{}
	h := NewHandlers(client, "bg-sa", "rep-sa", eventGen)

	logger := testr.New(t)
	resp := h.Validate(context.TODO(), logger, req, "", time.Now())

	assert.True(t, resp.Allowed)
	assert.NotEmpty(t, resp.Warnings)
	assert.Contains(t, resp.Warnings[0], "matches all kinds with wildcard '*'")

	// Check if event was generated
	assert.NotEmpty(t, eventGen.events)
	foundEvent := false
	for _, e := range eventGen.events {
		if e.Reason == event.PolicyError &&
			e.Regarding.Name == "wildcard-policy" &&
			e.Regarding.Kind == "ClusterPolicy" {
			foundEvent = true
			break
		}
	}
	assert.True(t, foundEvent, "Expected PolicyError event not generated")
}
