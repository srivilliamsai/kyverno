package policy

import (
	"strings"
	"testing"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateWildcardWarning(t *testing.T) {
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

	// We need a mock client, but for this specific test which checks for wildcard warning
	// which happens at the beginning of Validate, nil client might work or we might need a dummy one.
	// Validate function signature: Validate(policy, oldPolicy kyvernov1.PolicyInterface, client dclient.Interface, mock bool, backgroundSA, reportsSA string) ([]string, error)

	warnings, err := Validate(policy, nil, nil, true, "", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, warnings)

	found := false
	for _, w := range warnings {
		if strings.Contains(w, "matches all kinds with wildcard '*'") {
			found = true
			break
		}
	}
	assert.True(t, found, "Expected wildcard warning not found")
}
