package policy

import (
	"fmt"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
)

// validateWildcards checks for wildcard usage in policy rules
func validateWildcards(policy kyvernov1.PolicyInterface) []string {
	var warnings []string
	spec := policy.GetSpec()
	for _, rule := range spec.Rules {
		if hasWildcard(rule.MatchResources.GetKinds()) {
			warnings = append(warnings, fmt.Sprintf("Rule '%s' matches all kinds with wildcard '*'. This may cause high load on the API server and cluster instability.", rule.Name))
		}
		if rule.ExcludeResources != nil {
			if hasWildcard(rule.ExcludeResources.GetKinds()) {
				warnings = append(warnings, fmt.Sprintf("Rule '%s' excludes all kinds with wildcard '*'. This may cause high load on the API server and cluster instability.", rule.Name))
			}
		}
	}
	return warnings
}

func hasWildcard(kinds []string) bool {
	for _, kind := range kinds {
		if kind == "*" {
			return true
		}
	}
	return false
}
