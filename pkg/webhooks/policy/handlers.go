package policy

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/go-logr/logr"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	dpolvalidation "github.com/kyverno/kyverno/pkg/cel/policies/dpol"
	gpolvalidation "github.com/kyverno/kyverno/pkg/cel/policies/gpol"
	mpolvalidation "github.com/kyverno/kyverno/pkg/cel/policies/mpol"
	vpolvalidation "github.com/kyverno/kyverno/pkg/cel/policies/vpol"
	"github.com/kyverno/kyverno/pkg/clients/dclient"
	eval "github.com/kyverno/kyverno/pkg/image/verification/evaluator"
	admissionutils "github.com/kyverno/kyverno/pkg/utils/admission"
	"github.com/kyverno/kyverno/pkg/event"
	policyvalidate "github.com/kyverno/kyverno/pkg/validation/policy"
	"github.com/kyverno/kyverno/pkg/webhooks/handlers"
	corev1 "k8s.io/api/core/v1"
)

type policyHandlers struct {
	client                       dclient.Interface
	backgroundServiceAccountName string
	reportsServiceAccountName    string
	eventGen                     event.Interface
}

func NewHandlers(client dclient.Interface, backgroundSA, reportsSA string, eventGen event.Interface) *policyHandlers {
	return &policyHandlers{
		client:                       client,
		backgroundServiceAccountName: backgroundSA,
		reportsServiceAccountName:    reportsSA,
		eventGen:                     eventGen,
	}
}

func (h *policyHandlers) Validate(ctx context.Context, logger logr.Logger, request handlers.AdmissionRequest, _ string, _ time.Time) handlers.AdmissionResponse {
	policy, oldPolicy, err := admissionutils.GetPolicies(request.AdmissionRequest)
	if err != nil {
		logger.Error(err, "failed to unmarshal policies from admission request")
		return admissionutils.Response(request.UID, err)
	}

	if vpol := policy.AsValidatingPolicyLike(); vpol != nil {
		warnings, err := vpolvalidation.Validate(vpol)
		if err != nil {
			logger.Error(err, "ValidatingPolicy validation errors")
		}
		return admissionutils.Response(request.UID, err, warnings...)
	}

	if ivpol := policy.AsImageValidatingPolicyLike(); ivpol != nil {
		warnings, err := eval.Validate(ivpol, h.client.GetKubeClient().CoreV1().Secrets(""))
		if err != nil {
			logger.Error(err, "ImageValidatingPolicy validation errors")
		}
		return admissionutils.Response(request.UID, err, warnings...)
	}

	if mpol := policy.AsMutatingPolicyLike(); mpol != nil {
		warnings, err := mpolvalidation.Validate(mpol)
		if err != nil {
			logger.Error(err, "MutatingPolicy validation errors")
		}
		return admissionutils.Response(request.UID, err, warnings...)
	}

	if gpol := policy.AsGeneratingPolicyLike(); gpol != nil {
		warnings, err := gpolvalidation.Validate(gpol)
		if err != nil {
			logger.Error(err, "GeneratingPolicy validation errors")
		}
		return admissionutils.Response(request.UID, err, warnings...)
	}

	if dpol := policy.AsDeletingPolicy(); dpol != nil {
		warnings, err := dpolvalidation.Validate(dpol)
		if err != nil {
			logger.Error(err, "DeletingPolicy validation errors")
		}
		return admissionutils.Response(request.UID, err, warnings...)
	}

	if pol := policy.AsKyvernoPolicy(); pol != nil {
		var old kyvernov1.PolicyInterface
		if oldPolicy != nil {
			old = oldPolicy.AsKyvernoPolicy()
		}

		warnings, err := policyvalidate.Validate(policy.AsKyvernoPolicy(), old, h.client, false, h.backgroundServiceAccountName, h.reportsServiceAccountName)
		if err != nil {
			logger.Error(err, "policy validation errors")
		}
		for _, w := range warnings {
			if strings.Contains(w, "matches all kinds with wildcard '*'") {
				h.eventGen.Add(event.Info{
					Regarding: corev1.ObjectReference{
						Kind:       policy.GetKind(),
						Name:       policy.GetName(),
						Namespace:  policy.GetNamespace(),
						UID:        policy.GetUID(),
						APIVersion: policy.GetAPIVersion(),
					},
					Reason:  event.PolicyError,
					Message: w,
					Source:  event.AdmissionController,
					Action:  event.ResourcePassed,
				})
			}
		}
		return admissionutils.Response(request.UID, err, warnings...)
	}

	return admissionutils.Response(request.UID, errors.New("failed to convert policy"))
}

func (h *policyHandlers) Mutate(_ context.Context, _ logr.Logger, request handlers.AdmissionRequest, _ string, _ time.Time) handlers.AdmissionResponse {
	return admissionutils.ResponseSuccess(request.UID)
}
