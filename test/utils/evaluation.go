package utils

import (
	"context"
	"encoding/json"
	"fmt"

	authorizationv1 "k8s.io/api/authorization/v1"

	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
)

// NamespaceWitness is the value the Kubernetes program puts in a query's
// affected namespace when a request without a namespace may affect named
// namespaces.
const NamespaceWitness = "\x00namespace-witness"

// Evaluate evaluates review on endpoint of prepared with the engine's Rego
// modules, as an engine of the service ServiceUID serves it. The evaluation
// also reports the terminals the review reaches in the deciding authority's
// diagrams.
func Evaluate(ctx context.Context, prepared model.PreparedRevision, endpoint string, review authorizationv1.SubjectAccessReview) (engine.SnapshotEvaluation, error) {
	content, _, err := engine.FinalizeContent(prepared, ServiceUID)
	if err != nil {
		return engine.SnapshotEvaluation{}, err
	}
	data, err := json.Marshal(review)
	if err != nil {
		return engine.SnapshotEvaluation{}, fmt.Errorf("encode SubjectAccessReview: %w", err)
	}
	return engine.EvaluateSnapshot(ctx, content, endpoint, data)
}
