package compiler

import (
	"slices"

	"github.com/zcayou/k8s-authz/internal/model"
)

// exclusionCandidate is a region a policy's exclude removed from its include,
// computed in the branch's advisory arena. The advisory arena has the whole
// program's node budget and stops recording proofs when it's exhausted, so
// exclusion proofs never fail a compile.
type exclusionCandidate struct {
	node model.NodeID
	path []model.DocumentKey
}

func (w *branch) narrowExclusions(candidates []exclusionCandidate, bound model.NodeID) {
	for index := range candidates {
		candidates[index].node = w.advisoryIntersect(candidates[index].node, bound)
	}
}

func (w *branch) emitExclusionProofs(candidates []exclusionCandidate, use useContext, effect model.Effect) {
	for _, candidate := range candidates {
		if candidate.node == 0 || w.advisoriesExhausted {
			continue
		}
		context := use.derive()
		context.path = append(context.path, candidate.path...)
		proof := model.ExclusionProof{Endpoint: use.endpoint, Authority: use.authority, Effect: effect, PrincipalIDs: slices.Clone(use.principals), ContextID: context.identity(), Path: context.path}
		proof.ID = model.Digest(struct {
			Proof  model.ExclusionProof
			Region model.Diagram
		}{proof, w.advisoryArena.Snapshot(candidate.node)})
		labeled, err := w.advisoryArena.Label(candidate.node, proof.ID)
		if err != nil {
			w.stopAdvisories()
			return
		}
		diagram := w.advisoryArena.Snapshot(labeled)
		proof.DiagramID = model.Digest(diagram)
		w.owner.addExclusion(proof, diagram)
	}
}

func (b *builder) addExclusion(proof model.ExclusionProof, diagram model.Diagram) {
	prepared := &b.output.Prepared
	if _, exists := prepared.Exclusions[proof.ID]; exists {
		return
	}
	if len(prepared.Exclusions) >= maxAdvisories {
		prepared.ExclusionsTruncated = true
		return
	}
	if prepared.Exclusions == nil {
		prepared.Exclusions = make(map[string]model.ExclusionProof)
	}
	prepared.Exclusions[proof.ID] = proof
	if b.exclusionNodes+len(diagram.Nodes) > b.limits.MaxExclusionNodes || checkSelectorKeys(diagram) != nil {
		delete(prepared.Exclusions, proof.ID)
		prepared.ExclusionsTruncated = true
		return
	}
	b.exclusionNodes += len(diagram.Nodes)
	prepared.Diagrams[proof.DiagramID] = diagram
}

func (w *branch) advisoryRules(cubes []model.Cube) model.NodeID {
	if w.advisoriesExhausted {
		return 0
	}
	roots := make([]model.NodeID, 0, len(cubes))
	for _, cube := range cubes {
		next, err := w.advisoryArena.Cube(cube)
		if err != nil {
			w.stopAdvisories()
			return 0
		}
		roots = append(roots, next)
	}
	root, err := w.advisoryArena.UnionAll(roots)
	if err != nil {
		w.stopAdvisories()
		return 0
	}
	return root
}

func (w *branch) advisoryIntersect(left, right model.NodeID) model.NodeID {
	return w.advisoryApply(w.advisoryArena.Intersect, left, right)
}

func (w *branch) advisoryUnion(left, right model.NodeID) model.NodeID {
	return w.advisoryApply(w.advisoryArena.Union, left, right)
}

func (w *branch) advisorySubtract(left, right model.NodeID) model.NodeID {
	return w.advisoryApply(w.advisoryArena.Subtract, left, right)
}

func (w *branch) advisoryApply(operation func(model.NodeID, model.NodeID) (model.NodeID, error), left, right model.NodeID) model.NodeID {
	if w.advisoriesExhausted {
		return 0
	}
	result, err := operation(left, right)
	if err != nil {
		w.stopAdvisories()
		return 0
	}
	return result
}

func (w *branch) stopAdvisories() {
	w.advisoriesExhausted = true
	w.owner.output.Prepared.ExclusionsTruncated = true
}
