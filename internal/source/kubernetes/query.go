package kubernetes

import (
	"cmp"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/zcayou/k8s-authz/internal/model"
)

type collectionQuery struct {
	kind      schema.GroupVersionKind
	resource  schema.GroupVersionResource
	namespace string
	name      string
}

// restrict narrows list and watch requests to the query's name.
func (q collectionQuery) restrict(options *metav1.ListOptions) {
	if q.name != "" {
		options.FieldSelector = fields.OneTermEqualSelector("metadata.name", q.name).String()
	}
}

func (q collectionQuery) key() string {
	return strings.Join([]string{q.resource.Group, q.resource.Version, q.resource.Resource, q.namespace, q.name}, "\x00")
}

// covers reports whether every object other can return, q returns too.
func (q collectionQuery) covers(other collectionQuery) bool {
	return q.resource == other.resource && (q.namespace == "" || q.namespace == other.namespace) && (q.name == "" || q.name == other.name)
}

// collectionQueries plans one list and watch per kind, namespace and name
// the collection names, leaving out any query a broader one covers.
func collectionQueries(collection Collection) []collectionQuery {
	byKey := make(map[string]collectionQuery)
	for _, keyRange := range collection.Ranges {
		for _, kind := range keyRange.Kinds {
			documentKind := model.DocumentKinds[kind]
			namespaces := keyRange.Namespaces
			if !documentKind.Namespaced {
				namespaces = []string{""}
			}
			for _, namespace := range namespaces {
				for _, name := range keyRange.Names {
					query := collectionQuery{kind: documentKind.Resource.GroupVersion().WithKind(kind), resource: documentKind.Resource, namespace: unlessWildcard(namespace), name: unlessWildcard(name)}
					byKey[query.key()] = query
				}
			}
		}
	}
	return minimal(byKey)
}

// namespaceQueries plans the list and watch of the namespaces whose labels
// the collection reads: every namespace when a range selects "*", otherwise
// one per namespace a range names.
func namespaceQueries(collection Collection) []collectionQuery {
	if !collection.NamespaceLabels {
		return nil
	}
	byKey := make(map[string]collectionQuery)
	for _, keyRange := range collection.Ranges {
		for _, namespace := range keyRange.Namespaces {
			query := collectionQuery{kind: namespaceKind, resource: namespaceResource, name: unlessWildcard(namespace)}
			byKey[query.key()] = query
		}
	}
	return minimal(byKey)
}

// minimal returns the queries no other query covers, in key order.
func minimal(byKey map[string]collectionQuery) []collectionQuery {
	result := make([]collectionQuery, 0, len(byKey))
	for key, query := range byKey {
		covered := false
		for otherKey, other := range byKey {
			covered = covered || otherKey != key && other.covers(query)
		}
		if !covered {
			result = append(result, query)
		}
	}
	slices.SortFunc(result, func(left, right collectionQuery) int {
		return cmp.Compare(left.key(), right.key())
	})
	return result
}

// unlessWildcard maps the collection wildcard to an unrestricted query field.
func unlessWildcard(value string) string {
	if value == "*" {
		return ""
	}
	return value
}
