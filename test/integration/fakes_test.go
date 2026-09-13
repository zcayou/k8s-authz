//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/resources"
)

// pushed returns the state the operator last pushed to pod, or none.
func pushed(g Gomega, pod *corev1.Pod) model.ContentRevision {
	var content model.ContentRevision
	if state := engines.State(engineAddress(pod)); state != nil {
		g.Expect(json.Unmarshal(state, &content)).To(Succeed())
	}
	return content
}

func engineAddress(pod *corev1.Pod) string {
	return net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(int(resources.EnginePort)))
}

// secretGetRefused reads through its Reader but refuses to get a Secret.
type secretGetRefused struct {
	client.Reader
}

func (r secretGetRefused) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	if _, isSecret := object.(*corev1.Secret); isSecret {
		return errors.New("refused to get a Secret")
	}
	return r.Reader.Get(ctx, key, object, options...)
}
