package source

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/zcayou/k8s-authz/internal/model"
)

var (
	sourceLabels = []string{"namespace", "name"}

	synchronized = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "k8s_authz", Name: "source_synchronized",
		Help: "Whether the policy source's latest acquisition is complete (1) or not (0).",
	}, sourceLabels)
	failures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "k8s_authz", Name: "source_acquisition_failures_total",
		Help: "Times a policy source's acquisition started failing.",
	}, sourceLabels)
)

func init() {
	metrics.Registry.MustRegister(synchronized, failures)
}

func observeHealth(key model.SourceKey, health Health) {
	value := 0.0
	if health.Complete {
		value = 1
	}
	synchronized.WithLabelValues(key.Namespace, key.Name).Set(value)
}

func countFailure(key model.SourceKey) {
	failures.WithLabelValues(key.Namespace, key.Name).Inc()
}

func forgetMetrics(key model.SourceKey) {
	synchronized.DeleteLabelValues(key.Namespace, key.Name)
	failures.DeleteLabelValues(key.Namespace, key.Name)
}
