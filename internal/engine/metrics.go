package engine

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/zcayou/k8s-authz/internal/model"
)

var (
	compileDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "k8s_authz", Name: "compile_duration_seconds",
		Help:    "Policy compilation duration, excluding cache hits.",
		Buckets: []float64{0.001, 0.01, 0.1, 1, 10, 30},
	}, []string{"result"})
	compileLimitFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "k8s_authz", Name: "compile_limit_failures_total",
		Help: "Compilations containing a scoped resource limit failure.",
	})
)

func init() {
	metrics.Registry.MustRegister(compileDuration, compileLimitFailures)
}

// observeCompilation records one compilation that missed the cache.
func observeCompilation(duration time.Duration, program Program, err error) {
	result := "success"
	if err != nil {
		result = "failure"
	}
	compileDuration.WithLabelValues(result).Observe(duration.Seconds())
	for _, issue := range program.Compilation.Prepared.Issues {
		if issue.Reason == model.ReasonResourceLimitExceeded {
			compileLimitFailures.Inc()
			break
		}
	}
}
