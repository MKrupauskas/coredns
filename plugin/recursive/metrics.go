package recursive

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Variables declared for monitoring.
var (
	upstreamQueryCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "recursive",
		Name:      "upstream_queries_total",
		Help:      "Counter of queries sent to authoritative name servers, by response code (or \"error\" when no response was received).",
	}, []string{"rcode"})

	delegationCacheCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "recursive",
		Name:      "delegation_cache_total",
		Help:      "Counter of delegation cache lookups, by result (hit or miss).",
	}, []string{"result"})

	resolutionFailureCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "recursive",
		Name:      "resolution_failures_total",
		Help:      "Counter of client queries that could not be resolved and were answered with SERVFAIL.",
	})
)
