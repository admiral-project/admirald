package api

import "github.com/admiral-project/admiral/admirald/pkg/admiral"

func healthToTechStatus(h admiral.HealthStatus) string {
	switch h {
	case admiral.HealthHealthy:
		return "running"
	case admiral.HealthStopped:
		return "stopped"
	case admiral.HealthUnhealthy:
		return "failed"
	default:
		return ""
	}
}

// HandleMigrateInstance starts an offline migration of an instance to a target node.
