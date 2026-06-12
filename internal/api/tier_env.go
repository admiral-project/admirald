// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"strings"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func buildServiceInfos(payload admiral.AppDefinitionPayload, tier database.AppTier, instanceID, customerID string, secretValues map[string]map[string]string) []admiral.ServiceInfo {
	services := make([]admiral.ServiceInfo, 0, len(payload.Services))
	for name, svc := range payload.Services {
		// Precedence: tier environment > service env > Admiral internal vars
		// ADMIRAL_ prefixed vars are system-protected and cannot be overridden.
		env := mergeEnvironmentMaps(admiralEnvironment(payload.Name, tier.Name, instanceID, customerID))
		env = mergeEnvironmentMaps(env, filterProtectedVars(svc.Env))
		env = mergeEnvironmentMaps(env, filterProtectedVars(tier.Environment))
		// Resolve ${VAR} references in env values using secret values
		env = resolveEnvRefs(env, secretValues[name], secretValues["__global__"])
		si := admiral.ServiceInfo{
			Name:    name,
			Image:   svc.Image,
			Port:    svc.Port,
			Volume:  svc.Volume,
			Command: svc.Command,
			Env:     env,
			Secrets: secretValues[name],
		}
		if svc.Registry != nil {
			si.Registry = &admiral.RegistryConfig{
				Server:   svc.Registry.Server,
				Username: svc.Registry.Username,
				Password: svc.Registry.Password,
			}
		}
		services = append(services, si)
	}
	return services
}

func resolveEnvRefs(env map[string]string, svcSecrets, globalSecrets map[string]string) map[string]string {
	resolved := make(map[string]string, len(env))
	for k, v := range env {
		if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
			ref := v[2 : len(v)-1]
			if svcSecrets != nil {
				if val, ok := svcSecrets[ref]; ok {
					resolved[k] = val
					continue
				}
			}
			if globalSecrets != nil {
				if val, ok := globalSecrets[ref]; ok {
					resolved[k] = val
					continue
				}
			}
		}
		resolved[k] = v
	}
	return resolved
}

func admiralEnvironment(appCode, tierCode, instanceID, tenantID string) map[string]string {
	return map[string]string{
		"ADMIRAL_APP_CODE":    appCode,
		"ADMIRAL_TIER_CODE":   tierCode,
		"ADMIRAL_INSTANCE_ID": instanceID,
		"ADMIRAL_TENANT_ID":   tenantID,
		"ADMIRAL_ENVIRONMENT": "production",
	}
}

func mergeEnvironmentMaps(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

// filterProtectedVars removes ADMIRAL_ prefixed keys from the map.
// These are system-reserved and cannot be overridden by user-defined env.
func filterProtectedVars(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		if !strings.HasPrefix(k, "ADMIRAL_") {
			out[k] = v
		}
	}
	return out
}
