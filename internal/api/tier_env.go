// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"sort"
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
			Name:          name,
			Image:         svc.Image,
			Port:          svc.Port,
			Volume:        svc.Volume,
			DependsOn:     append([]string(nil), svc.DependsOn...),
			SharedVolumes: serviceSharedVolumes(payload, name),
			Command:       svc.Command,
			SetupCommand:  svc.SetupCommand,
			NotifyOnSetup: append([]admiral.YAMLSetupNotice(nil), svc.NotifyOnSetup...),
			Env:           env,
			Secrets:       secretValues[name],
			HealthCheck:   svc.HealthCheck,
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

func buildSharedVolumeInfos(payload admiral.AppDefinitionPayload) []admiral.SharedVolumeInfo {
	names := make([]string, 0, len(payload.SharedVolumes))
	for name := range payload.SharedVolumes {
		names = append(names, name)
	}
	sort.Strings(names)

	volumes := make([]admiral.SharedVolumeInfo, 0, len(names))
	for _, name := range names {
		volume := payload.SharedVolumes[name]
		volumes = append(volumes, admiral.SharedVolumeInfo{
			Name:     name,
			Mount:    volume.Mount,
			Services: append([]string(nil), volume.Services...),
			UID:      volume.UID,
			GID:      volume.GID,
		})
	}
	return volumes
}

func serviceSharedVolumes(payload admiral.AppDefinitionPayload, serviceName string) []admiral.ServiceSharedVolumeMount {
	names := make([]string, 0, len(payload.SharedVolumes))
	for name := range payload.SharedVolumes {
		names = append(names, name)
	}
	sort.Strings(names)

	mounts := make([]admiral.ServiceSharedVolumeMount, 0)
	for _, name := range names {
		volume := payload.SharedVolumes[name]
		for _, sharedService := range volume.Services {
			if sharedService == serviceName {
				mounts = append(mounts, admiral.ServiceSharedVolumeMount{
					Name:  name,
					Mount: volume.Mount,
					UID:   volume.UID,
					GID:   volume.GID,
				})
				break
			}
		}
	}
	return mounts
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

// hasSetupCommand returns true if any service in the app definition
// defines a setup_command. This is used by the provision handler to
// decide whether to set "initializing" status before dispatching the task.
func hasSetupCommand(payload admiral.AppDefinitionPayload) bool {
	for _, svc := range payload.Services {
		if strings.TrimSpace(svc.SetupCommand) != "" {
			return true
		}
	}
	return false
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
