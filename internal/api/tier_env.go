package api

import (
	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func buildServiceInfos(payload admiral.AppDefinitionPayload, tier database.AppTier, instanceID, customerID string, secretValues map[string]map[string]string) []admiral.ServiceInfo {
	services := make([]admiral.ServiceInfo, 0, len(payload.Services))
	for name, svc := range payload.Services {
		env := mergeEnvironmentMaps(svc.Env, tier.Environment)
		env = mergeEnvironmentMaps(env, admiralEnvironment(payload.Name, tier.Name, instanceID, customerID))
		services = append(services, admiral.ServiceInfo{
			Name:    name,
			Image:   svc.Image,
			Port:    svc.Port,
			Volume:  svc.Volume,
			Command: svc.Command,
			Env:     env,
			Secrets: secretValues[name],
		})
	}
	return services
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
