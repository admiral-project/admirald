package admiral

import (
	"fmt"
	"regexp"
)

var appNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func ValidateAppDefinition(payload AppDefinitionPayload) error {
	if payload.Name == "" {
		return fmt.Errorf("name is required")
	}
	if !appNamePattern.MatchString(payload.Name) {
		return fmt.Errorf("name %q must match %s", payload.Name, appNamePattern.String())
	}
	if payload.DisplayName == "" {
		return fmt.Errorf("display_name is required")
	}
	if len(payload.Services) == 0 {
		return fmt.Errorf("at least one service is required")
	}
	if len(payload.Tiers) == 0 {
		return fmt.Errorf("at least one tier is required")
	}

	for name, svc := range payload.Services {
		if name == "" {
			return fmt.Errorf("service name is required")
		}
		if svc.Image == "" {
			return fmt.Errorf("service %q image is required", name)
		}
		if svc.Public && svc.Port <= 0 {
			return fmt.Errorf("service %q marked public requires a port greater than zero", name)
		}
		for envName, secret := range svc.Secrets {
			if envName == "" {
				return fmt.Errorf("service %q secret name is required", name)
			}
			if secret.Generate == "" && secret.Value == "" {
				return fmt.Errorf("service %q secret %q requires generate or value", name, envName)
			}
			if secret.Generate != "" && secret.Value != "" {
				return fmt.Errorf("service %q secret %q cannot define both generate and value", name, envName)
			}
			if secret.Generate != "" && secret.Generate != "username" && secret.Generate != "password" {
				return fmt.Errorf("service %q secret %q has unsupported generator %q", name, envName, secret.Generate)
			}
		}
	}

	publicCount := 0
	for name, svc := range payload.Services {
		if svc.Public {
			publicCount++
			if publicCount > 1 {
				return fmt.Errorf("only one public service is supported per app definition for now")
			}
			if name == "" {
				return fmt.Errorf("public service name is required")
			}
		}
	}

	for name, tier := range payload.Tiers {
		if name == "" {
			return fmt.Errorf("tier name is required")
		}
		if tier.CPU <= 0 {
			return fmt.Errorf("tier %q cpu must be greater than zero", name)
		}
		if tier.Memory == "" {
			return fmt.Errorf("tier %q memory is required", name)
		}
		if tier.Storage == "" {
			return fmt.Errorf("tier %q storage is required", name)
		}
		if tier.PriceMonthly < 0 {
			return fmt.Errorf("tier %q price_monthly must not be negative", name)
		}
		if tier.Backups != nil && tier.Backups.Enabled {
			s := tier.Backups.Schedule
			if s != "disabled" && s != "daily" && s != "weekly" {
				return fmt.Errorf("tier %q backups schedule %q is unsupported, must be 'disabled', 'daily', or 'weekly'", name, s)
			}
			if tier.Backups.Retention.Count < 1 {
				return fmt.Errorf("tier %q backups retention count must be at least 1", name)
			}
			if tier.Backups.Retention.Days < 1 {
				return fmt.Errorf("tier %q backups retention days must be at least 1", name)
			}
		}
	}

	if payload.Backup != nil {
		if payload.Backup.Type == "" {
			return fmt.Errorf("backup type is required")
		}
		if payload.Backup.Type != "database" && payload.Backup.Type != "volume" {
			return fmt.Errorf("backup type must be database or volume")
		}
		if payload.Backup.Type == "database" {
			if payload.Backup.Engine == "" {
				return fmt.Errorf("backup engine is required for database backups")
			}
			if payload.Backup.Engine != "postgresql" && payload.Backup.Engine != "mysql" && payload.Backup.Engine != "mariadb" {
				return fmt.Errorf("backup engine %q is unsupported", payload.Backup.Engine)
			}
		}
		if payload.Backup.Service == "" {
			return fmt.Errorf("backup service is required")
		}

		svc, ok := payload.Services[payload.Backup.Service]
		if !ok {
			return fmt.Errorf("backup service %q is not defined", payload.Backup.Service)
		}
		for _, envName := range []string{payload.Backup.DatabaseEnv, payload.Backup.UsernameEnv, payload.Backup.PasswordEnv} {
			if envName == "" {
				return fmt.Errorf("backup env references are required")
			}
			if _, ok := svc.Env[envName]; !ok {
				if _, ok := svc.Secrets[envName]; !ok {
					return fmt.Errorf("backup env %q is not defined in service %q", envName, payload.Backup.Service)
				}
			}
		}
	}

	return nil
}
