package admiral

import (
	"fmt"
	"regexp"
)

var appNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
var envNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

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
		if errs := validateHealthcheck(name, svc.HealthCheck); len(errs) > 0 {
			for _, e := range errs {
				return e
			}
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
		if err := ValidateTierEnvironment(name, tier.Environment); err != nil {
			return err
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

func ValidateTierEnvironment(tierName string, environment map[string]string) error {
	for key, value := range environment {
		if key == "" {
			return fmt.Errorf("tier %q environment variable name is required", tierName)
		}
		if !envNamePattern.MatchString(key) {
			return fmt.Errorf("tier %q environment variable %q is invalid, must match %s", tierName, key, envNamePattern.String())
		}
		if len(key) >= len("ADMIRAL_") && key[:len("ADMIRAL_")] == "ADMIRAL_" {
			return fmt.Errorf("tier %q environment variable %q uses reserved ADMIRAL_ prefix", tierName, key)
		}
		if value == "" {
			// Empty strings are allowed; Admiral treats values as strings.
			continue
		}
	}
	return nil
}

func validateHealthcheck(serviceName string, hc *YAMLHealthCheck) []error {
	var errs []error
	if hc == nil {
		return nil
	}
	switch hc.Type {
	case "http":
		if hc.Path == "" {
			errs = append(errs, fmt.Errorf("service %q: healthcheck type http requires path", serviceName))
		}
		if hc.ExpectedStatus == 0 {
			hc.ExpectedStatus = 200
		}
	case "tcp":
		if hc.Port == 0 {
			errs = append(errs, fmt.Errorf("service %q: healthcheck type tcp requires port", serviceName))
		}
	case "command":
		if len(hc.Command) == 0 {
			errs = append(errs, fmt.Errorf("service %q: healthcheck type command requires command", serviceName))
		}
	default:
		errs = append(errs, fmt.Errorf("service %q: invalid healthcheck type %q, must be http, tcp, or command", serviceName, hc.Type))
	}
	return errs
}
