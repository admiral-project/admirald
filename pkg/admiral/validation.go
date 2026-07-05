// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package admiral

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var appNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
var envNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
var serviceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
var imagePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_\-\.:\/@]*$`)

var runArgsRe = regexp.MustCompile(`[;&\` + "`" + `$()|]`)

func ValidateRunArgs(args string) error {
	if runArgsRe.MatchString(args) {
		return fmt.Errorf("command contains unsafe shell metacharacters")
	}
	return nil
}

var setupArgsRe = regexp.MustCompile(`[;&\` + "`" + `|]|\$\(`)

func ValidateSetupArgs(args string) error {
	if setupArgsRe.MatchString(args) {
		return fmt.Errorf("setup_command contains unsafe shell metacharacters")
	}
	return nil
}

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
	if err := validateEnvironmentMap("app", payload.Environment); err != nil {
		return err
	}

	for envName, secret := range payload.Secrets {
		if envName == "" {
			return fmt.Errorf("top-level secret name is required")
		}
		if secret.Generate == "" && secret.Value == "" {
			return fmt.Errorf("top-level secret %q must define generate or value", envName)
		}
		if secret.Generate != "" && secret.Value != "" {
			return fmt.Errorf("top-level secret %q cannot define both generate and value", envName)
		}
		if secret.Generate != "" && secret.Generate != "username" && secret.Generate != "password" && secret.Generate != "random" && secret.Generate != "ssh_key" {
			return fmt.Errorf("top-level secret %q generate must be username, password, random, or ssh_key", envName)
		}
	}

	sharedMountIndex := make(map[string]string, len(payload.SharedVolumes))
	serviceSharedVolumes := make(map[string]map[string]YAMLSharedVolume, len(payload.Services))
	for volumeName, shared := range payload.SharedVolumes {
		if volumeName == "" {
			return fmt.Errorf("shared volume name is required")
		}
		if !serviceNamePattern.MatchString(volumeName) {
			return fmt.Errorf("shared volume name %q must match %s", volumeName, serviceNamePattern.String())
		}
		mount := filepath.Clean(strings.TrimSpace(shared.Mount))
		if !filepath.IsAbs(mount) {
			return fmt.Errorf("shared volume %q mount %q must be an absolute path", volumeName, shared.Mount)
		}
		if len(shared.Services) == 0 {
			return fmt.Errorf("shared volume %q requires at least one service", volumeName)
		}
		if existing, ok := sharedMountIndex[mount]; ok {
			return fmt.Errorf("shared volume %q mount %q conflicts with shared volume %q", volumeName, mount, existing)
		}
		sharedMountIndex[mount] = volumeName
		for _, serviceName := range shared.Services {
			if _, ok := payload.Services[serviceName]; !ok {
				return fmt.Errorf("shared volume %q references undefined service %q", volumeName, serviceName)
			}
			if serviceSharedVolumes[serviceName] == nil {
				serviceSharedVolumes[serviceName] = make(map[string]YAMLSharedVolume)
			}
			serviceSharedVolumes[serviceName][volumeName] = YAMLSharedVolume{
				Mount:    mount,
				Services: append([]string(nil), shared.Services...),
				UID:      shared.UID,
				GID:      shared.GID,
			}
		}
	}

	usedPorts := make(map[int]string)
	for name, svc := range payload.Services {
		if name == "" {
			return fmt.Errorf("service name is required")
		}
		if !serviceNamePattern.MatchString(name) {
			return fmt.Errorf("service name %q must match %s", name, serviceNamePattern.String())
		}
		if svc.Image == "" {
			return fmt.Errorf("service %q image is required", name)
		}
		if !imagePattern.MatchString(svc.Image) {
			return fmt.Errorf("service %q image %q contains invalid characters", name, svc.Image)
		}
		if svc.Command != "" {
			if err := ValidateRunArgs(svc.Command); err != nil {
				return fmt.Errorf("service %q command: %w", name, err)
			}
		}
		if svc.SetupCommand != "" {
			if err := ValidateSetupArgs(svc.SetupCommand); err != nil {
				return fmt.Errorf("service %q setup_command: %w", name, err)
			}
		}
		if svc.Backup == nil {
			return fmt.Errorf("service %q backup is required and must declare database, volume, or none", name)
		}
		if svc.Port > 0 {
			if existing, ok := usedPorts[svc.Port]; ok {
				return fmt.Errorf("port %d conflict between services %q and %q", svc.Port, existing, name)
			}
			usedPorts[svc.Port] = name
		}
		if svc.Public && svc.Port <= 0 {
			return fmt.Errorf("service %q marked public requires a port greater than zero", name)
		}
		for _, dep := range svc.DependsOn {
			if dep == name {
				return fmt.Errorf("service %q cannot depend on itself", name)
			}
			if _, ok := payload.Services[dep]; !ok {
				return fmt.Errorf("service %q depends_on references undefined service %q", name, dep)
			}
		}
		for _, req := range svc.Requires {
			if req == name {
				return fmt.Errorf("service %q cannot require itself", name)
			}
			if _, ok := payload.Services[req]; !ok {
				return fmt.Errorf("service %q requires references undefined service %q", name, req)
			}
		}
		if svc.HealthCheckWaitSecs < 0 {
			return fmt.Errorf("service %q healthcheck_wait_timeout must not be negative", name)
		}
		if errs := validateHealthcheck(name, svc.HealthCheck); len(errs) > 0 {
			for _, e := range errs {
				return e
			}
		}
		for _, notice := range svc.NotifyOnSetup {
			if strings.TrimSpace(notice.Label) == "" {
				return fmt.Errorf("service %q notify_on_setup label is required", name)
			}
			if strings.TrimSpace(notice.Value) == "" {
				return fmt.Errorf("service %q notify_on_setup value is required", name)
			}
		}
		if svc.Registry != nil {
			if svc.Registry.Server == "" {
				return fmt.Errorf("service %q registry server is required", name)
			}
			if svc.Registry.Username == "" {
				return fmt.Errorf("service %q registry username is required", name)
			}
			if svc.Registry.Password == "" {
				return fmt.Errorf("service %q registry password is required", name)
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
			if secret.Generate != "" && secret.Generate != "username" && secret.Generate != "password" && secret.Generate != "random" && secret.Generate != "ssh_key" {
				return fmt.Errorf("service %q secret %q has unsupported generator %q", name, envName, secret.Generate)
			}
		}
		if svc.Volume != "" {
			serviceVolumeMount := defaultServiceVolumeMount(name, svc.Image)
			for sharedName, shared := range serviceSharedVolumes[name] {
				if shared.Mount == serviceVolumeMount {
					return fmt.Errorf("service %q private volume mount %q conflicts with shared volume %q", name, serviceVolumeMount, sharedName)
				}
			}
		}
	}

	if err := validateDependencyCycles(payload.Services); err != nil {
		return err
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
		if !isValidStorageFormat(tier.Memory) {
			return fmt.Errorf("tier %q memory %q has invalid format: expected a number followed by unit (e.g., 512M, 1G, 2Gi)", name, tier.Memory)
		}
		if tier.Storage == "" {
			return fmt.Errorf("tier %q storage is required", name)
		}
		if !isValidStorageFormat(tier.Storage) {
			return fmt.Errorf("tier %q storage %q has invalid format: expected a number followed by unit (e.g., 10G, 5Gi, 1024M, 1T)", name, tier.Storage)
		}
		if storageBytes := parseStorageBytes(tier.Storage); storageBytes <= 0 {
			return fmt.Errorf("tier %q storage %q must be greater than zero", name, tier.Storage)
		}
		if tier.PriceMonthly < 0 {
			return fmt.Errorf("tier %q price_monthly must not be negative", name)
		}
		if tier.Free && tier.PriceMonthly != 0 {
			return fmt.Errorf("tier %q is marked free but has price_monthly %.2f", name, tier.PriceMonthly)
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

	databaseBackupCount := 0
	volumeBackupCount := 0
	for name, svc := range payload.Services {
		switch svc.Backup.Type {
		case "":
			return fmt.Errorf("service %q backup type is required", name)
		case "none":
			if svc.Backup.Engine != "" || svc.Backup.DatabaseEnv != "" || svc.Backup.UsernameEnv != "" || svc.Backup.PasswordEnv != "" {
				return fmt.Errorf("service %q backup type none cannot declare database backup fields", name)
			}
		case "database":
			databaseBackupCount++
			if svc.Backup.Engine == "" {
				return fmt.Errorf("service %q backup engine is required for database backups", name)
			}
			if svc.Backup.Engine != "postgresql" && svc.Backup.Engine != "mysql" && svc.Backup.Engine != "mariadb" {
				return fmt.Errorf("service %q backup engine %q is unsupported", name, svc.Backup.Engine)
			}
			for _, envName := range []string{svc.Backup.DatabaseEnv, svc.Backup.UsernameEnv, svc.Backup.PasswordEnv} {
				if envName == "" {
					return fmt.Errorf("service %q database backup env references are required", name)
				}
				if _, ok := svc.Env[envName]; !ok {
					if _, ok := svc.Secrets[envName]; !ok {
						return fmt.Errorf("service %q backup env %q is not defined", name, envName)
					}
				}
			}
		case "volume":
			volumeBackupCount++
			if svc.Volume == "" && len(serviceSharedVolumes[name]) == 0 {
				return fmt.Errorf("service %q volume backup requires a declared volume or shared volume", name)
			}
			if svc.Backup.Engine != "" || svc.Backup.DatabaseEnv != "" || svc.Backup.UsernameEnv != "" || svc.Backup.PasswordEnv != "" {
				return fmt.Errorf("service %q volume backup cannot declare database backup fields", name)
			}
		default:
			return fmt.Errorf("service %q backup type must be database, volume, or none", name)
		}
	}

	for name, tier := range payload.Tiers {
		if tier.Backups == nil {
			continue
		}
		if tier.Backups.BackupDatabase && databaseBackupCount == 0 {
			return fmt.Errorf("tier %q enables backup_database but no service declares backup type database", name)
		}
		if tier.Backups.BackupVolumes && volumeBackupCount == 0 {
			return fmt.Errorf("tier %q enables backup_volumes but no service declares backup type volume", name)
		}
	}

	return nil
}

func defaultServiceVolumeMount(serviceName, image string) string {
	img := strings.ToLower(strings.TrimSpace(image))
	switch {
	case strings.Contains(img, "postgres"):
		return "/var/lib/postgresql/data"
	case strings.Contains(img, "mariadb"), strings.Contains(img, "mysql"):
		return "/var/lib/mysql"
	case strings.Contains(img, "wordpress"):
		return "/var/www/html/wp-content"
	case serviceName == "db":
		return "/var/lib/postgresql/data"
	default:
		return "/data"
	}
}

func validateDependencyCycles(services map[string]YAMLService) error {
	visited := make(map[string]bool, len(services))
	inStack := make(map[string]bool, len(services))

	var visit func(string) error
	visit = func(name string) error {
		if inStack[name] {
			return fmt.Errorf("service dependency cycle detected involving %q", name)
		}
		if visited[name] {
			return nil
		}
		visited[name] = true
		inStack[name] = true
		for _, dep := range services[name].DependsOn {
			if err := visit(dep); err != nil {
				return err
			}
		}
		for _, req := range services[name].Requires {
			if err := visit(req); err != nil {
				return err
			}
		}
		inStack[name] = false
		return nil
	}

	for name := range services {
		if err := visit(name); err != nil {
			return err
		}
	}
	return nil
}

func ValidateTierEnvironment(tierName string, environment map[string]string) error {
	return validateEnvironmentMap(fmt.Sprintf("tier %q", tierName), environment)
}

func validateEnvironmentMap(scope string, environment map[string]string) error {
	if environment == nil {
		return nil
	}
	for key, value := range environment {
		if key == "" {
			return fmt.Errorf("%s environment variable name is required", scope)
		}
		if !envNamePattern.MatchString(key) {
			return fmt.Errorf("%s environment variable %q is invalid, must match %s", scope, key, envNamePattern.String())
		}
		if len(key) >= len("ADMIRAL_") && key[:len("ADMIRAL_")] == "ADMIRAL_" {
			return fmt.Errorf("%s environment variable %q uses reserved ADMIRAL_ prefix", scope, key)
		}
		if value == "" {
			// Empty strings are allowed; Admiral treats values as strings.
			continue
		}
	}
	return nil
}

var validStorageUnit = regexp.MustCompile(`^(?i)[0-9]+(\.[0-9]+)?\s*(k|kb|kib|ki|m|mb|mib|mi|g|gb|gib|gi|t|tb|tib|ti)?$`)

func isValidStorageFormat(value string) bool {
	return validStorageUnit.MatchString(strings.TrimSpace(value))
}

func parseStorageBytes(value string) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	lower := strings.ToLower(value)
	multiplier := int64(1)

	switch {
	case strings.HasSuffix(lower, "tib"):
		multiplier = 1024 * 1024 * 1024 * 1024
		value = value[:len(value)-3]
	case strings.HasSuffix(lower, "ti"), strings.HasSuffix(lower, "tb"):
		multiplier = 1024 * 1024 * 1024 * 1024
		value = value[:len(value)-2]
	case strings.HasSuffix(lower, "t"):
		multiplier = 1024 * 1024 * 1024 * 1024
		value = value[:len(value)-1]
	case strings.HasSuffix(lower, "gib"):
		multiplier = 1024 * 1024 * 1024
		value = value[:len(value)-3]
	case strings.HasSuffix(lower, "gi"), strings.HasSuffix(lower, "gb"):
		multiplier = 1024 * 1024 * 1024
		value = value[:len(value)-2]
	case strings.HasSuffix(lower, "g"):
		multiplier = 1024 * 1024 * 1024
		value = value[:len(value)-1]
	case strings.HasSuffix(lower, "mib"):
		multiplier = 1024 * 1024
		value = value[:len(value)-3]
	case strings.HasSuffix(lower, "mi"), strings.HasSuffix(lower, "mb"):
		multiplier = 1024 * 1024
		value = value[:len(value)-2]
	case strings.HasSuffix(lower, "m"):
		multiplier = 1024 * 1024
		value = value[:len(value)-1]
	case strings.HasSuffix(lower, "kib"):
		multiplier = 1024
		value = value[:len(value)-3]
	case strings.HasSuffix(lower, "ki"), strings.HasSuffix(lower, "kb"):
		multiplier = 1024
		value = value[:len(value)-2]
	case strings.HasSuffix(lower, "k"):
		multiplier = 1024
		value = value[:len(value)-1]
	}

	num, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || num <= 0 {
		return 0
	}
	return int64(num * float64(multiplier))
}

var allowedRestoreSourceTypes = map[string]bool{
	"local_path": true,
	"https":      true,
	"s3":         true,
}

func ValidateRestoreSource(source BackupRestoreSource, backupRecord *BackupRecord) error {
	srcType := strings.ToLower(strings.TrimSpace(source.Type))
	if srcType == "" {
		srcType = strings.ToLower(strings.TrimSpace(backupRecord.StorageBackend))
	}
	if srcType == "" {
		srcType = "local_path"
	}
	if srcType == "local" {
		srcType = "local_path"
	}

	if !allowedRestoreSourceTypes[srcType] {
		return fmt.Errorf("restore source type %q is not allowed: only local_path, https, and s3 are permitted", srcType)
	}

	srcURI := strings.TrimSpace(source.URI)
	if srcURI == "" {
		srcURI = backupRecord.StorageKey
	}

	if srcType == "local_path" && srcURI != "" {
		if strings.Contains(srcURI, "..") {
			return fmt.Errorf("restore source path %q contains path traversal sequences", srcURI)
		}
	}

	if srcType == "https" && srcURI != "" {
		if !strings.HasPrefix(srcURI, "https://") {
			return fmt.Errorf("restore source URI %q must use https scheme", srcURI)
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
