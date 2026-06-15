// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"

	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

type serviceBackupTarget struct {
	ServiceName string
	Service     admiral.YAMLService
	Backup      admiral.YAMLServiceBackup
}

func backupTargetsByType(payload admiral.AppDefinitionPayload, backupType string) []serviceBackupTarget {
	var targets []serviceBackupTarget
	for name, svc := range payload.Services {
		if svc.Backup == nil || svc.Backup.Type != backupType {
			continue
		}
		targets = append(targets, serviceBackupTarget{
			ServiceName: name,
			Service:     svc,
			Backup:      *svc.Backup,
		})
	}
	return targets
}

func resolveBackupTarget(payload admiral.AppDefinitionPayload, serviceName string) (serviceBackupTarget, error) {
	if serviceName == "" {
		return serviceBackupTarget{}, fmt.Errorf("service is required for backup actions")
	}
	svc, ok := payload.Services[serviceName]
	if !ok {
		return serviceBackupTarget{}, fmt.Errorf("service %q is not defined", serviceName)
	}
	if svc.Backup == nil {
		return serviceBackupTarget{}, fmt.Errorf("service %q does not declare backup settings", serviceName)
	}
	if svc.Backup.Type == "none" {
		return serviceBackupTarget{}, fmt.Errorf("service %q declares backup type none", serviceName)
	}
	return serviceBackupTarget{
		ServiceName: serviceName,
		Service:     svc,
		Backup:      *svc.Backup,
	}, nil
}

func resolveRestoreTarget(payload admiral.AppDefinitionPayload, backupType, serviceName string) (serviceBackupTarget, error) {
	if serviceName == "" {
		targets := backupTargetsByType(payload, backupType)
		if len(targets) == 0 {
			return serviceBackupTarget{}, fmt.Errorf("no service found for backup type %q", backupType)
		}
		return targets[0], nil
	}
	target, err := resolveBackupTarget(payload, serviceName)
	if err != nil {
		return serviceBackupTarget{}, err
	}
	if target.Backup.Type != backupType {
		return serviceBackupTarget{}, fmt.Errorf("service %q declares backup type %q, not %q", serviceName, target.Backup.Type, backupType)
	}
	return target, nil
}

func buildTaskBackupInfo(target serviceBackupTarget) *admiral.BackupInfo {
	databaseType := target.Backup.Engine
	if databaseType == "" && target.Backup.Type == "volume" {
		databaseType = "none"
	}
	return &admiral.BackupInfo{
		Type:         target.Backup.Type,
		Engine:       target.Backup.Engine,
		Service:      target.ServiceName,
		DatabaseType: databaseType,
		DatabaseEnv:  target.Backup.DatabaseEnv,
		UsernameEnv:  target.Backup.UsernameEnv,
		PasswordEnv:  target.Backup.PasswordEnv,
	}
}
