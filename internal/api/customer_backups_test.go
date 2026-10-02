// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func TestUploadedRestoreRecordUsesTargetBackupContract(t *testing.T) {
	instance := &database.CustomerApp{ID: "inst_owner", AppDefinitionName: "wordpress"}
	request := admiral.RestoreBackupRequest{
		BackupID:    "upbk_uploaded",
		TargetAppID: instance.ID,
		Service:     "db",
		Source: admiral.BackupRestoreSource{
			Type:      "https",
			URI:       "https://harbor.example.test/backups/upbk_uploaded",
			Checksum:  "0123456789abcdef",
			SizeBytes: 1024,
		},
	}
	rawYAML := `name: wordpress
services:
  db:
    image: docker.io/library/postgres:16
    backup:
      type: database
      engine: postgresql
`

	record, err := uploadedRestoreRecord(request, instance, rawYAML)
	if err != nil {
		t.Fatalf("build uploaded restore record: %v", err)
	}
	if record.ID != request.BackupID || record.InstanceID != instance.ID {
		t.Fatalf("unexpected restore identity: %#v", record)
	}
	if record.BackupType != "database" || record.Service != "db" || record.DatabaseType != "postgresql" {
		t.Fatalf("restore contract does not match target service: %#v", record)
	}
	if record.StorageBackend != "https" || record.StorageKey != request.Source.URI || record.ChecksumSHA256 != request.Source.Checksum {
		t.Fatalf("restore source was not preserved: %#v", record)
	}
}

func TestUploadedRestoreRecordRejectsUnbackedService(t *testing.T) {
	_, err := uploadedRestoreRecord(
		admiral.RestoreBackupRequest{BackupID: "upbk_uploaded", Service: "web", Source: admiral.BackupRestoreSource{Type: "https", URI: "https://example.test/archive"}},
		&database.CustomerApp{ID: "inst_owner", AppDefinitionName: "wordpress"},
		"name: wordpress\nservices:\n  web:\n    image: docker.io/library/nginx:latest\n",
	)
	if err == nil {
		t.Fatal("expected a service without backup configuration to be rejected")
	}
}
