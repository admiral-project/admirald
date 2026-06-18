// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	RAMCommitRatio          = 0.80
	DiskSafeNodeRatio       = 0.80
	DiskEmergencyMultiplier = 1.20
	RAMHealthCriticalRatio  = 0.90
	DiskHealthCriticalRatio = 0.90
	MetricsStaleAfterSec    = 180
)

func ParseSizeBytes(value string) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	lower := strings.ToLower(value)
	mult := int64(1)
	switch {
	case strings.HasSuffix(lower, "tb"), strings.HasSuffix(lower, "t"):
		mult = 1 << 40
		value = strings.TrimRight(value, "tbTB")
	case strings.HasSuffix(lower, "gb"), strings.HasSuffix(lower, "g"):
		mult = 1 << 30
		value = strings.TrimRight(value, "gbGB")
	case strings.HasSuffix(lower, "mb"), strings.HasSuffix(lower, "m"):
		mult = 1 << 20
		value = strings.TrimRight(value, "mbMB")
	case strings.HasSuffix(lower, "kb"), strings.HasSuffix(lower, "k"):
		mult = 1 << 10
		value = strings.TrimRight(value, "kbKB")
	}
	num, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || num <= 0 {
		return 0
	}
	return int64(num * float64(mult))
}

func CalculateRAMCommitLimit(totalRAM int64) int64 {
	return int64(float64(totalRAM) * RAMCommitRatio)
}

func CalculateDiskCommitLimit(totalDisk int64) int64 {
	return int64((float64(totalDisk) * DiskSafeNodeRatio) / DiskEmergencyMultiplier)
}

func NodeStorageState(diskTotal, diskUsed int64) (string, string) {
	if diskTotal <= 0 {
		return "", ""
	}
	pct := float64(diskUsed) / float64(diskTotal) * 100
	switch {
	case pct >= 95:
		return "critical", fmt.Sprintf("node disk usage at %.1f%%", pct)
	case pct >= 90:
		return "degraded", fmt.Sprintf("node disk usage at %.1f%%", pct)
	case pct >= 80:
		return "warning", fmt.Sprintf("node disk usage at %.1f%%", pct)
	default:
		return "", ""
	}
}
