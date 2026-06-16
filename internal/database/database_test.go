// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import "testing"

func TestParseSizeBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  int64
	}{
		{name: "empty", value: "", want: 0},
		{name: "invalid", value: "nope", want: 0},
		{name: "bytes", value: "512", want: 512},
		{name: "kilobytes", value: "2KB", want: 2 << 10},
		{name: "megabytes", value: "3mb", want: 3 << 20},
		{name: "gigabytes", value: "1.5GB", want: 1610612736},
		{name: "terabytes", value: "2 tb", want: 2 << 40},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := ParseSizeBytes(tc.value); got != tc.want {
				t.Fatalf("ParseSizeBytes(%q) = %d, want %d", tc.value, got, tc.want)
			}
		})
	}
}

func TestCalculateCommitLimits(t *testing.T) {
	t.Parallel()

	if got, want := CalculateRAMCommitLimit(1024), int64(819); got != want {
		t.Fatalf("CalculateRAMCommitLimit(1024) = %d, want %d", got, want)
	}

	if got, want := CalculateDiskCommitLimit(1000), int64(666); got != want {
		t.Fatalf("CalculateDiskCommitLimit(1000) = %d, want %d", got, want)
	}
}

func TestNodeStorageState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		diskTotal int64
		diskUsed  int64
		wantState string
		wantMsg   string
	}{
		{name: "no total", diskTotal: 0, diskUsed: 1, wantState: "", wantMsg: ""},
		{name: "healthy", diskTotal: 100, diskUsed: 79, wantState: "", wantMsg: ""},
		{name: "warning", diskTotal: 100, diskUsed: 80, wantState: "warning", wantMsg: "node disk usage at 80.0%"},
		{name: "degraded", diskTotal: 100, diskUsed: 90, wantState: "degraded", wantMsg: "node disk usage at 90.0%"},
		{name: "critical", diskTotal: 100, diskUsed: 95, wantState: "critical", wantMsg: "node disk usage at 95.0%"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotState, gotMsg := NodeStorageState(tc.diskTotal, tc.diskUsed)
			if gotState != tc.wantState || gotMsg != tc.wantMsg {
				t.Fatalf("NodeStorageState(%d, %d) = (%q, %q), want (%q, %q)", tc.diskTotal, tc.diskUsed, gotState, gotMsg, tc.wantState, tc.wantMsg)
			}
		})
	}
}
