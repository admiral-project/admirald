// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"fmt"
	"strings"
	"testing"
)

func TestRedactSensitiveKeys(t *testing.T) {
	entry := map[string]interface{}{
		"password":   "supersecret123",
		"token":      "abc123token",
		"secret_key": "mykey",
		"safe_field": "hello",
		"nested": map[string]interface{}{
			"password": "nestedsecret",
			"ok":       "visible",
		},
		"list": []interface{}{
			map[string]interface{}{
				"token": "listtoken",
			},
		},
	}
	redact(entry)

	tests := []struct {
		key      string
		wantMask bool
	}{
		{"password", true},
		{"token", true},
		{"secret_key", true},
		{"safe_field", false},
	}

	for _, tt := range tests {
		got := entry[tt.key]
		s, ok := got.(string)
		if !ok {
			t.Errorf("key %q: expected string, got %T", tt.key, got)
			continue
		}
		if tt.wantMask && !strings.Contains(s, "****") {
			t.Errorf("key %q = %q, expected masked value", tt.key, s)
		}
		if !tt.wantMask && s != "hello" {
			t.Errorf("key %q = %q, expected 'hello'", tt.key, s)
		}
	}

	nested := entry["nested"].(map[string]interface{})
	if s := nested["password"].(string); !strings.Contains(s, "****") {
		t.Errorf("nested password = %q, expected masked", s)
	}
	if s := nested["ok"].(string); s != "visible" {
		t.Errorf("nested ok = %q, expected visible", s)
	}

	list := entry["list"].([]interface{})
	if s := list[0].(map[string]interface{})["token"].(string); !strings.Contains(s, "****") {
		t.Errorf("list token = %q, expected masked", s)
	}
}

func TestMaskValueShort(t *testing.T) {
	if got := maskValue("ab"); got != "****" {
		t.Errorf("maskValue('ab') = %q, want '****'", got)
	}
}

func TestMaskValueLong(t *testing.T) {
	if got := maskValue("abcdefgh"); got != "****" {
		t.Errorf("maskValue('abcdefgh') = %q, want '****'", got)
	}
}

func TestMaskValueNonString(t *testing.T) {
	if got := maskValue(123); got != "****" {
		t.Errorf("maskValue(123) = %q, want '****'", got)
	}
}

func TestLogger(t *testing.T) {
	l := New("test")
	l.Info("test info", map[string]interface{}{"key": "val"})
	l.Warn("test warn", map[string]interface{}{"key": "val"})
	l.Error("test error", fmt.Errorf("fail"), map[string]interface{}{"key": "val"})
	l.Error("test error nil", nil, nil)
}

func TestLoggerFatal(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	l := New("test")
	l.Fatal("fatal error", fmt.Errorf("boom"), nil)
}

func TestIsSensitiveKey(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"password", true},
		{"PASSWORD", true},
		{"Password", true},
		{"db_password", true},
		{"access_key", true},
		{"safe", false},
		{"hostname", false},
	}
	for _, tc := range cases {
		got := isSensitiveKey(tc.key)
		if got != tc.want {
			t.Errorf("isSensitiveKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}
