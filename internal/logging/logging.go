package logging

import (
	"encoding/json"
	"fmt"
	"time"
)

var sensitiveKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"apikey",
	"api_key",
	"authorization",
	"access_key",
	"secret_key",
	"session_token",
}

type Logger struct {
	component string
}

func New(component string) *Logger {
	return &Logger{component: component}
}

func (l *Logger) Info(message string, fields map[string]interface{}) {
	l.log("INFO", message, fields)
}

func (l *Logger) Error(message string, err error, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	if err != nil {
		fields["error"] = err.Error()
	}
	l.log("ERROR", message, fields)
}

func (l *Logger) log(level, message string, fields map[string]interface{}) {
	entry := make(map[string]interface{})
	entry["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	entry["level"] = level
	entry["component"] = l.component
	entry["message"] = message
	for k, v := range fields {
		entry[k] = v
	}
	redact(entry)
	data, _ := json.Marshal(entry)
	fmt.Println(string(data))
}

func isSensitiveKey(k string) bool {
	for _, sk := range sensitiveKeys {
		if equalFold(k, sk) || containsFold(k, sk) {
			return true
		}
	}
	return false
}

func redact(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if isSensitiveKey(k) {
				t[k] = maskValue(val)
			} else {
				t[k] = redact(val)
			}
		}
		return t
	case []interface{}:
		for i, val := range t {
			t[i] = redact(val)
		}
		return t
	}
	return v
}

func maskValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		if len(val) <= 4 {
			return "****"
		}
		return val[:2] + "****" + val[len(val)-2:]
	case []byte:
		return maskValue(string(val))
	default:
		return "****"
	}
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if toLower(a[i]) != toLower(b[i]) {
			return false
		}
	}
	return true
}

func containsFold(s, substr string) bool {
	sl := len(s)
	sub := len(substr)
	if sub == 0 || sl < sub {
		return false
	}
	subLower := make([]byte, sub)
	for i := 0; i < sub; i++ {
		subLower[i] = toLower(substr[i])
	}
	for i := 0; i <= sl-sub; i++ {
		match := true
		for j := 0; j < sub; j++ {
			if toLower(s[i+j]) != subLower[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func toLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}
