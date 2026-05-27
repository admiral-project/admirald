package logging

import (
	"encoding/json"
	"fmt"
	"time"
)

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
	entry["timestamp"] = time.Now().Format(time.RFC3339)
	entry["level"] = level
	entry["component"] = l.component
	entry["message"] = message
	for k, v := range fields {
		entry[k] = v
	}
	data, _ := json.Marshal(entry)
	fmt.Println(string(data))
}
