package tlsconfig

import "testing"

func TestValidateURLScheme(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		allowed []string
		wantErr bool
	}{
		{name: "https accepted", raw: "https://admiral.example.com", allowed: []string{"https"}},
		{name: "amqps accepted", raw: "amqps://rabbitmq.example.com", allowed: []string{"amqps"}},
		{name: "http rejected", raw: "http://admiral.example.com", allowed: []string{"https"}, wantErr: true},
		{name: "amqp rejected", raw: "amqp://rabbitmq.example.com", allowed: []string{"amqps"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURLScheme(tt.raw, tt.allowed...)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestNewServerConfig(t *testing.T) {
	cfg := NewServerConfig()
	if cfg.MinVersion != 0 && cfg.MinVersion < 0x0303 {
		t.Fatalf("expected TLS 1.2 minimum, got %v", cfg.MinVersion)
	}
}
