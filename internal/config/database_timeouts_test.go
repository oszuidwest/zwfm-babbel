package config

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/caarlos0/env/v11"
)

func TestDatabaseTimeoutEnvironment(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name                 string
		environment          map[string]string
		connect, read, write time.Duration
	}{
		{"defaults", map[string]string{}, 10 * time.Second, 2 * time.Minute, 2 * time.Minute},
		{"configured", map[string]string{"BABBEL_DB_CONNECT_TIMEOUT": "3s", "BABBEL_DB_READ_TIMEOUT": "45s", "BABBEL_DB_WRITE_TIMEOUT": "90s"}, 3 * time.Second, 45 * time.Second, 90 * time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := env.ParseAsWithOptions[Config](env.Options{Prefix: "BABBEL_", Environment: tt.environment})
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Database.ConnectTimeout != tt.connect || cfg.Database.ReadTimeout != tt.read || cfg.Database.WriteTimeout != tt.write {
				t.Fatalf("timeouts = %v/%v/%v", cfg.Database.ConnectTimeout, cfg.Database.ReadTimeout, cfg.Database.WriteTimeout)
			}
		})
	}
}

func TestDatabaseTimeoutsMustBePositive(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"CONNECT_TIMEOUT", "READ_TIMEOUT", "WRITE_TIMEOUT"} {
		for _, value := range []time.Duration{0, -time.Second} {
			t.Run(fmt.Sprintf("%s/%s", name, value), func(t *testing.T) {
				cfg := validTestConfig(t)
				switch name {
				case "CONNECT_TIMEOUT":
					cfg.Database.ConnectTimeout = value
				case "READ_TIMEOUT":
					cfg.Database.ReadTimeout = value
				case "WRITE_TIMEOUT":
					cfg.Database.WriteTimeout = value
				}
				if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "BABBEL_DB_"+name+" must be > 0") {
					t.Fatalf("Validate = %v", err)
				}
			})
		}
	}
}
