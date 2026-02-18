package main

import (
	"context"
	"fmt"
	"os"

	"github.com/masterzen/winrm"
)

func main() {
	host := envOrDefault("WINRM_HOST", "192.168.100.62")
	port := envOrDefaultInt("WINRM_PORT", 5985)
	user := os.Getenv("WINRM_USER")
	pass := os.Getenv("WINRM_PASS")
	cmd := envOrDefault("WINRM_COMMAND", "whoami")

	if user == "" || pass == "" {
		fmt.Fprintln(os.Stderr, "missing credentials: set WINRM_USER and WINRM_PASS")
		fmt.Fprintln(os.Stderr, "optional: WINRM_HOST (default 192.168.100.62), WINRM_PORT (default 5985), WINRM_COMMAND (default whoami)")
		os.Exit(2)
	}

	endpoint := winrm.NewEndpoint(host, port, false, false, nil, nil, nil, 0)

	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter {
		return winrm.NewClientNTLMEncrypted()
	}

	client, err := winrm.NewClientWithParameters(endpoint, user, pass, params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client create failed: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	exitCode, err := client.RunWithContext(ctx, cmd, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\nexit code: %d\n", exitCode)
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envOrDefaultInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	var parsed int
	if _, err := fmt.Sscanf(value, "%d", &parsed); err != nil {
		fmt.Fprintf(os.Stderr, "invalid %s=%q, using default %d\n", key, value, fallback)
		return fallback
	}

	return parsed
}