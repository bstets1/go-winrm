package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/masterzen/winrm"
)

func main() {
	host := envOrDefault("WINRM_HOST", "192.168.100.62")
	port := envOrDefaultInt("WINRM_PORT", 5985)
	user := os.Getenv("WINRM_USER")
	pass := os.Getenv("WINRM_PASS")
	cmd := envOrDefault("WINRM_COMMAND", "whoami")
	transportMode := strings.ToLower(envOrDefault("WINRM_TRANSPORT", "ntlm-encrypted"))

	if user == "" || pass == "" {
		fmt.Fprintln(os.Stderr, "missing credentials: set WINRM_USER and WINRM_PASS")
		fmt.Fprintln(os.Stderr, "optional: WINRM_HOST WINRM_PORT WINRM_COMMAND WINRM_TRANSPORT (ntlm-encrypted|ntlm|basic)")
		os.Exit(2)
	}

	endpoint := winrm.NewEndpoint(host, port, false, false, nil, nil, nil, 0)

	params := winrm.DefaultParameters
	err := applyTransportMode(params, transportMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid transport: %v\n", err)
		os.Exit(2)
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
		if strings.Contains(err.Error(), "no Content-Type header") && transportMode == "ntlm-encrypted" {
			fmt.Fprintln(os.Stderr, "hint: server did not return an encrypted WinRM response in NTLM-encrypted mode")
			fmt.Fprintln(os.Stderr, "try: set WINRM_TRANSPORT=ntlm to verify auth first, or enable HTTPS on 5986 and test basic/kerberos over TLS")
		}
		os.Exit(1)
	}

	if exitCode != 0 {
		fmt.Fprintf(os.Stderr, "command exit code: %d\n", exitCode)
		os.Exit(1)
	}
}

func applyTransportMode(params *winrm.Parameters, mode string) error {
	switch mode {
	case "ntlm-encrypted":
		params.TransportDecorator = func() winrm.Transporter { return winrm.NewClientNTLMEncrypted() }
		return nil
	case "ntlm":
		params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
		return nil
	case "basic":
		params.TransportDecorator = nil
		return nil
	default:
		return fmt.Errorf("%q (allowed: ntlm-encrypted, ntlm, basic)", mode)
	}
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
