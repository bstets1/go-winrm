package winrm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/bodgit/ntlmssp"
	ntlmhttp "github.com/bodgit/ntlmssp/http"
	"github.com/masterzen/winrm/soap"
)

// contentLengthFixTransport works around a bug in bodgit/ntlmssp where the
// HTTP client's wrap() method replaces the request body with the encrypted
// (sealed) payload but does not update req.ContentLength. This causes Go's
// net/http transport to reject the request with:
//
//	"http: ContentLength=N with Body length M"
//
// This wrapper reads the final body, sets ContentLength to the actual size,
// and forwards the request to the real transport.
type contentLengthFixTransport struct {
	base http.RoundTripper
}

func (t *contentLengthFixTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}
	return t.base.RoundTrip(req)
}

// ClientNTLM provides a transport via NTLMv2 using bodgit/ntlmssp.
// When useEncryption is true, SOAP messages are sealed (encrypted) using
// the NTLM security session, which works with the default Windows
// AllowUnencrypted=false setting.
type ClientNTLM struct {
	clientRequest
	useEncryption bool

	// Cached session state — reused across Post() calls to avoid
	// re-creating the bodgit client on every request. Protected by mu.
	mu             sync.Mutex
	ntlmClient     *ntlmssp.Client
	ntlmHTTPClient *ntlmhttp.Client
	cachedUser     string
	cachedPass     string
}

// Transport creates the base HTTP transport for NTLM connections.
func (c *ClientNTLM) Transport(endpoint *Endpoint) error {
	return c.clientRequest.Transport(endpoint)
}

// Post sends a SOAP message to the WinRM service using NTLM authentication.
// It reuses cached NTLM sessions when possible to avoid repeated handshakes.
func (c *ClientNTLM) Post(client *Client, request *soap.SoapMessage) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureSession(client); err != nil {
		return "", err
	}

	if c.useEncryption {
		return c.postEncrypted(client, request)
	}
	return c.postPlain(client, request)
}

// ensureSession creates or reuses the bodgit NTLM client and HTTP client.
// If credentials changed, the session is re-created.
//
// No separate auth handshake is performed here. bodgit's Do() handles
// the full NTLM Negotiate → Challenge → Authenticate flow inline with
// the actual SOAP request. This ensures the handshake and the encrypted
// payload travel on the same TCP connection, which is required because
// NTLM sessions are bound to the connection.
func (c *ClientNTLM) ensureSession(client *Client) error {
	// Check if we need a fresh session (first call or credentials changed)
	credentialsChanged := client.username != c.cachedUser || client.password != c.cachedPass

	if c.ntlmHTTPClient != nil && !credentialsChanged {
		return nil // reuse existing session
	}

	userName, domain := parseUsernameAndDomain(client.username)

	ntlmClient, err := ntlmssp.NewClient(
		ntlmssp.SetUserInfo(userName, client.password),
		ntlmssp.SetDomain(domain),
		ntlmssp.SetVersion(ntlmssp.DefaultVersion()),
	)
	if err != nil {
		return fmt.Errorf("failed to create NTLM client: %w", err)
	}

	httpClient := &http.Client{Transport: c.transport}

	var opts []func(*ntlmhttp.Client) error
	if c.useEncryption {
		opts = append(opts, ntlmhttp.Encryption(true))
	}

	ntlmHTTPClient, err := ntlmhttp.NewClient(httpClient, ntlmClient, opts...)
	if err != nil {
		return fmt.Errorf("failed to create NTLM HTTP client: %w", err)
	}

	// Swap in our Content-Length fixing transport AFTER bodgit's NewClient()
	// has validated the *http.Transport (it type-asserts to check
	// DisableKeepAlives). bodgit stores the *http.Client by reference, so
	// subsequent Do() calls will use our wrapper, which recalculates
	// Content-Length after bodgit encrypts (seals) the body.
	if c.useEncryption {
		httpClient.Transport = &contentLengthFixTransport{base: c.transport}
	}

	c.ntlmClient = ntlmClient
	c.ntlmHTTPClient = ntlmHTTPClient
	c.cachedUser = client.username
	c.cachedPass = client.password

	return nil
}

// postPlain sends a SOAP request without message-level encryption.
// The NTLM handshake happens transparently via bodgit's HTTP client.
func (c *ClientNTLM) postPlain(client *Client, request *soap.SoapMessage) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), "POST", client.url, strings.NewReader(request.String()))
	if err != nil {
		return "", fmt.Errorf("impossible to create http request %w", err)
	}
	req.Header.Set("Content-Type", soapXML+";charset=UTF-8")

	resp, err := c.ntlmHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("unknown error %w", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http error %d: %s", resp.StatusCode, string(respBody))
	}

	if !strings.Contains(resp.Header.Get("Content-Type"), "application/soap+xml") {
		return "", fmt.Errorf("invalid content type")
	}

	return string(respBody), nil
}

// postEncrypted sends a SOAP request with NTLM message-level encryption.
//
// bodgit's Do() handles the complete flow in a single call:
//  1. Sends the request (plain on first call since NTLM isn't complete yet)
//  2. Receives 401 with WWW-Authenticate: Negotiate
//  3. Performs the NTLM Negotiate → Challenge → Authenticate handshake
//  4. Re-sends the request (now with wrap/seal since the session is established)
//  5. Receives the encrypted response and unwraps it
//
// On subsequent calls the NTLM session is already complete, so bodgit
// wraps the request, sends it, and unwraps the response directly.
//
// If the session becomes stale (e.g. server closed the keepalive
// connection), the request is retried with a fresh NTLM client.
func (c *ClientNTLM) postEncrypted(client *Client, request *soap.SoapMessage) (string, error) {
	result, err := c.doPostEncrypted(client, request)
	if err == nil {
		return result, nil
	}

	if !isEncryptionError(err) {
		return "", err
	}

	// The NTLM session may be stale (server closed the keepalive
	// connection, or the security context expired). Create a fresh
	// NTLM client so Do() performs a new handshake inline.
	c.ntlmHTTPClient = nil
	c.ntlmClient = nil

	if sessionErr := c.ensureSession(client); sessionErr != nil {
		return "", fmt.Errorf("encrypted request retry failed during session setup: %w", sessionErr)
	}

	return c.doPostEncrypted(client, request)
}

// doPostEncrypted performs a single encrypted SOAP round-trip.
// bodgit's Do() transparently handles NTLM auth and message encryption.
func (c *ClientNTLM) doPostEncrypted(client *Client, request *soap.SoapMessage) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), "POST", client.url, strings.NewReader(request.String()))
	if err != nil {
		return "", fmt.Errorf("failed to create SOAP request: %w", err)
	}
	req.Header.Set("Content-Type", soapXML+";charset=UTF-8")
	req.Header.Set("Connection", "Keep-Alive")

	resp, err := c.ntlmHTTPClient.Do(req)
	if err != nil {
		// Session may have expired — reset so next call re-establishes
		c.ntlmHTTPClient = nil
		return "", fmt.Errorf("encrypted request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http error %d: %s", resp.StatusCode, string(respBody))
	}

	return string(respBody), nil
}

// isEncryptionError reports whether err looks like a failure in the NTLM
// message encryption/decryption layer (bodgit's wrap/unwrap). These errors
// are recoverable by re-establishing the NTLM session.
func isEncryptionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no Content-Type header") ||
		strings.Contains(msg, "incorrect Content-Type value")
}

// NewClientNTLMWithDial creates a new NTLM transport with a custom dialer.
func NewClientNTLMWithDial(dial func(network, addr string) (net.Conn, error)) *ClientNTLM {
	return &ClientNTLM{
		clientRequest: clientRequest{
			dial: dial,
		},
	}
}

// NewClientNTLMWithProxyFunc creates a new NTLM transport with a custom proxy function.
func NewClientNTLMWithProxyFunc(proxyfunc func(req *http.Request) (*url.URL, error)) *ClientNTLM {
	return &ClientNTLM{
		clientRequest: clientRequest{
			proxyfunc: proxyfunc,
		},
	}
}

// NewClientNTLMEncrypted creates an NTLM transport with message encryption (sealing).
// This works with the default Windows AllowUnencrypted=false setting.
func NewClientNTLMEncrypted() *ClientNTLM {
	return &ClientNTLM{useEncryption: true}
}

// NewClientNTLMEncryptedWithDial creates an encrypted NTLM transport with a custom dialer.
func NewClientNTLMEncryptedWithDial(dial func(network, addr string) (net.Conn, error)) *ClientNTLM {
	return &ClientNTLM{
		clientRequest: clientRequest{dial: dial},
		useEncryption: true,
	}
}

// NewClientNTLMEncryptedWithProxyFunc creates an encrypted NTLM transport with a custom proxy function.
func NewClientNTLMEncryptedWithProxyFunc(proxyfunc func(req *http.Request) (*url.URL, error)) *ClientNTLM {
	return &ClientNTLM{
		clientRequest: clientRequest{proxyfunc: proxyfunc},
		useEncryption: true,
	}
}

// parseUsernameAndDomain extracts the username and domain from various formats:
//   - "DOMAIN\user" -> user, DOMAIN
//   - "user@domain.com" -> user, domain.com
//   - "user" -> user, ""
func parseUsernameAndDomain(username string) (string, string) {
	if strings.Contains(username, "@") {
		parts := strings.Split(username, "@")
		return parts[0], parts[1]
	} else if strings.Contains(username, "\\") {
		parts := strings.Split(username, "\\")
		return parts[1], parts[0]
	}
	return username, ""
}
