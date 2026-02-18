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
	// re-handshaking on every request. Protected by mu.
	mu             sync.Mutex
	ntlmClient     *ntlmssp.Client
	ntlmHTTPClient *ntlmhttp.Client
	cachedUser     string
	cachedPass     string
	sessionReady   bool // true after encrypted session handshake completes
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
// For encrypted sessions, performs the initial auth handshake if needed.
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
	c.sessionReady = false

	// For encrypted mode, establish the NTLM session immediately
	// with an empty POST so the security session is ready for sealing.
	if c.useEncryption {
		if err := c.doAuthHandshake(client); err != nil {
			// Reset session state on failure
			c.ntlmHTTPClient = nil
			c.ntlmClient = nil
			c.sessionReady = false
			return err
		}
		c.sessionReady = true
	}

	return nil
}

// doAuthHandshake performs the NTLM authentication handshake with an empty
// POST request. After this completes, the security session is established
// and can be used for message sealing/unsealing.
func (c *ClientNTLM) doAuthHandshake(client *Client) error {
	req, err := http.NewRequestWithContext(context.Background(), "POST", client.url, nil)
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", soapXML+";charset=UTF-8")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Connection", "Keep-Alive")

	resp, err := c.ntlmHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("NTLM authentication failed: %w", err)
	}
	defer resp.Body.Close()

	if _, err := io.ReadAll(resp.Body); err != nil {
		return fmt.Errorf("read auth response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("NTLM auth http error %d", resp.StatusCode)
	}

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
// The NTLM session must already be established via doAuthHandshake().
// bodgit's HTTP client automatically wraps (seals) the request and
// unwraps (unseals) the response.
//
// If the first attempt fails with an encryption-related error (e.g. stale
// keepalive connection), the session is re-established and the request is
// retried once. If the retry also fails with an encryption error, a
// descriptive message is returned suggesting the server may not support
// NTLM message encryption.
func (c *ClientNTLM) postEncrypted(client *Client, request *soap.SoapMessage) (string, error) {
	result, err := c.doPostEncrypted(client, request)
	if err == nil {
		return result, nil
	}

	if !isEncryptionError(err) {
		return "", err
	}

	// The NTLM session may be stale (server closed the keepalive
	// connection, or the security context expired). Re-establish
	// the session from scratch and retry once.
	c.ntlmHTTPClient = nil
	c.ntlmClient = nil
	c.sessionReady = false

	if sessionErr := c.ensureSession(client); sessionErr != nil {
		return "", fmt.Errorf("encrypted request failed (retry re-auth failed): %w", sessionErr)
	}

	result, retryErr := c.doPostEncrypted(client, request)
	if retryErr != nil {
		if isEncryptionError(retryErr) {
			return "", fmt.Errorf("server did not return an encrypted response; "+
				"it may not support NTLM message-level encryption — "+
				"try plain NTLM (without encryption) or use HTTPS: %w", retryErr)
		}
		return "", retryErr
	}

	return result, nil
}

// doPostEncrypted performs a single encrypted SOAP round-trip.
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
		c.sessionReady = false
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
