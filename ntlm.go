package winrm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/bodgit/ntlmssp"
	ntlmhttp "github.com/bodgit/ntlmssp/http"
	"github.com/masterzen/winrm/soap"
)

var wwwAuthHeader = textproto.CanonicalMIMEHeaderKey("WWW-Authenticate")

// ntlmDebug prints to stderr when WINRM_DEBUG=1.
func ntlmDebug(format string, args ...interface{}) {
	if os.Getenv("WINRM_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "[ntlm] "+format+"\n", args...)
	}
}

// debugRoundTripper logs HTTP request/response metadata to stderr when WINRM_DEBUG=1.
// It does NOT modify ContentLength or bodies.
type debugRoundTripper struct {
	base  http.RoundTripper
	label string
}

func (d *debugRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	authLen := 0
	if a := req.Header.Get("Authorization"); a != "" {
		authLen = len(a)
	}
	ntlmDebug("[%s] → POST %s  CT=%q  auth=%d  CL=%d",
		d.label, req.URL.Path, req.Header.Get("Content-Type"), authLen, req.ContentLength)
	resp, err := d.base.RoundTrip(req)
	if err != nil {
		ntlmDebug("[%s] ← ERROR: %v", d.label, err)
		return nil, err
	}
	ntlmDebug("[%s] ← %d  CT=%q  Conn=%q",
		d.label, resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Connection"))
	return resp, nil
}

// wrapDebug wraps t in a debug logger when WINRM_DEBUG=1, otherwise returns t unchanged.
// NOTE: Do NOT use the wrapped result where a *http.Transport type-assertion is required.
func wrapDebug(label string, t http.RoundTripper) http.RoundTripper {
	if os.Getenv("WINRM_DEBUG") == "1" {
		return &debugRoundTripper{base: t, label: label}
	}
	return t
}

// ClientNTLM provides a transport via NTLMv2 using bodgit/ntlmssp.
//
//   - Plain NTLM (useEncryption==false): delegates to bodgit's ntlmhttp.Client which handles
//     the NTLM 3-way handshake transparently. Requires AllowUnencrypted=true on the server.
//
//   - Encrypted NTLM (useEncryption==true): implements the MS-WSMV NTLM message-encryption
//     protocol (application/HTTP-SPNEGO-session-encrypted) directly. Works with the default
//     Windows AllowUnencrypted=false. The AUTHENTICATE token and sealed SOAP body are combined
//     in a single HTTP request as required by MS-WSMV §7.2.
type ClientNTLM struct {
	clientRequest
	useEncryption bool

	mu sync.Mutex

	// Shared state
	ntlmClient *ntlmssp.Client
	cachedUser string
	cachedPass string

	// Plain NTLM only — bodgit's client handles auth transparently.
	ntlmHTTPClient *ntlmhttp.Client

	// Encrypted NTLM only — we drive the wire protocol manually.
	rawHTTP         *http.Client    // pinned-connection http.Client
	pinnedTransport *http.Transport // underlying transport (owns conn pool)
	sessionReady    bool
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

// ensureSession creates or reuses the NTLM session.
//
// Encrypted path: initialises the raw http.Client. The actual NTLM 3-way
// handshake (probe→NEGOTIATE→AUTHENTICATE) is deferred to doPostEncrypted
// so it can be done on the correct TCP connection.
//
// Plain path: creates a bodgit ntlmhttp.Client which drives the full 3-way
// handshake transparently on every new TCP connection.
func (c *ClientNTLM) ensureSession(client *Client) error {
	credentialsChanged := client.username != c.cachedUser || client.password != c.cachedPass
	if c.useEncryption {
		if c.rawHTTP != nil && !credentialsChanged {
			return nil
		}
	} else {
		if c.ntlmHTTPClient != nil && !credentialsChanged {
			return nil
		}
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

	if c.useEncryption {
		return c.setupEncryptedSession(client, ntlmClient)
	}
	return c.setupPlainSession(client, ntlmClient)
}

// setupEncryptedSession initialises the raw http.Client for the encrypted
// path. The NTLM 3-way handshake (probe→NEGOTIATE→AUTHENTICATE with empty
// bodies) is deferred to primeNTLM, called from doPostEncrypted on first use.
func (c *ClientNTLM) setupEncryptedSession(client *Client, ntlmClient *ntlmssp.Client) error {
	var pt *http.Transport
	if t, ok := c.transport.(*http.Transport); ok {
		pt = t.Clone()
	} else {
		pt = &http.Transport{}
	}
	pt.MaxConnsPerHost = 1
	pt.MaxIdleConnsPerHost = 1

	// Track new dials in debug mode to detect unexpected connection recreation.
	if os.Getenv("WINRM_DEBUG") == "1" {
		baseDial := pt.DialContext
		if baseDial == nil {
			d := &net.Dialer{}
			baseDial = d.DialContext
		}
		connNum := 0
		pt.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			connNum++
			ntlmDebug("TCP DIAL #%d → %s", connNum, addr)
			return baseDial(ctx, network, addr)
		}
	}

	rawHTTP := &http.Client{Transport: wrapDebug("raw", pt)}

	c.ntlmClient = ntlmClient
	c.rawHTTP = rawHTTP
	c.pinnedTransport = pt
	c.sessionReady = false
	c.cachedUser = client.username
	c.cachedPass = client.password
	return nil
}

// setupPlainSession creates a bodgit ntlmhttp.Client for plain (unencrypted)
// NTLM, which drives the full 3-way handshake transparently.
func (c *ClientNTLM) setupPlainSession(client *Client, ntlmClient *ntlmssp.Client) error {
	var pt *http.Transport
	if t, ok := c.transport.(*http.Transport); ok {
		pt = t.Clone()
	} else {
		pt = &http.Transport{}
	}
	pt.MaxConnsPerHost = 1

	// bodgit's NewClient type-asserts rawHTTP.Transport to *http.Transport.
	// Pass the bare transport here; optionally replace with a debug wrapper after.
	rawHTTP := &http.Client{Transport: pt}

	ntlmHTTPClient, err := ntlmhttp.NewClient(rawHTTP, ntlmClient)
	if err != nil {
		return fmt.Errorf("failed to create NTLM HTTP client: %w", err)
	}

	// Swap in the debug logger after bodgit has validated the transport.
	rawHTTP.Transport = wrapDebug("raw", pt)

	c.ntlmClient = ntlmClient
	c.ntlmHTTPClient = ntlmHTTPClient
	c.rawHTTP = rawHTTP
	c.pinnedTransport = pt
	c.cachedUser = client.username
	c.cachedPass = client.password
	c.sessionReady = true
	return nil
}

// primeNTLM drives the NTLM 3-way handshake using empty bodies (pywinrm pattern).
//
// Step 1: POST empty body, no auth → 401
// Step 2: POST empty body + NEGOTIATE → 401 + CHALLENGE
// Step 3: POST empty body + AUTHENTICATE → 200 (session established)
//
// This matches pywinrm's setup_encryption() approach: establish the NTLM
// session on the TCP connection with empty bodies first, then send encrypted
// SOAP separately on the same connection.
//
// Sets c.sessionReady=true on success.
func (c *ClientNTLM) primeNTLM(urlStr string) error {
	emptyBody := func(authHeader string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(context.Background(), "POST", urlStr, http.NoBody)
		if err != nil {
			return nil, err
		}
		req.ContentLength = 0
		req.Header.Set("Content-Type", soapXML+";charset=UTF-8")
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		resp, err := c.rawHTTP.Do(req)
		if err != nil {
			return nil, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp, nil
	}

	// Step 1: probe (no auth) → expect 401
	resp1, err := emptyBody("")
	if err != nil {
		return fmt.Errorf("NTLM probe: %w", err)
	}
	ntlmDebug("primeNTLM step1(probe): status=%d", resp1.StatusCode)
	if resp1.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("NTLM probe: expected 401, got %d", resp1.StatusCode)
	}

	// Step 2: NEGOTIATE (empty body) → expect 401 + challenge
	negotiateToken, err := c.ntlmClient.Authenticate(nil, nil)
	if err != nil {
		return fmt.Errorf("NTLM negotiate token: %w", err)
	}
	resp2, err := emptyBody("Negotiate " + base64.StdEncoding.EncodeToString(negotiateToken))
	if err != nil {
		return fmt.Errorf("NTLM negotiate: %w", err)
	}
	ntlmDebug("primeNTLM step2(negotiate): status=%d", resp2.StatusCode)
	if resp2.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("NTLM negotiate: expected 401, got %d", resp2.StatusCode)
	}
	challenge, err := extractNTLMToken(resp2)
	if err != nil {
		return fmt.Errorf("NTLM negotiate challenge: %w", err)
	}

	// Step 3: AUTHENTICATE (empty body) → expect 200 (session established)
	authenticateToken, err := c.ntlmClient.Authenticate(challenge, nil)
	if err != nil {
		return fmt.Errorf("NTLM authenticate token: %w", err)
	}
	resp3, err := emptyBody("Negotiate " + base64.StdEncoding.EncodeToString(authenticateToken))
	if err != nil {
		return fmt.Errorf("NTLM authenticate: %w", err)
	}
	ntlmDebug("primeNTLM step3(authenticate): status=%d", resp3.StatusCode)
	if resp3.StatusCode != http.StatusOK {
		return fmt.Errorf("NTLM authenticate: expected 200, got %d (check credentials)", resp3.StatusCode)
	}

	c.sessionReady = true
	return nil
}

// extractNTLMToken parses the first "Negotiate <base64>" value from the
// WWW-Authenticate response header.
func extractNTLMToken(resp *http.Response) ([]byte, error) {
	for _, v := range resp.Header[wwwAuthHeader] {
		if strings.HasPrefix(v, "Negotiate ") {
			tok, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, "Negotiate "))
			if err != nil {
				return nil, fmt.Errorf("decode NTLM token: %w", err)
			}
			return tok, nil
		}
	}
	return nil, fmt.Errorf("no Negotiate token in WWW-Authenticate header")
}

// postPlain sends a SOAP message using bodgit's ntlmhttp.Client, which
// handles NTLM 3-way auth transparently. Requires AllowUnencrypted=true.
func (c *ClientNTLM) postPlain(client *Client, request *soap.SoapMessage) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), "POST", client.url,
		strings.NewReader(request.String()))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", soapXML+";charset=UTF-8")

	resp, err := c.ntlmHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ntlm plain: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http %d: %s", resp.StatusCode, body)
	}
	return string(body), nil
}

// postEncrypted sends a SOAP message with NTLM message-level encryption.
//
// On the first call it runs primeNTLM (3 empty-body requests) to establish the
// NTLM session, then sends the encrypted SOAP on the same TCP connection.
// Subsequent calls reuse the session (no Authorization header).
//
// On any error the session is torn down and the attempt is retried once
// (recovers from stale keepalive connections).
func (c *ClientNTLM) postEncrypted(client *Client, request *soap.SoapMessage) (string, error) {
	result, err := c.doPostEncrypted(client, request)
	if err == nil {
		return result, nil
	}

	// Tear down and retry once on any error — stale keepalive connection.
	ntlmDebug("postEncrypted: error=%v; resetting session", err)
	c.rawHTTP = nil
	c.pinnedTransport = nil
	c.ntlmClient = nil
	c.sessionReady = false

	if sessionErr := c.ensureSession(client); sessionErr != nil {
		return "", fmt.Errorf("retry session setup: %w", sessionErr)
	}
	return c.doPostEncrypted(client, request)
}

// doPostEncrypted performs the full encrypted SOAP lifecycle:
//
//   - If not yet authenticated (sessionReady==false): runs the NTLM 3-way
//     empty-body handshake (probe→NEGOTIATE→AUTHENTICATE) to establish the
//     session, then sends the encrypted SOAP on the same connection.
//
//   - If sessionReady==true: seals the SOAP body and sends it without an
//     Authorization header (session already established on this connection).
func (c *ClientNTLM) doPostEncrypted(client *Client, request *soap.SoapMessage) (string, error) {
	soapBytes := []byte(request.String())

	// Run the 3-way empty-body NTLM handshake if session not yet established.
	if !c.sessionReady {
		if err := c.primeNTLM(client.url); err != nil {
			return "", err
		}
	}

	encBody, encCT, err := c.sealSOAP(soapBytes)
	if err != nil {
		return "", fmt.Errorf("seal SOAP: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", client.url, bytes.NewReader(encBody))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", encCT)
	req.Header.Set("Connection", "Keep-Alive")
	req.ContentLength = int64(len(encBody))

	ntlmDebug("doPostEncrypted: sending sealed SOAP (no auth header — session on conn)")

	resp, err := c.rawHTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	ntlmDebug("doPostEncrypted: status=%d ct=%q", resp.StatusCode, resp.Header.Get("Content-Type"))

	if resp.StatusCode == http.StatusUnauthorized {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("session expired (401)")
	}

	return c.unsealResponse(resp)
}

// sealSOAP encrypts soapBytes using the established NTLM security session
// and builds the multipart/encrypted body required by MS-WSMV.
//
// Wire format for the encrypted payload (second MIME part):
//
//	[4-byte LE: len(signature)] [signature bytes] [sealed body bytes]
//
// The multipart format matches pywinrm's _encrypt_message:
// - OriginalContent Length = len(soapBytes) (original, not encrypted)
// - No \r\n before the closing boundary delimiter
func (c *ClientNTLM) sealSOAP(soapBytes []byte) (body []byte, ct string, err error) {
	session := c.ntlmClient.SecuritySession()
	if session == nil {
		return nil, "", fmt.Errorf("no NTLM security session available")
	}

	sealed, signature, err := session.Wrap(soapBytes)
	if err != nil {
		return nil, "", fmt.Errorf("session.Wrap: %w", err)
	}

	// Build payload: 4-byte LE signature length + signature + sealed body.
	payload := make([]byte, 4+len(signature)+len(sealed))
	binary.LittleEndian.PutUint32(payload[0:4], uint32(len(signature)))
	copy(payload[4:], signature)
	copy(payload[4+len(signature):], sealed)

	body, ct = buildEncryptedMultipart(payload, soapXML+";charset=UTF-8", len(soapBytes))
	ntlmDebug("sealSOAP: payload=%d sigLen=%d sealedLen=%d totalBody=%d",
		len(payload), len(signature), len(sealed), len(body))
	return body, ct, nil
}

// buildEncryptedMultipart constructs the multipart/encrypted MIME body required
// by MS-WSMV §2.2.9.1 for NTLM-encrypted SOAP messages.
//
// Format (matches pywinrm _encrypt_message exactly):
//
//	--Encrypted Boundary\r\n
//	\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n
//	\tOriginalContent: type=<contentType>;Length=<originalLen>\r\n
//	--Encrypted Boundary\r\n
//	\tContent-Type: application/octet-stream\r\n
//	[payload][--Encrypted Boundary--\r\n]
//
// Note: originalLen must be len(original SOAP), NOT len(encrypted payload).
// Note: no \r\n before the closing boundary delimiter (pywinrm-compatible).
func buildEncryptedMultipart(payload []byte, contentType string, originalLen int) ([]byte, string) {
	const boundary = "Encrypted Boundary"
	const protocol = "application/HTTP-SPNEGO-session-encrypted"
	const ct = "multipart/encrypted;protocol=\"" + protocol + "\";boundary=\"" + boundary + "\""

	var b []byte
	b = append(b, "--"+boundary+"\r\n"...)
	b = append(b, "\tContent-Type: "+protocol+"\r\n"...)
	b = append(b, "\tOriginalContent: type="+contentType+";Length="+fmt.Sprintf("%d", originalLen)+"\r\n"...)
	b = append(b, "--"+boundary+"\r\n"...)
	b = append(b, "\tContent-Type: application/octet-stream\r\n"...)
	b = append(b, payload...)
	// No \r\n before closing boundary — matches pywinrm's format
	b = append(b, "--"+boundary+"--\r\n"...)
	return b, ct
}

// unsealResponse decrypts an encrypted WinRM response.
// It uses ntlmhttp.Unwrap to extract the raw payload, then ntlmssp to
// decrypt and verify the sealed body.
func (c *ClientNTLM) unsealResponse(resp *http.Response) (string, error) {
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http %d: %s", resp.StatusCode, respBody)
	}

	ct := resp.Header.Get("Content-Type")
	payload, _, err := ntlmhttp.Unwrap(respBody, ct)
	if err != nil {
		return "", fmt.Errorf("ntlmhttp.Unwrap: %w", err)
	}

	if len(payload) < 4 {
		return "", fmt.Errorf("encrypted payload too short (%d bytes)", len(payload))
	}
	sigLen := binary.LittleEndian.Uint32(payload[0:4])
	if int(4+sigLen) > len(payload) {
		return "", fmt.Errorf("signature length %d exceeds payload size %d", sigLen, len(payload))
	}
	signature := payload[4 : 4+sigLen]
	sealed := payload[4+sigLen:]

	session := c.ntlmClient.SecuritySession()
	if session == nil {
		return "", fmt.Errorf("no NTLM security session for decryption")
	}
	plain, err := session.Unwrap(sealed, signature)
	if err != nil {
		return "", fmt.Errorf("session.Unwrap: %w", err)
	}
	return string(plain), nil
}

// NewClientNTLMWithDial creates a new NTLM transport with a custom dialer.
func NewClientNTLMWithDial(dial func(network, addr string) (net.Conn, error)) *ClientNTLM {
	return &ClientNTLM{
		clientRequest: clientRequest{dial: dial},
	}
}

// NewClientNTLMWithProxyFunc creates a new NTLM transport with a custom proxy function.
func NewClientNTLMWithProxyFunc(proxyfunc func(req *http.Request) (*url.URL, error)) *ClientNTLM {
	return &ClientNTLM{
		clientRequest: clientRequest{proxyfunc: proxyfunc},
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
		user, domain := parts[1], parts[0]
		// ".\\user" means local account — Windows rejects domain="." in NTLM
		if domain == "." {
			domain = ""
		}
		return user, domain
	}
	return username, ""
}

// isEncryptionError reports whether err looks like a failure in the NTLM
// message encryption/decryption layer (e.g. from ntlmhttp.Unwrap). These
// errors indicate a stale session that can be recovered by re-handshaking.
func isEncryptionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no Content-Type header") ||
		strings.Contains(msg, "incorrect Content-Type value")
}
