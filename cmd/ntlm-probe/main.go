// cmd/ntlm-probe: bare-metal test using bodgit's ntlmhttp.Client directly,
// bypassing all winrm library code. Validates that bodgit + the target
// WinRM server can complete the encrypted handshake.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"strings"

	"github.com/bodgit/ntlmssp"
	ntlmhttp "github.com/bodgit/ntlmssp/http"
)

var wwwAuthHeader = textproto.CanonicalMIMEHeaderKey("WWW-Authenticate")

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

// loggingTransport wraps an http.Transport and logs each request/response.
type loggingTransport struct {
	label string
	inner http.RoundTripper
	seq   int
}

func (lt *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	lt.seq++
	fmt.Fprintf(os.Stderr, "[%s #%d] → %s %s\n", lt.label, lt.seq, req.Method, req.URL)
	for k, vs := range req.Header {
		for _, v := range vs {
			fmt.Fprintf(os.Stderr, "[%s #%d]   req> %s: %s\n", lt.label, lt.seq, k, v)
		}
	}
	if req.ContentLength >= 0 {
		fmt.Fprintf(os.Stderr, "[%s #%d]   ContentLength=%d\n", lt.label, lt.seq, req.ContentLength)
	}
	resp, err := lt.inner.RoundTrip(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s #%d] ← error: %v\n", lt.label, lt.seq, err)
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "[%s #%d] ← %d\n", lt.label, lt.seq, resp.StatusCode)
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(os.Stderr, "[%s #%d]   %s: %s\n", lt.label, lt.seq, k, v)
		}
	}
	return resp, nil
}

func main() {
	host := envOrDefault("WINRM_HOST", "192.168.100.61")
	port := envOrDefault("WINRM_PORT", "5985")
	user := os.Getenv("WINRM_USER")
	pass := os.Getenv("WINRM_PASS")
	if user == "" || pass == "" {
		fmt.Fprintln(os.Stderr, "Set WINRM_USER and WINRM_PASS")
		os.Exit(2)
	}

	url := fmt.Sprintf("http://%s:%s/wsman", host, port)
	userName, domain := parseUsernameAndDomain(user)
	fmt.Fprintf(os.Stderr, "parsed: user=%q domain=%q\n", userName, domain)

	fmt.Fprintln(os.Stderr, "\n=== MODE 1: bodgit ntlmhttp.Client WITH encryption ===")
	testBodgitClient(url, userName, domain, pass, true)

	fmt.Fprintln(os.Stderr, "\n=== MODE 3: bodgit ntlmhttp.Client WITHOUT encryption (plain NTLM) ===")
	testBodgitClient(url, userName, domain, pass, false)

	fmt.Fprintln(os.Stderr, "\n=== MODE 2: manual 2-round NTLM (NEGOTIATE+AUTHENTICATE+sealed) ===")
	testManualClient(url, userName, domain, pass)
}

const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:cfg="http://schemas.microsoft.com/wbem/wsman/1/config"><env:Header><a:To>http://windows-host:5985/wsman</a:To><w:ResourceURI env:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI><a:ReplyTo><a:Address env:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><a:Action env:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action><w:MaxEnvelopeSize env:mustUnderstand="true">153600</w:MaxEnvelopeSize><a:MessageID>uuid:00000000-0000-0000-0000-000000000001</a:MessageID><w:Locale xml:lang="en-US" env:mustUnderstand="false"/><p:DataLocale xml:lang="en-US" env:mustUnderstand="false"/><w:OperationTimeout>PT60.000S</w:OperationTimeout><w:OptionSet><w:Option Name="WINRS_CODEPAGE">65001</w:Option><w:Option Name="WINRS_NOPROFILE">FALSE</w:Option></w:OptionSet></env:Header><env:Body><rsp:Shell><rsp:Environment/><rsp:WorkingDirectory>C:\</rsp:WorkingDirectory><rsp:Lifetime>PT60.000S</rsp:Lifetime><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell></env:Body></env:Envelope>`

func testBodgitClient(url, userName, domain, pass string, useEncryption bool) {
	ntlmClient, err := ntlmssp.NewClient(
		ntlmssp.SetUserInfo(userName, pass),
		ntlmssp.SetDomain(domain),
		ntlmssp.SetVersion(ntlmssp.DefaultVersion()),
	)
	must(err)

	// bodgit type-asserts Transport to *http.Transport, so pass the bare transport.
	pt := &http.Transport{}
	pt.MaxConnsPerHost = 1
	rawHTTP := &http.Client{Transport: pt}

	opts := []func(*ntlmhttp.Client) error{}
	if useEncryption {
		opts = append(opts, ntlmhttp.Encryption(true))
	}
	bodgitClient, err := ntlmhttp.NewClient(rawHTTP, ntlmClient, opts...)
	must(err)

	// Swap in logging transport AFTER bodgit has grabbed the raw *http.Transport.
	lt := &loggingTransport{label: "bodgit", inner: pt}
	rawHTTP.Transport = lt

	req, err := http.NewRequestWithContext(context.Background(), "POST", url, strings.NewReader(soapBody))
	must(err)
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")

	resp, err := bodgitClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bodgit error:", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Fprintf(os.Stderr, "bodgit FINAL: status=%d ct=%s body[:%d]=%s\n",
		resp.StatusCode, resp.Header.Get("Content-Type"),
		min(200, len(body)), body[:min(200, len(body))])
}

func testManualClient(url, userName, domain, pass string) {
	ntlmClient, err := ntlmssp.NewClient(
		ntlmssp.SetUserInfo(userName, pass),
		ntlmssp.SetDomain(domain),
		ntlmssp.SetVersion(ntlmssp.DefaultVersion()),
	)
	must(err)

	pt := &http.Transport{}
	pt.MaxConnsPerHost = 1
	pt.MaxIdleConnsPerHost = 1
	// Install logging transport BEFORE all requests
	lt2 := &loggingTransport{label: "manual", inner: pt}
	rawHTTP := &http.Client{Transport: lt2}

	soapBytes := []byte(soapBody)
	fmt.Fprintf(os.Stderr, "soapBytes len=%d\n", len(soapBytes))

	// Phase 1: 3-way NTLM handshake with EMPTY BODY to establish session
	// (mimicking pywinrm's setup_encryption which sends data=None first)

	// Phase1-Req1: Attempt empty request (get bare 401)
	probe, _ := http.NewRequestWithContext(context.Background(), "POST", url, http.NoBody)
	probe.ContentLength = 0
	probe.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	resp0, err := rawHTTP.Do(probe)
	must(err)
	io.ReadAll(resp0.Body)
	resp0.Body.Close()
	fmt.Fprintf(os.Stderr, "probe: status=%d\n", resp0.StatusCode)
	if resp0.StatusCode != http.StatusUnauthorized {
		fmt.Fprintf(os.Stderr, "expected 401 on probe, got %d\n", resp0.StatusCode)
		return
	}

	// Phase1-Req2: NEGOTIATE with empty body
	negToken, err := ntlmClient.Authenticate(nil, nil)
	must(err)
	req1, _ := http.NewRequestWithContext(context.Background(), "POST", url, http.NoBody)
	req1.ContentLength = 0
	req1.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req1.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(negToken))
	resp1, err := rawHTTP.Do(req1)
	must(err)
	io.ReadAll(resp1.Body)
	resp1.Body.Close()
	fmt.Fprintf(os.Stderr, "negotiate: status=%d\n", resp1.StatusCode)
	if resp1.StatusCode != http.StatusUnauthorized {
		fmt.Fprintf(os.Stderr, "expected 401 on negotiate, got %d\n", resp1.StatusCode)
		return
	}

	// Extract challenge
	var challengeToken []byte
	for _, v := range resp1.Header[wwwAuthHeader] {
		if strings.HasPrefix(v, "Negotiate ") {
			challengeToken, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(v, "Negotiate "))
			must(err)
			break
		}
	}
	if challengeToken == nil {
		fmt.Fprintln(os.Stderr, "no challenge token in NEGOTIATE response")
		return
	}
	fmt.Fprintf(os.Stderr, "  challenge len=%d\n", len(challengeToken))

	// Phase1-Req3: AUTHENTICATE with empty body — establishes session
	authToken, err := ntlmClient.Authenticate(challengeToken, nil)
	must(err)
	req3, _ := http.NewRequestWithContext(context.Background(), "POST", url, http.NoBody)
	req3.ContentLength = 0
	req3.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req3.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(authToken))
	resp3, err := rawHTTP.Do(req3)
	must(err)
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	fmt.Fprintf(os.Stderr, "authenticate(empty): status=%d conn=%q body[:100]=%s\n",
		resp3.StatusCode, resp3.Header.Get("Connection"), body3[:min(100, len(body3))])

	// Get the security session from the completed NTLM exchange
	session := ntlmClient.SecuritySession()
	if session == nil {
		fmt.Fprintln(os.Stderr, "no security session after Authenticate!")
		return
	}
	fmt.Fprintln(os.Stderr, "session established!")

	// Phase 2: Now send the actual encrypted SOAP
	// NO Authorization header — the TCP connection is already authenticated
	sealed, signature, err := session.Wrap(soapBytes)
	must(err)

	payload := make([]byte, 4+len(signature)+len(sealed))
	binary.LittleEndian.PutUint32(payload[0:4], uint32(len(signature)))
	copy(payload[4:], signature)
	copy(payload[4+len(signature):], sealed)

	fmt.Fprintf(os.Stderr, "soapBytes len=%d  payload len=%d (sig=%d sealed=%d)\n",
		len(soapBytes), len(payload), len(signature), len(sealed))

	encBody, encCT := buildEncryptedMultipart(payload, "application/soap+xml;charset=UTF-8", len(soapBytes))
	fmt.Fprintf(os.Stderr, "encBody len=%d\n", len(encBody))

	// Send the encrypted SOAP — no Authorization header (session already on this conn)
	reqSOAP, _ := http.NewRequestWithContext(context.Background(), "POST", url, bytes.NewReader(encBody))
	reqSOAP.Header.Set("Content-Type", encCT)
	reqSOAP.ContentLength = int64(len(encBody))

	respSOAP, err := rawHTTP.Do(reqSOAP)
	must(err)
	defer respSOAP.Body.Close()
	bodySOAP, _ := io.ReadAll(respSOAP.Body)
	fmt.Fprintf(os.Stderr, "SOAP(encrypted) response: status=%d ct=%s\n",
		respSOAP.StatusCode, respSOAP.Header.Get("Content-Type"))
	fmt.Fprintf(os.Stderr, "soap-enc body[:200]: %s\n", bodySOAP[:min(200, len(bodySOAP))])
}

func envOrDefault(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

// buildEncryptedMultipart constructs the multipart/encrypted body manually,
// allowing originalLen to differ from len(payload). Per MS-WSMV §5.2.2.1,
// OriginalContent.Length should be the length of the ORIGINAL (unencrypted)
// content, but many implementations use len(payload) (the encrypted blob).
// Pass originalLen=len(soapBytes) to use the spec-compliant value.
func buildEncryptedMultipart(payload []byte, contentType string, originalLen int) ([]byte, string) {
	const boundary = "Encrypted Boundary"
	const protocol = "application/HTTP-SPNEGO-session-encrypted"
	const ct = "multipart/encrypted;protocol=\"" + protocol + "\";boundary=\"" + boundary + "\""

	var b []byte
	// Part 1: header part (WSMV uses tab-indented headers, no blank line)
	b = append(b, "--"+boundary+"\r\n"...)
	b = append(b, "\tContent-Type: "+protocol+"\r\n"...)
	b = append(b, "\tOriginalContent: type="+contentType+";Length="+fmt.Sprintf("%d", originalLen)+"\r\n"...)
	// Part 2: encrypted payload (WSMV uses tab-indented content-type, then data directly)
	b = append(b, "--"+boundary+"\r\n"...)
	b = append(b, "\tContent-Type: application/octet-stream\r\n"...)
	// No extra blank line before binary body - this matches WSMV toWSMV formatting
	// which strips empty lines between boundary and content
	b = append(b, payload...)
	// No CRLF before closing boundary - matches pywinrm's format
	b = append(b, "--"+boundary+"--\r\n"...)
	return b, ct
}

func parseUsernameAndDomain(username string) (string, string) {
	if strings.Contains(username, "@") {
		parts := strings.Split(username, "@")
		return parts[0], parts[1]
	} else if strings.Contains(username, "\\") {
		parts := strings.Split(username, "\\")
		user, domain := parts[1], parts[0]
		if domain == "." {
			domain = ""
		}
		return user, domain
	}
	return username, ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
