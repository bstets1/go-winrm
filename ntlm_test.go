package winrm

import (
	"net/http"

	"net"
	"time"

	. "gopkg.in/check.v1"
)

func (s *WinRMSuite) TestHttpNTLMRequest(c *C) {
	ts, host, port, err := StartTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/soap+xml")
		_, _ = w.Write([]byte(response))
	}))
	c.Assert(err, IsNil)
	defer ts.Close()
	endpoint := NewEndpoint(host, port, false, false, nil, nil, nil, 0)

	params := DefaultParameters
	params.TransportDecorator = func() Transporter { return &ClientNTLM{} }
	client, err := NewClientWithParameters(endpoint, "test", "test", params)

	c.Assert(err, IsNil)
	shell, err := client.CreateShell()
	c.Assert(err, IsNil)
	c.Assert(shell.id, Equals, "67A74734-DD32-4F10-89DE-49A060483810")
}

func (s *WinRMSuite) TestHttpNTLMViaCustomDialerRequest(c *C) {
	normalDialer := (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial
	usedCustomDialer := false
	dial := func(network, addr string) (net.Conn, error) {
		usedCustomDialer = true
		return normalDialer(network, addr)
	}

	ts, host, port, err := StartTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/soap+xml")
		_, _ = w.Write([]byte(response))
	}))
	c.Assert(err, IsNil)
	defer ts.Close()
	endpoint := NewEndpoint(host, port, false, false, nil, nil, nil, 0)

	params := DefaultParameters
	params.TransportDecorator = func() Transporter { return NewClientNTLMWithDial(dial) }
	client, err := NewClientWithParameters(endpoint, "test", "test", params)
	c.Assert(err, IsNil)
	_, err = client.CreateShell()
	c.Assert(err, IsNil)
	c.Assert(usedCustomDialer, Equals, true)
}

func (s *WinRMSuite) TestParseUsernameAndDomainBackslash(c *C) {
	user, domain := parseUsernameAndDomain(`MYDOMAIN\admin`)
	c.Assert(user, Equals, "admin")
	c.Assert(domain, Equals, "MYDOMAIN")
}

func (s *WinRMSuite) TestParseUsernameAndDomainAtSign(c *C) {
	user, domain := parseUsernameAndDomain("admin@corp.example.com")
	c.Assert(user, Equals, "admin")
	c.Assert(domain, Equals, "corp.example.com")
}

func (s *WinRMSuite) TestParseUsernameAndDomainPlain(c *C) {
	user, domain := parseUsernameAndDomain("admin")
	c.Assert(user, Equals, "admin")
	c.Assert(domain, Equals, "")
}

func (s *WinRMSuite) TestNewEncryptionNTLM(c *C) {
	enc, err := NewEncryption("ntlm")
	c.Assert(err, IsNil)
	c.Assert(enc, NotNil)
	c.Assert(enc.protocol, Equals, "ntlm")
	c.Assert(enc.ntlm.useEncryption, Equals, true)
}

func (s *WinRMSuite) TestNewEncryptionUnsupportedProtocol(c *C) {
	enc, err := NewEncryption("credssp")
	c.Assert(err, NotNil)
	c.Assert(enc, IsNil)
	c.Assert(err, ErrorMatches, `encryption for protocol 'credssp' not supported`)
}

func (s *WinRMSuite) TestNewClientNTLMEncrypted(c *C) {
	client := NewClientNTLMEncrypted()
	c.Assert(client.useEncryption, Equals, true)
}

func (s *WinRMSuite) TestNewClientNTLMEncryptedWithDial(c *C) {
	dial := func(network, addr string) (net.Conn, error) {
		return nil, nil
	}
	client := NewClientNTLMEncryptedWithDial(dial)
	c.Assert(client.useEncryption, Equals, true)
	c.Assert(client.dial, NotNil)
}

func (s *WinRMSuite) TestNewClientNTLMEncryptedWithProxyFunc(c *C) {
	proxy := http.ProxyFromEnvironment
	client := NewClientNTLMEncryptedWithProxyFunc(proxy)
	c.Assert(client.useEncryption, Equals, true)
	c.Assert(client.proxyfunc, NotNil)
}

func (s *WinRMSuite) TestNTLMEncryptedViaEncryptionWrapper(c *C) {
	// Verify that NewEncryption("ntlm") creates a transport with encryption enabled
	enc, err := NewEncryption("ntlm")
	c.Assert(err, IsNil)

	endpoint := NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)
	err = enc.Transport(endpoint)
	c.Assert(err, IsNil)
}
