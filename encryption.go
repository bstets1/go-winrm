package winrm

import (
	"fmt"

	"github.com/masterzen/winrm/soap"
)

// Encryption provides a transport that uses NTLM authentication with
// message-level encryption (sealing). This works with the default Windows
// AllowUnencrypted=false setting.
//
// It delegates to ClientNTLM with encryption enabled, which uses
// bodgit/ntlmssp for both the NTLM handshake and message sealing/unsealing.
//
// Currently only the "ntlm" protocol is supported. CredSSP and Kerberos
// encryption are not yet implemented.
type Encryption struct {
	ntlm     *ClientNTLM
	protocol string
}

// NewEncryption creates a new Encryption transport for the given protocol.
// Currently only "ntlm" is supported.
//
// Usage:
//
//	params.TransportDecorator = func() Transporter {
//	    enc, _ := NewEncryption("ntlm")
//	    return enc
//	}
func NewEncryption(protocol string) (*Encryption, error) {
	switch protocol {
	case "ntlm":
		return &Encryption{
			ntlm:     &ClientNTLM{useEncryption: true},
			protocol: protocol,
		}, nil
	}

	return nil, fmt.Errorf("encryption for protocol '%s' not supported", protocol)
}

// Transport sets up the underlying HTTP transport.
func (e *Encryption) Transport(endpoint *Endpoint) error {
	return e.ntlm.Transport(endpoint)
}

// Post sends a SOAP message with NTLM encryption.
func (e *Encryption) Post(client *Client, message *soap.SoapMessage) (string, error) {
	return e.ntlm.Post(client, message)
}
