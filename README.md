# WinRM for Go

_Note_: if you're looking for the `winrm` command-line tool, this has been splitted from this project and is available at [winrm-cli](https://github.com/masterzen/winrm-cli)

This is a Go library to execute remote commands on Windows machines through
the use of WinRM/WinRS.

This library supports:
- **Basic authentication** for local accounts
- **NTLM authentication** (NTLMv2) for local and domain accounts (`DOMAIN\user` or `user@domain`)
- **NTLM with message encryption** (sealing) — works with the default Windows `AllowUnencrypted=false` setting
- **Kerberos authentication** for domain accounts
- **Certificate-based authentication** (x509 mutual TLS)

## Contact

- Bugs: https://github.com/masterzen/winrm/issues


## Getting Started
WinRM is available on Windows Server 2008 and up. This project supports multiple authentication methods — see the sections below for how to prepare the remote Windows machine for each scenario. The authentication model is pluggable via the `TransportDecorator` parameter.

_Note_: This library requires Go 1.21+

### Preparing the remote Windows machine for Basic authentication
The remote windows system must be prepared for winrm:

_For a PowerShell script to do what is described below in one go, check [Richard Downer's blog](http://www.frontiertown.co.uk/2011/12/overthere-control-windows-from-java/)_

On the remote host, a PowerShell prompt, using the __Run as Administrator__ option and paste in the following lines:

		winrm quickconfig
		y
		winrm set winrm/config/service/Auth '@{Basic="true"}'
		winrm set winrm/config/service '@{AllowUnencrypted="true"}'
		winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}'

__N.B.:__ The Windows Firewall needs to be running to run this command. See [Microsoft Knowledge Base article #2004640](http://support.microsoft.com/kb/2004640).

__N.B.:__ Do not disable Negotiate authentication as the `winrm` command itself uses this for internal authentication, and you risk getting a system where `winrm` doesn't work anymore.

__N.B.:__ The `MaxMemoryPerShellMB` option has no effects on some Windows 2008R2 systems because of a WinRM bug. Make sure to install the hotfix described [Microsoft Knowledge Base article #2842230](http://support.microsoft.com/kb/2842230) if you need to run commands that use more than 150MB of memory.

For more information on WinRM, please refer to <a href="http://msdn.microsoft.com/en-us/library/windows/desktop/aa384426(v=vs.85).aspx">the online documentation at Microsoft's DevCenter</a>.

### Preparing the remote Windows machine for NTLM authentication

NTLM authentication works with the default Windows WinRM configuration. No special server-side setup is required beyond enabling WinRM:

		winrm quickconfig
		y
		winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}'

When using NTLM with encryption (the default and recommended mode), you do **not** need to set `AllowUnencrypted="true"` — the SOAP messages are encrypted using the NTLM security session.

### Preparing the remote Windows machine for Kerberos authentication
On the remote host, a PowerShell prompt, using the __Run as Administrator__ option and paste in the following lines:

                winrm quickconfig
                y
                winrm set winrm/config/service '@{AllowUnencrypted="true"}'
                winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}'

All __N.B__ points of "Preparing the remote Windows machine for Basic authentication" also applies.


### Building the winrm go and executable

You can build winrm from source:

```sh
git clone https://github.com/masterzen/winrm
cd winrm
make
```

_Note_: this winrm code doesn't depend anymore on [Gokogiri](https://github.com/moovweb/gokogiri) which means it is now in pure Go.

## Command-line usage

For command-line usage check the [winrm-cli project](https://github.com/masterzen/winrm-cli)

## Library Usage

**Warning the API might be subject to change.**

### Basic authentication

For the fast version (this doesn't allow to send input to the command) and it's using HTTP as the transport:

```go
package main

import (
	"context"
	"os"

	"github.com/masterzen/winrm"
)

func main() {
	endpoint := winrm.NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)
	client, err := winrm.NewClient(endpoint, "Administrator", "secret")
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.RunWithContext(ctx, "ipconfig /all", os.Stdout, os.Stderr)
}
```

or with stdin:
```go
package main

import (
	"context"
	"os"

	"github.com/masterzen/winrm"
)

func main() {
	endpoint := winrm.NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)
	client, err := winrm.NewClient(endpoint, "Administrator", "secret")
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = client.RunWithContextWithInput(ctx, "ipconfig", os.Stdout, os.Stderr, os.Stdin)
	if err != nil {
		panic(err)
	}
}
```

### NTLM authentication (without encryption)

Use `ClientNTLM` via the `TransportDecorator`. This requires `AllowUnencrypted="true"` on the server:

```go
endpoint := winrm.NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)

params := winrm.DefaultParameters
params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }

client, err := winrm.NewClientWithParameters(endpoint, "Administrator", "secret", params)
if err != nil {
	panic(err)
}
client.RunWithContext(ctx, "ipconfig /all", os.Stdout, os.Stderr)
```

### NTLM authentication with encryption (recommended)

Use `NewClientNTLMEncrypted()` for NTLM with message-level encryption. This works with the **default Windows configuration** (`AllowUnencrypted=false`) and is the recommended approach:

```go
endpoint := winrm.NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)

params := winrm.DefaultParameters
params.TransportDecorator = func() winrm.Transporter { return winrm.NewClientNTLMEncrypted() }

client, err := winrm.NewClientWithParameters(endpoint, "Administrator", "secret", params)
if err != nil {
	panic(err)
}
client.RunWithContext(ctx, "ipconfig /all", os.Stdout, os.Stderr)
```

Domain users are supported via `DOMAIN\user` or `user@domain` formats:

```go
client, err := winrm.NewClientWithParameters(endpoint, `MYDOMAIN\admin`, "secret", params)
// or
client, err := winrm.NewClientWithParameters(endpoint, "admin@mydomain.com", "secret", params)
```

The `NewEncryption("ntlm")` API is also available for backwards compatibility:

```go
params.TransportDecorator = func() winrm.Transporter {
	enc, _ := winrm.NewEncryption("ntlm")
	return enc
}
```

### Kerberos authentication

```go
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/masterzen/winrm"
)

func main() {
	endpoint := winrm.NewEndpoint("srv-win", 5985, false, false, nil, nil, nil, 0)

	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter {
		return &winrm.ClientKerberos{
			Username: "test",
			Password: "s3cr3t",
			Hostname: "srv-win",
			Realm:    "DOMAIN.LAN",
			Port:     5985,
			Proto:    "http",
			KrbConf:  "/etc/krb5.conf",
			SPN:      fmt.Sprintf("HTTP/%s", "srv-win"),
		}
	}

	client, err := winrm.NewClientWithParameters(endpoint, "test", "s3cr3t", params)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = client.RunWithContextWithInput(ctx, "ipconfig", os.Stdout, os.Stderr, os.Stdin)
	if err != nil {
		panic(err)
	}
}
```

### Custom dialer (e.g. tunnel through SSH)

```go
package main

import (
	"context"
	"os"

	"github.com/masterzen/winrm"
	"golang.org/x/crypto/ssh"
)

func main() {
	sshClient, err := ssh.Dial("tcp", "localhost:22", &ssh.ClientConfig{
		User:            "ubuntu",
		Auth:            []ssh.AuthMethod{ssh.Password("ubuntu")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		panic(err)
	}

	endpoint := winrm.NewEndpoint("other-host", 5985, false, false, nil, nil, nil, 0)

	params := winrm.DefaultParameters
	params.Dial = sshClient.Dial

	client, err := winrm.NewClientWithParameters(endpoint, "test", "test", params)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = client.RunWithContextWithInput(ctx, "ipconfig", os.Stdout, os.Stderr, os.Stdin)
	if err != nil {
		panic(err)
	}
}
```


### Shell API (advanced)

For a more complex example, it is possible to call the various functions directly:

```go
package main

import (
	"bytes"
	"io"
	"os"

	"github.com/masterzen/winrm"
)

func main() {
	stdin := bytes.NewBufferString("ipconfig /all")
	endpoint := winrm.NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)
	client, err := winrm.NewClient(endpoint, "Administrator", "secret")
	if err != nil {
		panic(err)
	}
	shell, err := client.CreateShell()
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cmd *winrm.Command
	cmd, err = shell.ExecuteWithContext(ctx, "cmd.exe")
	if err != nil {
		panic(err)
	}

	go io.Copy(cmd.Stdin, stdin)
	go io.Copy(os.Stdout, cmd.Stdout)
	go io.Copy(os.Stderr, cmd.Stderr)

	cmd.Wait()
	shell.Close()
}
```

### HTTPS with certificate authentication

```go
package main

import (
	"context"
	"log"
	"os"

	"github.com/masterzen/winrm"
)

func main() {
	clientCert, err := os.ReadFile("/home/example/winrm_client_cert.pem")
	if err != nil {
		log.Fatalf("failed to read client certificate: %q", err)
	}

	clientKey, err := os.ReadFile("/home/example/winrm_client_key.pem")
	if err != nil {
		log.Fatalf("failed to read client key: %q", err)
	}

	winrm.DefaultParameters.TransportDecorator = func() winrm.Transporter {
		// winrm https module
		return &winrm.ClientAuthRequest{}
	}

	endpoint := winrm.NewEndpoint(
		"192.168.100.2", // host to connect to
		5986,            // winrm port
		true,            // use TLS
		true,            // Allow insecure connection
		nil,             // CA certificate
		clientCert,      // Client Certificate
		clientKey,       // Client Key
		0,               // Timeout
	)
	client, err := winrm.NewClient(endpoint, "Administrator", "")
	if err != nil {
		log.Fatalf("failed to create client: %q", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = client.RunWithContext(ctx, "whoami", os.Stdout, os.Stderr)
	if err != nil {
		log.Fatalf("failed to run command: %q", err)
	}
}
```

Note: canceling the `context.Context` passed as first argument to the various
functions of the API will not cancel the HTTP requests themselves, it will
rather cause a running command to be aborted on the remote machine via a call to
`command.Stop()`.

## Developing on WinRM

If you wish to work on `winrm` itself, you'll first need [Go](http://golang.org)
installed (version 1.21+ is _required_). Make sure you have Go properly installed,
including setting up your [GOPATH](http://golang.org/doc/code.html#GOPATH).

Next, clone this repository and then just type `make`.

You can run tests by typing `make test`.

If you make any changes to the code, run `make format` in order to automatically
format the code according to Go standards.

When new dependencies are added to winrm you can use `make updatedeps` to
get the latest and subsequently use `make` to compile.
