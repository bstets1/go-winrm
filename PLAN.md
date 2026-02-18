# WinRM NTLM Auth Fix — Implementation Plan

## Current State Analysis

The codebase has **two NTLM auth paths**:

| Transport | File | Library | Encryption | Works with default Windows? |
|-----------|------|---------|------------|-----------------------------|
| `ClientNTLM` | `ntlm.go` | Azure/go-ntlmssp | No | No (`AllowUnencrypted=false` by default) |
| `Encryption` | `encryption.go` | bodgit/ntlmssp | Yes (sealing) | Yes |

**The problem:** Azure/go-ntlmssp does NOT support NTLM sealing (message encryption). Windows servers default to `AllowUnencrypted = false`, so `ClientNTLM` fails in practice. The `Encryption` struct already uses bodgit/ntlmssp (which supports sealing), but it creates fresh NTLM sessions per request (expensive) and has some error handling gaps.

**The fix:** Replace Azure/go-ntlmssp with bodgit/ntlmssp everywhere, remove the Azure dependency, and improve the overall NTLM transport.

---

## Key Discovery: bodgit/ntlmssp/http Already Does Everything

The `bodgit/ntlmssp/http` package provides:
- `http.Client` — wraps `*http.Client` with NTLM auth handshake handling
- `Encryption(true)` option — enables automatic SOAP body sealing/unsealing
- `Wrap()`/`Unwrap()` — MIME multipart encryption envelope handling
- `SendCBT(true)` — Channel Binding Token support for HTTPS

This means both `ClientNTLM` (auth only) and `Encryption` (auth + sealing) can be built on top of bodgit's http.Client with different options.

---

## Sprint 1: Core NTLM Transport Replacement (Sequential — Foundation)

**Goal:** Replace Azure/go-ntlmssp with bodgit/ntlmssp in `ClientNTLM`. After this sprint, unencrypted NTLM auth uses bodgit.

### Task 1.1: Rewrite `ntlm.go`

**Current code (Azure):**
```go
import "github.com/Azure/go-ntlmssp"

func (c *ClientNTLM) Transport(endpoint *Endpoint) error {
    c.clientRequest.Transport(endpoint)
    c.clientRequest.transport = &ntlmssp.Negotiator{RoundTripper: c.clientRequest.transport}
    return nil
}

func (c ClientNTLM) Post(client *Client, request *soap.SoapMessage) (string, error) {
    return c.clientRequest.Post(client, request)
}
```

**New code (bodgit):**
```go
import (
    "github.com/bodgit/ntlmssp"
    ntlmhttp "github.com/bodgit/ntlmssp/http"
)

type ClientNTLM struct {
    clientRequest
    useEncryption bool
}

func (c *ClientNTLM) Transport(endpoint *Endpoint) error {
    return c.clientRequest.Transport(endpoint)
}

func (c *ClientNTLM) Post(client *Client, request *soap.SoapMessage) (string, error) {
    // 1. Parse username/domain from client.username
    // 2. Create bodgit ntlmssp.Client with SetUserInfo, SetDomain
    // 3. Create *http.Client with base transport
    // 4. Create bodgit http.Client wrapping it
    // 5. Build and send POST request
    // 6. Return response body
}
```

**Key changes:**
- Remove Azure Negotiator — bodgit doesn't implement `http.RoundTripper`
- Move the HTTP request logic INTO `ClientNTLM.Post()` instead of delegating to `clientRequest.Post()`
- Parse `DOMAIN\user` and `user@domain` formats (reuse logic from `encryption.go:83-94`)
- Create bodgit client per Post() call initially (matches current encryption.go behavior)

### Task 1.2: Add username parsing helper

Extract the username/domain parsing from `encryption.go:83-94` into a shared helper:
```go
func parseUsernameAndDomain(username string) (user, domain string) {
    if strings.Contains(username, "@") {
        parts := strings.Split(username, "@")
        return parts[0], parts[1]
    } else if strings.Contains(username, "\\") {
        parts := strings.Split(username, "\\")
        return parts[1], parts[0]
    }
    return username, ""
}
```

### Task 1.3: Remove Azure/go-ntlmssp dependency

- Remove `github.com/Azure/go-ntlmssp` from `go.mod`
- Run `go mod tidy`
- Verify no remaining Azure imports

### Task 1.4: Update tests

- Update `ntlm_test.go` — tests use a local HTTP test server, should work with bodgit
- Verify `go test ./...` passes

### Task 1.5: Verify build

- `go build ./...`
- `go vet ./...`

---

## Sprint 2: Refactor Encryption & Add Encrypted NTLM to ClientNTLM (Can Parallelize)

**Goal:** Unify the NTLM code paths. Make `ClientNTLM` support optional encryption. Simplify `Encryption` to delegate to `ClientNTLM`.

### Task 2.1: Add encryption support to ClientNTLM

Add a `useEncryption` field to `ClientNTLM`:
```go
type ClientNTLM struct {
    clientRequest
    useEncryption bool
}
```

When `useEncryption` is true, create the bodgit http.Client with `Encryption(true)`:
- bodgit handles MIME wrapping/unwrapping automatically
- No manual `encryptMessage`/`decryptMessage` needed

**Two-step approach for encrypted NTLM:**
1. First request: empty POST to establish NTLM session (handshake)
2. Second request: POST with SOAP body (bodgit wraps/unwraps automatically)

This matches the current `encryption.go` PrepareRequest + PrepareEncryptedRequest pattern but using bodgit's built-in encryption.

### Task 2.2: Simplify `encryption.go`

Refactor `Encryption` struct to delegate to `ClientNTLM`:
```go
type Encryption struct {
    ntlm *ClientNTLM  // ClientNTLM with useEncryption=true
    protocol string
}

func NewEncryption(protocol string) (*Encryption, error) {
    if protocol != "ntlm" {
        return nil, fmt.Errorf(...)
    }
    return &Encryption{
        ntlm: &ClientNTLM{useEncryption: true},
        protocol: protocol,
    }, nil
}

func (e *Encryption) Post(client *Client, request *soap.SoapMessage) (string, error) {
    return e.ntlm.Post(client, request)
}
```

This removes ~300 lines of manual MIME wrapping code (`encryptMessage`, `decryptMessage`, `buildNTLMMessage`, `decryptNtlmMessage`, `ParseEncryptedResponse`, `PrepareEncryptedRequest`).

### Task 2.3: Add convenience constructors

```go
// NewClientNTLMEncrypted creates an NTLM transport with message encryption (sealing).
// This works with the default Windows AllowUnencrypted=false setting.
func NewClientNTLMEncrypted() *ClientNTLM {
    return &ClientNTLM{useEncryption: true}
}

func NewClientNTLMEncryptedWithDial(dial func(network, addr string) (net.Conn, error)) *ClientNTLM {
    return &ClientNTLM{
        clientRequest: clientRequest{dial: dial},
        useEncryption: true,
    }
}
```

---

## Sprint 3: Session Management & Performance (Sequential — After Sprint 2)

**Goal:** Reuse NTLM sessions across Post() calls to avoid re-handshaking.

### Task 3.1: Cache bodgit clients in ClientNTLM

Instead of creating fresh bodgit clients per Post() call, cache them:
```go
type ClientNTLM struct {
    clientRequest
    useEncryption bool

    // Cached session state
    mu         sync.Mutex
    ntlmClient *ntlmssp.Client
    ntlmHTTP   *ntlmhttp.Client
    lastUser   string  // Invalidate cache if user changes
}
```

- Lazy initialization on first Post() call
- Invalidate if username/password changes
- Thread-safe with mutex

### Task 3.2: Handle session expiry

If the server returns 401 after a previously successful session:
- Detect this condition
- Create fresh bodgit clients
- Retry the request

### Task 3.3: Connection keep-alive tuning

Ensure the base HTTP transport is configured for keep-alive:
- Verify `DisableKeepAlives` is false (bodgit requires this)
- Set appropriate idle connection timeout
- Consider connection pooling settings

---

## Sprint 4: Testing & Polish (Can Parallelize)

### Task 4.1: Unit tests for new NTLM transport (Agent: test-writer)

- Test `ClientNTLM.Post()` with mock server that does NTLM handshake
- Test `parseUsernameAndDomain()` with various formats:
  - `user` → user, ""
  - `DOMAIN\user` → user, DOMAIN
  - `user@domain.com` → user, domain.com
- Test `ClientNTLM` with encryption enabled
- Test session reuse (multiple Post() calls)
- Test error handling (connection refused, 401, 500)

### Task 4.2: Unit tests for simplified Encryption (Agent: test-writer)

- Test `Encryption.Post()` delegates correctly
- Test backwards compatibility (same `NewEncryption("ntlm")` API)
- Test protocol validation (only "ntlm" supported)

### Task 4.3: Integration test helpers (Agent: test-writer)

Update `development/winrm-tests.sh` or add Go integration tests:
- Test against real Windows VM (if available via Vagrant)
- Test with AllowUnencrypted=false (default)
- Test with AllowUnencrypted=true
- Test DOMAIN\user and user@domain formats

### Task 4.4: Code cleanup

- Run `golangci-lint` (per `.golangci.yml`)
- Fix any linting issues
- Ensure consistent error handling patterns
- Remove any dead code

---

## Agent Parallelization Strategy

```
Sprint 1 (Sequential - Must complete first)
├── Agent A: Rewrite ntlm.go + add username helper
│   Files: ntlm.go (new username parsing utility)
│
└── After Agent A completes:
    └── Agent B: Remove Azure dep, run tests, verify build
        Files: go.mod, go.sum

Sprint 2 (After Sprint 1, tasks can parallelize)
├── Agent C: Add encryption to ClientNTLM + simplify encryption.go
│   Files: ntlm.go, encryption.go
│
└── Agent D: Add convenience constructors + update factory functions
    Files: ntlm.go, parameters.go (if needed)

Sprint 3 (After Sprint 2)
└── Agent E: Session caching + keep-alive tuning
    Files: ntlm.go

Sprint 4 (After Sprint 2, can parallelize with Sprint 3)
├── Agent F: Write unit tests
│   Files: ntlm_test.go, encryption_test.go
│
└── Agent G: Lint + cleanup
    Files: all
```

---

## File Change Summary

| File | Change | Sprint |
|------|--------|--------|
| `ntlm.go` | **Major rewrite** — Replace Azure with bodgit, add encryption support | 1, 2 |
| `encryption.go` | **Simplify** — Delegate to ClientNTLM | 2 |
| `go.mod` | Remove Azure/go-ntlmssp, run tidy | 1 |
| `ntlm_test.go` | Update for new API | 1, 4 |
| `encryption_test.go` | New tests | 4 |

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| bodgit http.Client first-request body not encrypted | Server rejects unencrypted body | Use two-step approach: empty auth POST, then encrypted POST |
| Session expiry between requests | 401 errors mid-operation | Detect and re-establish session (Sprint 3) |
| bodgit API changes | Build breaks | Pin dependency version in go.mod |
| Backwards API compatibility | Users' code breaks | Keep same Transporter interface, same constructor signatures |
| NTLM handshake per request (performance) | Slow operations | Session caching (Sprint 3) |

---

## Success Criteria

1. `go build ./...` succeeds with zero Azure/go-ntlmssp references
2. `go test ./...` passes
3. `ClientNTLM` works for NTLM auth without encryption (AllowUnencrypted=true)
4. `ClientNTLM` with encryption works with default Windows config (AllowUnencrypted=false)
5. `Encryption` struct maintains backwards-compatible API
6. `DOMAIN\user` and `user@domain` formats work
7. No Azure/go-ntlmssp in go.mod
