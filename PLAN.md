# WinRM NTLM Auth Fix — Implementation Plan

## Status: COMPLETED

All sprints have been implemented. Azure/go-ntlmssp has been fully replaced with bodgit/ntlmssp.

## What Changed

### Before
| Transport | File | Library | Encryption | Works with default Windows? |
|-----------|------|---------|------------|-----------------------------|
| `ClientNTLM` | `ntlm.go` | Azure/go-ntlmssp | No | No (`AllowUnencrypted=false` by default) |
| `Encryption` | `encryption.go` | bodgit/ntlmssp | Yes (sealing) | Yes |

### After
| Transport | File | Library | Encryption | Works with default Windows? |
|-----------|------|---------|------------|-----------------------------|
| `ClientNTLM` | `ntlm.go` | bodgit/ntlmssp | Optional | Yes (with encryption) |
| `Encryption` | `encryption.go` | delegates to ClientNTLM | Yes (sealing) | Yes |

## Completed Sprints

### Sprint 1: Core NTLM Transport Replacement
- [x] Rewrote `ntlm.go` — replaced Azure `Negotiator` with bodgit `http.Client`
- [x] Extracted `parseUsernameAndDomain()` shared helper
- [x] Removed `github.com/Azure/go-ntlmssp` from `go.mod`
- [x] All tests pass, build clean

### Sprint 2: Unified Encrypted NTLM
- [x] Added `useEncryption` flag to `ClientNTLM`
- [x] Simplified `encryption.go` from ~440 lines to ~53 lines (delegates to `ClientNTLM`)
- [x] Added convenience constructors: `NewClientNTLMEncrypted()`, `NewClientNTLMEncryptedWithDial()`, `NewClientNTLMEncryptedWithProxyFunc()`

### Sprint 3: Session Caching
- [x] Cached bodgit NTLM clients across `Post()` calls (avoids re-handshaking)
- [x] Session invalidation on credential change
- [x] Session reset on encrypted request failure (auto-recovery)
- [x] Thread-safe with `sync.Mutex`

### Sprint 4: Tests & Cleanup
- [x] Added tests for `parseUsernameAndDomain` (backslash, @-sign, plain)
- [x] Added tests for `NewEncryption` (ntlm, unsupported protocol)
- [x] Added tests for all new constructors
- [x] Added test for `Encryption` wrapper Transport
- [x] `go vet` passes clean
- [x] Zero Azure references in codebase

## Usage Examples

### NTLM without encryption (requires AllowUnencrypted=true on server)
```go
params.TransportDecorator = func() Transporter { return &ClientNTLM{} }
```

### NTLM with encryption (works with default Windows config)
```go
params.TransportDecorator = func() Transporter { return NewClientNTLMEncrypted() }
// or equivalently:
params.TransportDecorator = func() Transporter { enc, _ := NewEncryption("ntlm"); return enc }
```

### NTLM with encryption + custom dialer
```go
params.TransportDecorator = func() Transporter { return NewClientNTLMEncryptedWithDial(myDialer) }
```

### Domain user formats
All three formats are supported:
- `DOMAIN\user`
- `user@domain.com`
- `user` (no domain)
