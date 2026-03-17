---
name: go-nonserver-audit
description: Security code audit workflow for non-web Go projects (CLI/agent/tools), focusing on local inputs, filesystem, exec, deps, and fuzzing.
---

# Go (Non-Web/Server) Security Code Audit Skill (Vulnerability Hunting & Bug Finding)

## 1) Objective & Scope
**Goal:** Systematically find security vulnerabilities, reliability bugs, and misuse of Go runtime/library features in **non-web/server** Go programs (CLI tools, agents, desktop apps, libraries, batch jobs, file/network utilities).

**Primary attack surfaces (typical for non-server Go):**
- CLI arguments and flags
- Environment variables
- Config files (YAML/JSON/TOML/INI), `.env`
- Local file formats (archives, media, custom binary formats)
- IPC (pipes, Unix sockets), plugins, shared folders
- Outbound network clients (HTTP client, gRPC client) even if not hosting a server
- Update mechanisms (self-update, downloads, integrity checks)

**Key risk categories:**
- Command execution / injection
- Path traversal and filesystem race conditions
- Insecure deserialization / parsing bombs (zip bombs, decompression)
- Credential/secret leakage (logs, panic, error messages, core dumps)
- TLS/cert validation mistakes (client-side)
- Concurrency bugs leading to corruption/DoS
- Supply-chain risks (modules, `go:embed`, plugins)

---

## 2) Required Tooling & Environment

### Go Toolchain
- Go version pinned (prefer `go.mod` with explicit version)
- Build with reproducibility awareness (modules, `GONOSUMDB`, `GOPROXY` policy)

### Static Analysis
- `go vet` (baseline)
- `staticcheck` (high signal)
- `govulncheck` (known vulns in deps)
- Optional linters via `golangci-lint` (curated set only; avoid noise)

### Fuzzing & Testing
- Go native fuzzing (`go test -fuzz=...`) for parsers/decoders
- Property-based testing (e.g., `testing/quick`) where suitable

### Dependency & Binary Inspection
- `go list -m all`, `go mod graph`
- `go env -json`
- SBOM generation if required (e.g., Syft)

---

## 3) Threat Modeling Quick Pass (Non-Server Focus)
1. **Enumerate inputs**: argv, env, stdin, files, network responses, plugins.
2. **Map trust boundaries**:
   - Untrusted file content → parser → filesystem writes
   - Untrusted network response → parsing → command execution / file writes
3. **Assets**:
   - Local filesystem integrity
   - Credentials/tokens, API keys
   - Update channel integrity
4. **Security objectives**:
   - Prevent arbitrary code execution (command exec, plugin load)
   - Prevent data exfiltration (logs, temp files, permissions)
   - Avoid DoS by resource exhaustion (memory, CPU, disk)

Deliverable: a short diagram/list of inputs → sensitive sinks.

---

## 4) Manual Code Review Checklist (Go Hotspots)

### 4.1 Command Execution & Argument Injection
High-risk usage:
- `os/exec.Command("sh","-c", ...)`
- Building command strings by concatenation
- Passing untrusted args that change behavior (e.g., `--output=/etc/...`)

Audit actions:
- Prefer `exec.Command(name, arg1, arg2...)` with strict arg construction.
- Avoid shells unless necessary; if unavoidable, robust escaping and allowlist.
- Ensure environment passed to subprocess is controlled (`Cmd.Env`).

Search:
- `rg -n \"os/exec|exec\\.Command\\(\" -S .`

---

### 4.2 Filesystem: Path Traversal, Symlinks, TOCTOU
Risk patterns:
- Writing user-controlled paths without cleaning
- Following symlinks unexpectedly
- Temp file misuse

Audit actions:
- Canonicalize and validate paths.
- Use safe temp APIs (`os.CreateTemp`) and explicit permissions.
- Treat archives as untrusted; defend against zip slip.

Search:
- `rg -n \"filepath\\.|os\\.Open|os\\.Create|WriteFile|Mkdir|Remove|Chmod|Chown\" -S .`

---

### 4.3 Parsing Bombs & Resource Exhaustion
Risk patterns:
- Decompression without limits
- Unbounded reads into memory
- Regex worst-case behavior

Audit actions:
- Enforce size/time limits on reads and decompression.
- Prefer streaming decoders when possible.

Search:
- `rg -n \"gzip\\.NewReader|zlib\\.NewReader|tar\\.NewReader|zip\\.NewReader\" -S .`

---

### 4.4 Secrets & Logging
Risk patterns:
- Logging full requests/responses/tokens
- Panics revealing sensitive data
- Core dumps and temp artifacts

Audit actions:
- Scrub secrets in logs, avoid printing env vars.
- Consider disabling core dumps for sensitive tools (deployment-dependent).

Search:
- `rg -n \"(API_KEY|TOKEN|SECRET|PASSWORD)|log\\.|fmt\\.Print\" -S .`

