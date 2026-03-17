---
name: c-project-audit
description: Security code audit workflow for C projects (vulnerability hunting, sanitizers, fuzzing, and triage).
---

# C Project Security Code Audit Skill (Vulnerability Hunting & Bug Finding)

## 1) Objective & Scope
**Goal:** Systematically identify security vulnerabilities, reliability bugs, and undefined behavior in C codebases through manual review + automated tooling.

**In scope:**
- Memory safety (stack/heap overflows, UAF, double free, OOB)
- Integer issues (overflow/underflow, signedness, truncation)
- Input validation & parsing
- Concurrency (data races, deadlocks)
- Privilege/security boundaries (authz/authn, sandbox escapes)
- Cryptography misuse (if applicable)
- Build system & compiler flags that affect security

**Outputs:**
- Findings with severity, impact, PoC or reasoning, and remediation guidance
- Risk summary and prioritized fix plan

---

## 2) Required Environment & Tooling

### Compilers & Hardening Flags
- GCC/Clang (both if possible)
- Recommended baseline flags:
  - `-Wall -Wextra -Wpedantic -Wformat=2 -Wconversion -Wsign-conversion -Wshadow`
  - `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie`
  - `-fno-strict-aliasing` (case-by-case; depends on project)
  - `-O2 -g` (release-like but debuggable)

### Sanitizers (Dynamic Bug Discovery)
- AddressSanitizer (ASan): heap/stack OOB, UAF
- UndefinedBehaviorSanitizer (UBSan): overflows, invalid shifts, etc.
- MemorySanitizer (MSan): uninitialized reads (Clang)
- ThreadSanitizer (TSan): data races

Example CMake toggles (illustrative):
```bash
cmake -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" ..
make -j
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ./target < testcase
```

### Static Analysis
- `clang-tidy`
- `clang-analyzer` / `scan-build`
- `cppcheck`
- Semgrep (for patterns, if used in org)

### Fuzzing (Input-Driven Vulnerability Hunting)
- libFuzzer (Clang), AFL++, honggfuzz
- Corpus minimization + crash triage with ASan/UBSan

### Debugging & Triage
- `gdb` / `lldb`
- `valgrind` (slower, good for confirmation)
- `addr2line`, `eu-addr2line`, `readelf`, `objdump`

---

## 3) Threat Modeling Quick Pass (Before Deep Dive)
1. **Identify attack surfaces**
   - Network parsers, file parsers, IPC, CLI args, environment variables
   - Deserialization, plugin systems, scripting bindings
2. **Trust boundaries**
   - Untrusted input → parser/decoder → internal state
3. **Assets**
   - Memory safety, secrets, integrity of config/state, privilege boundaries
4. **Entry points**
   - `main()`, request handlers, protocol message handlers, callbacks

Deliverable: a short map of entry points + trust boundaries to guide audit focus.

---

## 4) Manual Code Review Checklist (High-Signal Areas)

### 4.1 Memory Safety Hotspots
Look for:
- **Unbounded copies/concats:** `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s")`
- **Length confusion:** wrong buffer size passed to `snprintf`, `memcpy`, `strncpy`
- **Off-by-one:** terminators, loop bounds
- **Use-after-free / double free:** ownership unclear, multiple cleanup paths
- **Stack lifetime bugs:** returning pointers to stack memory

Questions to ask:
- Who owns this pointer? Who frees it?
- Are allocations checked for failure?
- Are sizes computed with correct types?

### 4.2 Integer Vulnerabilities
Common patterns:
- `int` used for sizes/lengths instead of `size_t`
- Signed/unsigned mix in comparisons (`len < 0` on `size_t` is meaningless)
- Multiplication when allocating: `malloc(n * sizeof(T))` without overflow check
- Truncation: `size_t → int`, `uint64_t → uint32_t`

Audit actions:
- Trace all size computations from input to allocation/copy.
- Ensure bounds checks happen **before** arithmetic that can overflow.

### 4.3 Input Validation & Parsing
Focus on:
- Partial reads/writes and protocol framing
- NUL byte handling in binary protocols
- UTF-8 / encoding assumptions
- Path traversal (`../`), symlinks, TOCTOU on files
- Unsafe format strings (user-controlled format)

Check:
- Are parse errors handled consistently?
- Are rejected inputs truly rejected, or partially processed?

### 4.4 Error Handling & Cleanup Paths
Typical issues:
- Ignoring return values (I/O, `malloc`, `realloc`, crypto APIs)
- Inconsistent cleanup → leaks or double frees
- `goto fail` blocks missing resets/guards

Technique:
- Trace every error return path from sensitive functions.
- Verify cleanup order, nulling pointers, and idempotence of cleanup helpers.

---

## 5) Automated Recon & Audit Workflow (Practical Steps)

### 5.1 Identify Entry Points and Inputs
Use grep/ripgrep:
- `rg -n "int\\s+main\\s*\\(" -S .`
- `rg -n "(read|recv|fread|getenv|argv\\[|stdin)" -S .`
- `rg -n "(open\\(|fopen\\(|stat\\(|lstat\\(|realpath\\()" -S .`

Build a list of:
- Input sources (argv/env/files/network)
- Parsing functions (tokenizers, decoders, deserializers)
- Sinks (memcpy/strcpy, allocation, format strings, exec)

### 5.2 Build With Sanitizers
Prefer Clang for sanitizer builds when possible:
- ASan/UBSan: `-fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g`
- TSan for concurrency: `-fsanitize=thread -O1 -g`

Run representative inputs and regression tests (if any).

### 5.3 Static Analysis Pass
- `scan-build` for compile-time issue discovery
- `clang-tidy` focused checks for:
  - bounds, null deref, UB, insecure API use
  - mis-sized buffers and suspicious casts
- `cppcheck` for additional patterns

### 5.4 Fuzzing (If Applicable)
Pick the parser/decoder boundary and create a harness.
Suggested fuzzing setups:
- libFuzzer + ASan/UBSan for tight loops and easy triage
- AFL++ for blackbox-ish workflows and broader exploration

Crash triage:
- Minimize inputs (`afl-tmin`, `afl-cmin` where appropriate)
- Reproduce under ASan with `abort_on_error=1`
- Map to source via symbols + `addr2line`

---

## 6) Reporting Template (Findings)

For each finding:
- **ID**: `<PROJECT><NNN>` (e.g., `OPEN001`, `CURL002`, `IOXX001`)
- **Title**: short, precise
- **Severity**: Critical/High/Medium/Low
- **Impact**: what can be achieved
- **Root cause**: what logic/assumption failed
- **Trigger**: minimal input / conditions
- **Evidence**: code location + stack trace / sanitizer output
- **PoC**: minimal reproduction steps (preferred)
- **Fix guidance**: high-level remediation ideas

Example ID scheme:
- Project name: `openssl` → `OPEN001`, `OPEN002`, `OPEN003`
- Project name: `curl` → `CURL001`, `CURL002`
- Project name: `io` (short) → `IOXX001`, `IOXX002`

