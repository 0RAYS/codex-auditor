---
name: cpp-project-audit
description: Security code audit workflow for C++ projects (lifetime/RAII/UB issues, static analysis, sanitizers, fuzzing).
---

# C++ Project Security Code Audit Skill (Vulnerability Hunting & Bug Finding)

> **Agent instruction:** Before starting this C++ audit, read `../c-project-audit/SKILL.md` and reuse all applicable methodology (threat modeling, workflow, reporting template, grep strategy, sanitizer usage). This C++ skill is an extension: it **adds C++-specific vulnerability classes, review hotspots, and tooling**.

---

## 1) Objective & Scope
**Goal:** Identify security vulnerabilities, reliability bugs, undefined behavior, and design flaws in C++ codebases via manual review, static analysis, and dynamic testing.

**In scope (inherits all from C):**
- Memory safety, integer issues, parsing/input validation
- Concurrency bugs and security boundary violations
- Build configuration risks and unsafe compiler/linker settings

**Additional C++-specific scope:**
- Object lifetime, RAII, exceptions, move semantics
- Templates/generics, type confusion via casts
- Smart pointer misuse and ownership modeling
- ODR (One Definition Rule) / ABI / dynamic linking pitfalls
- Default behaviors (implicit conversions, default copy/move, implicit destructors) that introduce bugs

---

## 2) Tooling & Build Configuration (C++ Focus)

### Compiler Flags (Recommended Additions)
Use the C skill’s warning/hardening baseline, plus:
- `-Wnon-virtual-dtor`
- `-Woverloaded-virtual`
- `-Wold-style-cast`
- `-Wextra-semi`
- `-Wnull-dereference`
- `-Wdouble-promotion`
- `-Wimplicit-fallthrough`
- `-Wzero-as-null-pointer-constant` (mostly for modern C++ codebases)
- Consider: `-Werror` in CI for security-critical components

### Sanitizers & Runtime Checks
Same as C, plus C++-relevant notes:
- **ASan**: catches UAF/OOB that often arise from **incorrect ownership** and **iterator invalidation**.
- **UBSan**: valuable for **vptr issues**, invalid downcasts, misaligned pointers.
- **LSan**: leak detection (especially with exceptions and complex ownership graphs).

### Static Analysis (C++ Strong Picks)
- `clang-tidy` (high value for modern C++ misuse patterns)
- `clang-analyzer` / `scan-build`
- `cppcheck` (some C++ coverage)
- Optional: CodeQL (excellent for C++ codebases if available)

---

## 3) C++-Specific Threat Modeling Notes
Beyond entry points and untrusted inputs (from the C skill), explicitly map:
- **Plugin / shared library boundaries** (ABI mismatches, allocator mismatch, exception propagation across boundaries)
- **Serialization frameworks / reflection** (type confusion, deserialization gadgets)
- **Custom allocators** and **memory resource** usage (`pmr::memory_resource`)

---

## 4) Manual Code Review Checklist (C++ Hotspots)

### 4.1 Default/Implicit Behavior That Causes Vulnerabilities
These are frequent “looks correct” bugs:

#### A) Implicit Copy/Move and the Rule of 3/5/0
Risk:
- Classes managing resources (raw pointers, file handles, mutexes) may get **implicit copy** leading to **double free**, **use-after-free**, or **double close**.

Audit actions:
- Identify types that own resources and ensure:
  - Copy is deleted or properly implemented
  - Move is safe and leaves source in a valid state
- Look for suspicious patterns: raw pointer members, manual `new/delete`, custom destructors.

#### B) Implicit Conversions & Narrowing
Risk:
- Vulnerable logic from implicit numeric conversions, truncation, signedness, `bool` coercions.

Audit actions:
- Track conversions in comparisons and size calculations (`size_t`, `int`, `long`).
- Prefer explicit casts and bounds checks.

#### C) Exception Safety & Cleanup
Risk:
- Resource leaks or partially-mutated state on exceptions.

Audit actions:
- Identify functions that can throw and verify strong/basic exception safety guarantees.
- Avoid raw `new/delete`; prefer RAII wrappers.

---

### 4.2 Lifetime & Ownership Hotspots

#### A) Dangling References / Views
Risk sources:
- `std::string_view` outlives backing storage
- Returning references to local variables
- Iterators invalidated by container operations

Audit actions:
- Confirm view/reference lifetimes and ownership boundaries.
- Watch for `c_str()` pointer lifetimes across mutations.

#### B) Smart Pointer Misuse
Common risks:
- `shared_ptr` cycles (leaks) without `weak_ptr`
- `unique_ptr` moved-from use
- Mixing raw pointers with smart pointers leading to double frees

Audit actions:
- Trace ownership: who creates, who stores, who deletes?
- Validate custom deleters and allocator mismatches across shared library boundaries.

---

### 4.3 Type Confusion & Casting
Risks:
- `static_cast` where `dynamic_cast` is required
- `reinterpret_cast` and pointer punning leading to UB
- Downcasts across class hierarchies with untrusted type tags

Audit actions:
- Look for user-controlled type tags and casts.
- Use UBSan checks (e.g., vptr) when possible.

---

### 4.4 Concurrency & Atomics
Risks:
- Data races masked by undefined behavior
- Deadlocks in complex ownership graphs
- Incorrect memory order usage

Audit actions:
- Use TSan for runtime verification.
- Prefer well-scoped locking and documented invariants.

