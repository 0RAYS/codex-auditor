# Functions and Priority Commands

## How to Use This File

- Read this file first for leak analysis, rebasing, GOT/libc inspection, pointer chasing, or quick execution control.
- Prefer these commands over raw GDB equivalents because they usually collapse several manual steps into one view.
- Prefer `$base()` and `$rebase()` whenever the user gives offsets relative to a shared library or the main executable.

## First-Choice Rules

- Use `$base("libc") + off` instead of manually reading `vmmap` and adding the offset.
- Use `$rebase(off)` instead of manually resolving PIE base for the main executable.
- Use `errno` after a libc/API failure instead of manually reading `__errno_location`.
- Use `got` instead of manual GOT dumping when you need entry address, symbol name, backing object, and writability.
- Use `libcinfo` instead of manually combining `vmmap`, symbol lookups, and version guesses.
- Use `distance`, `xinfo`, and `probeleak` for leak triage before doing hand calculations.
- Use `telescope` for pointer-rich memory and `hexdump` for raw bytes/strings.
- Use `search` instead of ad hoc memory loops.
- Use `nextcall`, `nextjmp`, `nextret`, `nextsyscall`, and `xuntil` for quick control-flow travel.
- Use `breakrva` for PIE breakpoints.

## Convenience Functions

### Address Helpers

| Function | Best use | Preferred pattern | Notes |
| --- | --- | --- | --- |
| `$base(name)` | Find the base of a mapped shared object or region by name | `p/x $base("libc")`, `telescope '$base("ld")+0x1234'` | Match carefully; the first mapping with that substring wins. |
| `$rebase(off)` | Convert a file offset/RVA in the main PIE executable to a runtime address | `p/x $rebase(0x1234)`, `break *$rebase(0x1234)` | Use for the main executable, not arbitrary shared objects. |

### Other Useful Functions

| Function | Best use | Typical pattern |
| --- | --- | --- |
| `$argc()` | Inspect program argument count | `p $argc()` |
| `$argv(i)` | Read one argv entry | `p $argv(0)` |
| `$environ(name)` | Fetch one environment variable | `p $environ("PATH")` |
| `$envp(i)` | Read one environment string by index | `p $envp(0)` |
| `$fsbase()` | Inspect thread-local base on x86/x86-64 | `p/x $fsbase()` |
| `$gsbase()` | Inspect GS base on x86/x86-64 | `p/x $gsbase()` |
| `$hex2ptr(hex)` | Convert leaked hex bytes into a pointer | `p/x $hex2ptr("20 74 ed f7 ff 7f")` |

## Priority Commands

### `errno`

- Purpose: Decode the current `errno`, or a supplied errno value, into a readable failure reason.
- Prefer when: a libc/syscall wrapper failed and you want the real cause immediately.
- Syntax: `errno [err]`
- Patterns:
  - `errno`
  - `errno 2`
- Why it wins: avoids manual `p *__errno_location()` plus manual strerror mapping.

### `got`

- Purpose: Show GOT entry addresses, symbol names, source object paths, resolved targets, and whether an entry is writable.
- Prefer when: checking lazy binding state, overwrite targets, RELRO impact, or cross-library symbol resolution.
- Syntax: `got [-p PATH_FILTER | -a] [-r] [symbol_filter]`
- Patterns:
  - `got`
  - `got puts`
  - `got -p libc`
  - `got -ra`
- Why it wins: one command answers “where is it, what symbol is it, and can I write it?”.

### `libcinfo`

- Purpose: Summarize the currently loaded libc and useful derived information.
- Prefer when: triaging a libc leak, checking which libc is active, or quickly orienting an exploit/debug session.
- Syntax: `libcinfo`
- Pattern: `libcinfo`

### `parse-seccomp`

- Purpose: Parse a `struct sock_fprog` from memory and dump the seccomp filter.
- Prefer when: `seccomp-tools` style tracing is unavailable or live `seccomp` tracing is not working.
- Syntax: `parse-seccomp addr`
- Pattern: `parse-seccomp 0xdeadbeef`
- Typical workflow: recover/filter pointer from a syscall argument, then parse it directly.

### `distance`

- Purpose: Compute address deltas, or the page-base offset of one address.
- Prefer when: converting a leak into an offset or checking how far a pointer is from a base.
- Syntax: `distance a [b]`
- Patterns:
  - `distance '$base("libc")' '$hex2ptr("20 74 ed f7 ff 7f")'`
  - `distance 0x7ffff7ed7420`

### `p2p`

- Purpose: Search one mapping for pointers that point into another mapping, including chains.
- Prefer when: looking for stable pivot pointers, saved references, or usable in-segment pointer chains.
- Syntax: `p2p mapping_names [mapping_names ...]`
- Patterns:
  - `p2p stack libc`
  - `p2p heap`
- Heuristic: start with one mapping to inventory pointers, then add a target mapping to constrain the search.

### `telescope`

- Purpose: Recursively dereference pointers from an address and show the chain.
- Prefer when: exploring stack, heap, argv/env, vtables, jump tables, or leaked pointers.
- Syntax: `telescope [-r] [-f] [-i] [address] [count]`
- Patterns:
  - `telescope $rsp 16`
  - `telescope '$base("libc")+0x1337'`
  - `telescope -f`
- Why it wins: richer than repeated `x/gx` and manual dereferencing.

### `hexdump`

- Purpose: Show raw memory bytes with printable character context.
- Prefer when: you need exact byte content, embedded strings, or shellcode/data verification.
- Syntax: `hexdump [-C {py,c}] [address] [count]`
- Patterns:
  - `hexdump $rsp 0x80`
  - `hexdump '$base("libc")+0x2000' 0x40`
- Why it wins: faster than hand-selecting `x/xb`, `x/s`, and format switches.

### `search`

- Purpose: Search mapped memory for strings, bytes, integers, pointers, or assembly.
- Prefer when: hunting `/bin/sh`, gadgets by bytes, leaked pointers, vtables, or duplicated markers.
- Syntax: `search [options] value [mapping_name]`
- Patterns:
  - `search /bin/sh libc`
  - `search -p '$base("libc")' stack`
  - `search -x 41424344 heap`
  - `search --asm 'syscall' libc`
- High-value flags: `-p`, `-x`, `-e`, `-w`, `-l`, `-a`, `--save`, `-n`.

### `xinfo`

- Purpose: Show how one address relates to nearby mappings and useful bases.
- Prefer when: turning an address into a libc/module offset or checking closeness to segment boundaries.
- Syntax: `xinfo [address]`
- Patterns:
  - `xinfo $rip`
  - `xinfo 0x7ffff7ed7420`
- Why it wins: immediately answers “what mapping is this in, and what is the offset?”.

### `probeleak`

- Purpose: Scan a memory range for candidate pointers and annotate likely leaked offsets.
- Prefer when: triaging stack/heap leaks and you want likely module-relative pointers fast.
- Syntax: `probeleak [--max-distance N] [--point-to NAME] [--max-ptrs N] [--flags FLAGS] [address] [count]`
- Patterns:
  - `probeleak $rsp 0x80`
  - `probeleak $rsp 0x80 --point-to libc --max-ptrs 1`
  - `probeleak $rsp 0x80 --flags rwx`
- Why it wins: turns raw bytes into candidate leak intelligence without manual filtering.

### `valist`

- Purpose: Decode a `va_list` and dump its arguments.
- Prefer when: auditing variadic wrappers or inspecting `printf`-style call state.
- Syntax: `valist addr [count]`
- Patterns:
  - `valist $rdi`
  - `valist 0x7fffffffdc30 12`

### `procinfo`

- Purpose: Show process-level runtime information in one place.
- Prefer when: you want a quick summary of the inferior before deeper inspection.
- Syntax: `procinfo`
- Pattern: `procinfo`

### `xuntil`

- Purpose: Continue until an address or expression without keeping a permanent breakpoint.
- Prefer when: making a one-off temporary jump in execution.
- Syntax: `xuntil target`
- Patterns:
  - `xuntil *$rebase(0x1234)`
  - `xuntil main+0x90`

### `nextcall`

- Purpose: Run to the next call instruction, optionally constrained by callee name regex.
- Prefer when: skipping noisy instructions until the next interesting call site.
- Syntax: `nextcall [symbol_regex]`
- Patterns:
  - `nextcall`
  - `nextcall read|recv|malloc`

### `nextjmp`

- Purpose: Run to the next jump instruction.
- Prefer when: tracing branch-heavy dispatch or loop decisions.
- Syntax: `nextjmp`

### `nextret`

- Purpose: Run to the next return-like instruction.
- Prefer when: escaping helper functions or stopping at function exit quickly.
- Syntax: `nextret`

### `nextsyscall`

- Purpose: Run to the next syscall without taking branches.
- Prefer when: focusing on system-call boundaries rather than full control-flow detail.
- Syntax: `nextsyscall`

### `breakrva`

- Purpose: Set a breakpoint by RVA relative to the PIE base.
- Prefer when: the user gives a static file offset for a PIE binary.
- Syntax: `breakrva [offset] [module]`
- Patterns:
  - `breakrva 0x1234`
  - `breakrva 0x5678 libc`
- Why it wins: cleaner than computing `piebase + offset` by hand.

## Fast Choice Matrix

| Need | First choice | Backup |
| --- | --- | --- |
| Decode libc/API failure | `errno` | manual `__errno_location` work |
| Translate shared-object offset | `$base()` | `vmmap` + manual addition |
| Translate PIE offset | `$rebase()` or `breakrva` | `piebase` + manual math |
| Inspect GOT writability and targets | `got` | manual memory dump |
| Turn a leak into an offset | `xinfo`, `distance`, `probeleak` | `vmmap` + manual subtraction |
| Follow pointer chains | `telescope`, `p2p` | repeated `x/gx` |
| Search data/pointers/bytes | `search` | custom loops |
| Quick run-to-control-flow landmark | `next*`, `xuntil` | temporary breakpoints |
