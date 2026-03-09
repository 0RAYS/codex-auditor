# Memory, Process, Linux/ELF, and Misc Commands

## Use This File For

- generic Linux userland memory inspection
- ELF/process metadata helpers
- small but high-leverage utility commands not covered elsewhere

## Linux / ELF Helpers

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `argc` | Print argument vector count | `argc` |
| `argv` | Dump argv pointers/strings | `argv` |
| `aslr` | Show ASLR status | `aslr` |
| `auxv` | Dump auxiliary vector | `auxv` |
| `auxv-explore` | Explore auxv entries interactively | `auxv-explore` |
| `elfsections` | Show ELF sections | `elfsections` |
| `envp` | Dump environment pointers/strings | `envp` |
| `errno` | Decode errno | `errno` |
| `got` | Inspect GOT entries | `got` |
| `gotplt` | Inspect GOT/PLT relationship | `gotplt` |
| `libcinfo` | Summarize current libc | `libcinfo` |
| `linkmap` | Show dynamic linker link-map | `linkmap` |
| `onegadget` | Show one-gadget candidates | `onegadget` |
| `parse-seccomp` | Decode seccomp filter from memory | `parse-seccomp addr` |
| `piebase` | Print PIE base | `piebase` |
| `plt` | Show PLT entries | `plt` |
| `strings` | Dump strings from modules | `strings libc` |
| `threads` | Show thread list/details | `threads` |
| `tls` | Show thread-local storage data | `tls` |
| `track-got` | Track GOT entry changes | `track-got puts` |
| `track-heap` | Track heap allocations | `track-heap` |

## Memory Inspection and Search

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `distance` | Compute deltas or page offsets | `distance a b` |
| `dump-register-frame` | Dump saved register frame | `dump-register-frame` |
| `gdt` | Show GDT | `gdt` |
| `go-dump` | Decode Go runtime data | `go-dump` |
| `go-type` | Decode Go type info | `go-type addr` |
| `hexdump` | Hex/ASCII dump bytes | `hexdump addr 0x80` |
| `leakfind` | Find likely pointer leaks | `leakfind addr 0x100` |
| `memfrob` | Reverse glibc `memfrob`-style obfuscation | `memfrob addr count` |
| `mmap` | Display/assist memory map usage | `mmap` |
| `mprotect` | Inspect or trigger protection changes | `mprotect` |
| `p2p` | Pointer-to-pointer chain search | `p2p stack libc` |
| `probeleak` | Scan a range for valid pointers | `probeleak $rsp 0x80` |
| `search` | Search for strings/bytes/pointers/asm | `search /bin/sh libc` |
| `telescope` | Recursive pointer dereference | `telescope $rsp 16` |
| `vmmap` | Show process mappings | `vmmap libc` |
| `vmmap-add` | Add a synthetic map entry | `vmmap-add start size rwx 0` |
| `vmmap-clear` | Clear vmmap cache | `vmmap-clear` |
| `vmmap-explore` | Guess permissions for a page | `vmmap-explore addr` |
| `xinfo` | Show address-relative mapping info | `xinfo addr` |
| `xor` | XOR a memory region | `xor addr key count` |

## Misc Utilities

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `asm` | Assemble instructions | `asm 'pop rdi; ret'` |
| `checksec` | Show binary security properties | `checksec` |
| `comm` | Add comments in disassembly | `comm --addr $pc note` |
| `cyclic` | Create/search cyclic patterns | `cyclic 200`, `cyclic -l 0x6161616b` |
| `cymbol` | Add custom C structures | `cymbol add` |
| `down`, `up` | Move stack frames | `down`, `up` |
| `dt` | Dump type info at an address | `dt ucontext_t $rsp` |
| `dumpargs` | Infer call/syscall arguments | `dumpargs` |
| `getfile` | Show current file | `getfile` |
| `hex2ptr` | Convert leaked hex bytes to pointer | `hex2ptr '20 74 ed f7 ff 7f'` |
| `hijack-fd` | Replace a process FD backing file | `hijack-fd 1 /tmp/out` |
| `ipi` | Drop into IPython | `ipi` |
| `patch` | Patch code/bytes | `patch $pc 'nop; nop'` |
| `patch-list` | List patches | `patch-list` |
| `patch-revert` | Revert a patch | `patch-revert $pc` |
| `plist` | Walk linked structures | `plist head` |
| `sigreturn` | Decode a sigreturn frame | `sigreturn $rsp` |
| `spray` | Fill memory with cyclic/data | `spray addr len` |
| `tips` | Show pwndbg tips | `tips` |
| `valist` | Decode a `va_list` | `valist addr` |
| `vmmap-load` | Load map pages from an ELF file | `vmmap-load ./a.out` |

## Process Helpers

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `killthreads` | Kill selected or all threads | `killthreads -a` |
| `pid` | Print inferior PID | `pid` |
| `procinfo` | Show runtime process info | `procinfo` |

## Practical Notes

- Use `vmmap` plus `xinfo` together when mapping relationships matter.
- Use `search` first, then refine with `--save` and `-n` for iterative narrowing.
- Use `cyclic`, `checksec`, `procinfo`, and `vmmap` as cheap early-session context builders.
- Keep `patch`/`patch-revert` in mind for hypothesis testing, not just exploit development.
