---
name: pwndbg-skill
description: Teach Codex/LLMs to use Pwndbg efficiently by preferring high-signal Pwndbg commands over raw GDB commands, navigating command families quickly, and using convenience functions like $base() and $rebase() for rebased addresses.
---

# Pwndbg Skill

## Priority Index

- `references/functions-and-priority.md`
  - Functions: `argc`, `argv`, `base`, `environ`, `envp`, `fsbase`, `gsbase`, `hex2ptr`, `rebase`
  - `base`: use when the user gives an offset relative to a shared object such as `libc`, `ld`, or another mapped library.
  - `rebase`: use when the user gives an offset/RVA relative to the main executable, especially for PIE binaries.
  - `errno`: use right after a failed libc/API call to decode the failure reason quickly.
  - `got`: use when checking GOT entry addresses, resolved symbols, backing object paths, and whether entries are writable.
  - `libcinfo`: use when the task needs a quick summary of the currently loaded libc and related exploit context.
  - `parse-seccomp`: use when a seccomp filter address is available and live seccomp tracing is unavailable or unhelpful.
  - `distance`: use when turning a leak into an offset or computing how far two addresses are apart.
  - `p2p`: use when searching a mapping for useful pointers or pointer chains into another mapping.
  - `telescope`: use when inspecting pointer-rich memory such as stack, heap, argv/envp, or leaked addresses.
  - `hexdump`: use when exact bytes or printable characters matter more than pointer dereferencing.
  - `search`: use when hunting for strings, byte sequences, pointers, or instruction bytes across mappings.
  - `xinfo`: use when the task needs the offset of an address inside a nearby mapping or relative to a library base.
  - `probeleak`: use when triaging a leaked memory blob and looking for likely pointers plus mapping-relative offsets.
  - `valist`: use when auditing or debugging variadic functions and a `va_list` pointer is available.
  - `procinfo`: use when a compact process-level runtime summary is needed.
  - `xuntil`: use for a one-shot temporary run-until-address/action without leaving a permanent breakpoint behind.
  - `nextcall`: use to skip ahead to the next interesting call site, optionally filtered by callee name.
  - `nextjmp`: use to jump quickly to the next branch instruction in branch-heavy code.
  - `nextret`: use to move quickly to a function return boundary.
  - `nextsyscall`: use to move quickly to the next syscall boundary.
  - `breakrva`: use when the user gives a static offset for a PIE binary and wants a breakpoint there.

## Category Index

- `references/context-breakpoint-register-stack.md`
  - Use when the task is about context panes, branch-aware breakpoints, register/flag inspection, stack layout, stack canaries, or saved return addresses.
  - `break-if-not-taken`, `break-if-taken`, `breakrva`, `ignore`
  - `context`, `contextnext`, `contextoutput`, `contextprev`, `contextsearch`, `contextunwatch`, `contextwatch`, `regs`
  - `cpsr`, `fsbase`, `gsbase`, `setflag`
  - `canary`, `retaddr`, `stack`, `stack-explore`, `stackf`

- `references/glibc-heap.md`
  - Use when the target uses glibc `ptmalloc` and the task involves arenas, bins, tcache, chunk ownership, fake-fastbin ideas, or free behavior.
  - `arena`, `arenas`, `bins`, `fastbins`, `find-fake-fast`, `heap`, `hi`, `largebins`, `malloc-chunk`, `mp`, `smallbins`, `tcache`, `tcachebins`, `top-chunk`, `try-free`, `unsortedbin`, `vis-heap-chunks`

- `references/jemalloc-heap.md`
  - Use when the target uses `jemalloc` and the task involves extents, extent metadata, or mapping an allocation pointer back to its owning extent.
  - `jemalloc heap`, `jemalloc extent-info`, `jemalloc find-extent`

- `references/musl-heap.md`
  - Use when the target uses musl `mallocng` and the task involves slots, groups, meta areas, or allocator-global context.
  - `mallocng explain`, `mallocng dump`, `mallocng vis`, `mallocng find`, `mallocng ctx`, `mallocng metaarea`, `mallocng group`, `mallocng meta`, `mallocng slots`, `mallocng slotu`

- `references/kernel.md`
  - Use when debugging a Linux kernel target or kernel memory state: base/symbol lookup, syscalls, tasks, modules, paging, slab, BPF, nftables, or kernel hardening/config.
  - `binder`, `buddydump`, `kbase`, `kbpf`, `kchecksec`, `kcmdline`, `kconfig`, `kcurrent`, `kdmabuf`, `kdmesg`, `kfile`, `klookup`, `kmem-trace`, `kmod`, `knft`, `ksyscalls`, `ktask`, `kversion`, `msr`, `p2v`, `pageinfo`, `pagewalk`, `slab`, `v2p`

- `references/memory-misc.md`
  - Use when the task is general Linux userland memory/process/ELF inspection: mappings, dumps, pointer searches, ELF metadata, patching, cyclic patterns, type dumps, or process helpers not specific to heap families.
  - `argc`, `argv`, `aslr`, `auxv`, `auxv-explore`, `elfsections`, `envp`, `errno`, `got`, `gotplt`, `libcinfo`, `linkmap`, `onegadget`, `parse-seccomp`, `piebase`, `plt`, `strings`, `threads`, `tls`, `track-got`, `track-heap`
  - `distance`, `dump-register-frame`, `gdt`, `go-dump`, `go-type`, `hexdump`, `leakfind`, `memfrob`, `mmap`, `mprotect`, `p2p`, `probeleak`, `search`, `telescope`, `vmmap`, `vmmap-add`, `vmmap-clear`, `vmmap-explore`, `xinfo`, `xor`
  - `asm`, `checksec`, `comm`, `cyclic`, `cymbol`, `down`, `dt`, `dumpargs`, `getfile`, `hex2ptr`, `hijack-fd`, `ipi`, `patch`, `patch-list`, `patch-revert`, `plist`, `sigreturn`, `spray`, `tips`, `up`, `valist`, `vmmap-load`
  - `killthreads`, `pid`, `procinfo`

- `references/start-step-windbg.md`
  - Use when the task is about starting a target, attaching, stepping to the next useful control-flow event, running until a temporary destination, or using WinDbg-style aliases for breakpoints, memory display, and patching.
  - `attachp`, `entry`, `sstart`, `start`
  - `nextcall`, `nextjmp`, `nextproginstr`, `nextret`, `nextsyscall`, `stepover`, `stepret`, `stepsyscall`, `stepuntilasm`, `xuntil`
  - `bc`, `bd`, `be`, `bl`, `bp`, `da`, `db`, `dc`, `dd`, `dds`, `dq`, `ds`, `dw`, `eb`, `ed`, `eq`, `ew`, `ez`, `eza`, `go`, `k`, `ln`, `pc`, `peb`
