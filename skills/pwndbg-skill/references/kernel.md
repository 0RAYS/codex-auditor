# Kernel Commands

## Use This File For

- Linux kernel debugging in Pwndbg
- kernel base/symbol/config inspection
- page translation, slab, BPF, nftables, task/file, and module queries

## Fast Selection

| Need | Command |
| --- | --- |
| Find kernel base | `kbase` |
| Search kernel symbols | `klookup` |
| Show syscall table | `ksyscalls` |
| Inspect current task / tasks | `kcurrent`, `ktask` |
| Check kernel hardening/config | `kchecksec`, `kconfig`, `kcmdline`, `kversion` |
| Show modules | `kmod` |
| Translate addresses | `p2v`, `v2p`, `pagewalk`, `pageinfo` |
| Inspect slab allocator | `slab` |
| View dmesg | `kdmesg` |

## Core Inventory Commands

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `kbase [-r] [-v]` | Find kernel virtual base | `kbase`, `kbase -v` |
| `klookup [symbol]` | Look up kernel symbols | `klookup commit_creds` |
| `ksyscalls [name]` | Show syscall table or filter by syscall | `ksyscalls openat` |
| `kcurrent [pid]` | Show current kernel task / select by pid | `kcurrent`, `kcurrent 1337` |
| `ktask [task_name]` | Show kernel tasks | `ktask sshd` |
| `kmod [module_name]` | Show loaded modules | `kmod`, `kmod nf_tables` |

## Configuration and Hardening

| Command | Purpose |
| --- | --- |
| `kchecksec` | Show kernel hardening state |
| `kcmdline` | Dump `/proc/cmdline` |
| `kconfig [config_name]` | Show kernel config or filter one option |
| `kversion` | Show kernel version |

## Memory Translation and Paging

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `p2v paddr` | Physical to virtual address | `p2v 0x12345000` |
| `v2p vaddr` | Virtual to physical address | `v2p 0xffffffff81000000` |
| `pagewalk vaddr` | Walk page tables | `pagewalk 0xffffffff81000000` |
| `pageinfo page` | Convert a `struct page *` | `pageinfo 0xffffea0001234000` |

## Subsystem Helpers

| Command | Purpose |
| --- | --- |
| `binder` | Android Binder information |
| `buddydump` | Buddy allocator state |
| `kbpf` | BPF programs/maps |
| `kdmabuf` | DMA-BUF information |
| `kfile [pid]` | File descriptors reachable by a kernel task |
| `kmem-trace` | Trace SLUB/buddy alloc/free activity |
| `knft ...` | nftables data |
| `slab ...` | SLUB/slab data |
| `msr ...` | Read/write model-specific registers |

## Notes

- Prefer `kbase` and `klookup` before manual symbol rebasing.
- Prefer `pagewalk` over hand-decoding paging structures.
- Use `kchecksec` early in kernel exploit triage to anchor assumptions.
