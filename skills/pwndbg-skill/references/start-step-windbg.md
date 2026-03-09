# Start, Step/Next/Continue, and WinDbg-Style Commands

## Use This File For

- starting a target cleanly
- quickly moving to the next interesting control-flow point
- using WinDbg-style aliases inside Pwndbg

## Start Commands

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `attachp [target]` | Attach by pid, name, argv match, or device | `attachp 1337`, `attachp nginx` |
| `entry [args ...]` | Start and stop at entry point | `entry`, `entry ./arg1` |
| `sstart` | Break at `__libc_start_main` then run | `sstart` |
| `start [args ...]` | Start and stop at a convenient early symbol | `start`, `start AAAA` |

## Execution Travel Commands

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `nextcall [regex]` | Run to next call instruction, optionally matching callee name | `nextcall malloc|free` |
| `nextjmp` | Run to next jump instruction | `nextjmp` |
| `nextproginstr` | Run to next instruction in the main program | `nextproginstr` |
| `nextret` | Run to next return-like instruction | `nextret` |
| `nextsyscall` | Run to next syscall without taking branches | `nextsyscall` |
| `stepover [addr]` | Break after the current instruction | `stepover`, `stepover $pc` |
| `stepret` | Step until the next return-like instruction | `stepret` |
| `stepsyscall` | Step until next syscall while taking branches | `stepsyscall` |
| `stepuntilasm mnemonic [ops ...]` | Step until a matching instruction | `stepuntilasm syscall` |
| `xuntil target` | Continue until a target address/expression | `xuntil *$rebase(0x1234)` |

## Execution Heuristics

- Use `start` for quick setup, `entry` for the real ELF entry point, and `sstart` for libc startup context.
- Use `nextcall` when the next interesting event is a function call.
- Use `nextret` or `stepret` when you want to escape the current routine.
- Use `nextsyscall` or `stepsyscall` when kernel boundaries are the interesting events.
- Use `xuntil` for one-shot destination control without leaving a normal breakpoint behind.

## WinDbg-Style Commands

### Breakpoint and Flow

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `bp where` | Set a breakpoint | `bp *$rebase(0x1234)` |
| `bc [which]` | Clear breakpoint | `bc 3` |
| `bd [which]` | Disable breakpoint | `bd 3` |
| `be [which]` | Enable breakpoint | `be 3` |
| `bl` | List breakpoints | `bl` |
| `go` | Continue execution | `go` |
| `pc` | Alias for `nextcall` | `pc` |
| `k` | Backtrace alias | `k` |
| `ln [value]` | Nearest symbol lookup | `ln $rip` |

### Memory Display / Edit

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `da`, `ds` | Dump string | `da $rdi` |
| `db`, `dc`, `dd`, `dq`, `dw` | Dump bytes/hexdump/dwords/qwords/words | `dq $rsp 16` |
| `dds` | Dump pointers and symbols | `dds $rsp` |
| `eb`, `ed`, `eq`, `ew` | Write bytes/dwords/qwords/words | `eb addr 90 90` |
| `ez`, `eza` | Write strings | `ez addr /bin/sh` |
| `peb` | Placeholder compatibility command | `peb` |

## Notes

- Prefer `dds` over raw word dumps when symbolized pointers matter.
- Prefer the `next*` family over repeated single-step commands when the user wants speed, not instruction-by-instruction auditing.
