# Context, Breakpoint, Register, and Stack Commands

## Use This File For

- Pwndbg panes and watch expressions
- Conditional branch break helpers
- Register/flag inspection
- Stack and return-address views

## Fast Selection

| Need | Command |
| --- | --- |
| Toggle pane layout | `context` |
| Redirect pane output | `contextoutput` |
| Add/remove watched expressions | `contextwatch`, `contextunwatch` |
| Search old context snapshots | `contextsearch`, `contextprev`, `contextnext` |
| Break on branch outcome | `break-if-taken`, `break-if-not-taken` |
| Break by PIE-relative offset | `breakrva` |
| Show enhanced registers | `regs` |
| Change one status flag | `setflag` |
| Dump stack or full frame | `stack`, `stackf` |
| Locate return addresses | `retaddr` |

## Breakpoints

| Command | When to use | Key pattern |
| --- | --- | --- |
| `break-if-taken branch` | Stop only when a conditional branch is taken | `break-if-taken *$pc` |
| `break-if-not-taken branch` | Stop only when a conditional branch is not taken | `break-if-not-taken *$pc` |
| `breakrva off [module]` | Set a breakpoint from PIE/module base | `breakrva 0x1234` |
| `ignore N COUNT` | Skip the next `COUNT` hits of breakpoint `N` | `ignore 3 100` |

## Context Pane Family

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `context [subcontext ...]` | Show or enable/disable context sections | `context regs disasm stack` |
| `contextnext [count]` | Move forward in context history | `contextnext` |
| `contextprev [count]` | Move backward in context history | `contextprev 3` |
| `contextsearch needle [section]` | Search text in stored context history | `contextsearch malloc disasm` |
| `contextwatch {eval,execute} expr` | Add an expression or command output into the context view | `contextwatch eval '$base("libc")'` |
| `contextunwatch num` | Remove a watched entry | `contextunwatch 2` |
| `contextoutput section path clearing [banner] [width] [height]` | Send a context section to a file/TTY | `contextoutput stack /tmp/stack.txt 1` |

## Registers and Flags

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `regs [regs ...]` | Show enhanced register state | `regs rax rbx rip` |
| `cpsr [value]` | Decode ARM CPSR/xPSR | `cpsr` |
| `fsbase` | Print FS base | `fsbase` |
| `gsbase` | Print GS base | `gsbase` |
| `setflag flag value` | Flip one status flag quickly | `setflag zf 1` |

## Stack Views

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `stack [count] [offset]` | Dereference stack slots from the current SP | `stack 32 0` |
| `stackf [count] [offset]` | Show the current stack frame layout | `stackf` |
| `stack-explore` | Explore stacks from all threads | `stack-explore` |
| `retaddr` | Show stack words that look like return addresses | `retaddr` |
| `canary [-a]` | Show the current stack canary | `canary` |

## Practical Heuristics

- Prefer `regs` over plain `info registers` because it adds dereference/context.
- Prefer `stack`/`stackf` over manual `x/gx $sp` loops.
- Use `retaddr` before walking a deep stack manually when you only need likely saved RIPs.
- Use `contextwatch` for expressions that you keep recomputing after every stop.
- Use `break-if-taken` or `break-if-not-taken` to target one branch outcome without scripting a conditional breakpoint.
