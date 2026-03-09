# musl mallocng Heap Commands

## Use This File For

- musl libc targets that use `mallocng`
- slot, group, meta, and global context inspection

## First Commands to Try

| Need | First command |
| --- | --- |
| Quick conceptual refresher | `mallocng explain` |
| Dump the whole heap | `mallocng dump` |
| Find which slot owns an address | `mallocng find` |
| Visualize neighboring slots | `mallocng vis` |
| Inspect global allocator state | `mallocng ctx` |

## Command Map

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `mallocng explain` | Print a compact allocator overview | `mallocng explain` |
| `mallocng dump [-ma addr]` | Dump heap state, optionally one meta area | `mallocng dump`, `mallocng dump -ma 0x1234` |
| `mallocng vis address [count]` | Visualize slots in the owning group | `mallocng vis 0x555555559200 16` |
| `mallocng find [-a] [-m] [-s] address` | Find the slot containing an address | `mallocng find -a 0x555555559200` |
| `mallocng ctx [address]` | Show `__malloc_context` | `mallocng ctx` |
| `mallocng metaarea [-i idx] address` | Decode one `meta_area` | `mallocng metaarea 0x555555558000` |
| `mallocng group [-i idx] address` | Decode one group | `mallocng group 0x555555559000` |
| `mallocng meta address` | Decode a group from its `meta` address | `mallocng meta 0x555555557e80` |
| `mallocng slots [-a] address` | Decode one slot by slot start | `mallocng slots 0x5555555591f0` |
| `mallocng slotu [-a] address` | Decode one slot by user pointer | `mallocng slotu 0x555555559200` |

## Practical Heuristics

- Start with `mallocng explain` when the model needs a mental refresh before reasoning about corruption.
- Prefer `mallocng find` when the user gives an arbitrary pointer.
- Use `mallocng slotu` when the pointer is the user-facing allocation pointer.
- Use `mallocng slots` when you already know the slot start.
- Use `mallocng ctx` early when global state matters.
