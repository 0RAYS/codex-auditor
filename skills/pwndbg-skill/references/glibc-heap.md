# glibc ptmalloc Heap Commands

## Use This File For

- glibc `ptmalloc` arena/bin/tcache inspection
- quick chunk ownership checks
- fake-fastbin and free-behavior triage

## Entry Points

| Need | First command |
| --- | --- |
| Whole heap walk | `heap` |
| Which heap/chunk owns this address | `hi` or `malloc-chunk` |
| Arena overview | `arenas`, `arena` |
| Bin overview | `bins` |
| Only tcache | `tcache`, `tcachebins` |
| Only fastbins/smallbins/largebins/unsorted | matching `*bins` command |
| Top chunk and allocator globals | `top-chunk`, `mp` |
| Check a candidate free | `try-free` |
| Visual layout | `vis-heap-chunks` |

## Core Commands

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `heap [-v] [-s] [addr]` | Walk chunks on a heap | `heap`, `heap -v` |
| `malloc-chunk addr` | Decode one chunk header | `malloc-chunk 0x555555559290` |
| `hi addr` | Tell whether an address belongs to a heap chunk | `hi 0x5555555592a0` |
| `arenas` | List arenas | `arenas` |
| `arena [addr]` | Print one arena structure | `arena`, `arena 0x7ffff7fc4c40` |
| `bins [addr] [tcache_addr]` | Show all bins plus thread tcache | `bins` |

## Bin-Specific Commands

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `fastbins [addr]` | Show fastbins for an arena | `fastbins` |
| `smallbins [addr]` | Show smallbins | `smallbins` |
| `largebins [addr]` | Show largebins | `largebins` |
| `unsortedbin [addr]` | Show the unsorted bin | `unsortedbin` |
| `tcache [addr]` | Show one thread tcache summary | `tcache` |
| `tcachebins [addr]` | Show tcache bin contents | `tcachebins` |

## Specialized Helpers

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `mp` | Print `mp_` allocator globals | `mp` |
| `top-chunk [addr]` | Show top chunk information | `top-chunk` |
| `try-free addr` | Predict what `free(addr)` would do | `try-free 0x5555555592a0` |
| `find-fake-fast` | Search for fake-fastbin candidates | `find-fake-fast --align` |
| `vis-heap-chunks` | Visual heap layout output | `vis-heap-chunks --beyond-top` |

## Recommended Workflow

1. Start with `heap`, `arenas`, and `bins` for a global picture.
2. Use `hi` or `malloc-chunk` when the user gives a suspicious pointer.
3. Narrow to `tcache*`, `fastbins`, `smallbins`, `largebins`, or `unsortedbin` depending on the target path.
4. Use `try-free` for “what happens if this is freed?” questions.
5. Use `vis-heap-chunks` when textual chunk output is too noisy.

## Notes

- `bins` is a strong default because it summarizes multiple allocator queues at once.
- `hi` is usually faster than manually comparing an address against heap ranges.
- `find-fake-fast` is niche; load it when the user is explicitly exploring fake fastbin placement.
