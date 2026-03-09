# jemalloc Heap Commands

## Use This File For

- programs linked against `jemalloc`
- extent inspection and pointer-to-extent mapping

## Command Map

| Command | Purpose | Key pattern |
| --- | --- | --- |
| `jemalloc heap` | Print all extent information | `jemalloc heap` |
| `jemalloc extent-info addr` | Decode one extent metadata structure | `jemalloc extent-info 0x7ffff0001000` |
| `jemalloc find-extent addr` | Find which extent owns an allocated pointer | `jemalloc find-extent 0x7ffff0204560` |

## Suggested Workflow

1. Use `jemalloc heap` to inventory extents.
2. Use `jemalloc find-extent ptr` when the user gives an allocation pointer.
3. Use `jemalloc extent-info addr` when you already have the metadata address and want full detail.

## Heuristics

- Prefer `jemalloc find-extent` over manual metadata hunting from the user pointer.
- Use `-v` with `jemalloc extent-info` when exploitation/debugging depends on less common fields.
