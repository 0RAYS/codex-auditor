# C/C++ 语义代码浏览器

这是一个本地 SQLite 索引和 CLI，用于收集 C/C++ 审计事实。主后端使用 `libclang` 解析
`compile_commands.json`，索引符号、定义、引用和诊断；同时保留近期 commit 和路由提示等辅助信息。

## 生成 compile_commands.json

CMake 项目：

```sh
cmake -S /目标/路径 -B /目标/路径/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

非 CMake 项目可用 Bear：

```sh
bear -- make
```

`build_index` 默认会在 workspace、`build/`、`out/` 等常见位置查找 `compile_commands.json`，也可以显式指定：

```sh
cargo run --release --manifest-path code_browser/Cargo.toml --bin build_index -- \
  --workspace /目标/路径 \
  --compile-commands /目标/路径/build/compile_commands.json \
  --db /目标/路径/code_browser/code_browser.sqlite
```

## 构建索引

```sh
cargo run --release --manifest-path code_browser/Cargo.toml --bin build_index -- \
  --workspace /目标/路径 \
  --db /目标/路径/code_browser/code_browser.sqlite \
  --route-file /目标/路径/code_browser/routes.json \
  --max-commits 500
```

`--path` 只限制文件辅助信息的收集范围；C/C++ 语义索引由 compile database 中的翻译单元决定。
默认只收集 C/C++ 相关后缀：`.c/.cc/.cpp/.cxx/.h/.hh/.hpp/.hxx`；test/fuzz 目录不会被特殊过滤。
`PARSE_DETAILED_PROCESSING_RECORD` 默认关闭，需要时可加 `--detailed-processing-record`。

`routes.json` 是可选路由文件：

```json
[
  {
    "pattern": "src/parser",
    "skill": "target-parser-audit",
    "reason": "输入格式解析、字段边界和错误恢复"
  }
]
```

## 查询示例

```sh
python3 code_browser/query.py --workspace /目标/路径 meta
python3 code_browser/query.py --workspace /目标/路径 symbols parse_header
python3 code_browser/query.py --workspace /目标/路径 def parse_header
python3 code_browser/query.py --workspace /目标/路径 refs 'c:@F@parse_header'
python3 code_browser/query.py --workspace /目标/路径 context src/foo.c:120-150
python3 code_browser/query.py --workspace /目标/路径 context parse_header
python3 code_browser/query.py --workspace /目标/路径 diagnostics
python3 code_browser/query.py --workspace /目标/路径 route src/parser/read.c
python3 code_browser/query.py --workspace /目标/路径 commits parser --limit 20
```

`refs <name>` 如果匹配多个不同 USR，会打印候选并要求改用 `refs <usr>`，避免把不同同名符号的引用静默合并。

## diagnostics 解释

`diagnostics` 表保存 libclang 解析诊断，severity 与 clang Python 绑定一致：

- `0`: ignored
- `1`: note
- `2`: warning
- `3`: error
- `4`: fatal

少量 warning 通常不影响索引可用性；`error`/`fatal` 表示某些翻译单元可能缺失真实符号或引用，应优先检查 include path、生成头文件、sysroot 或编译参数清洗问题。

## 通用可用性测试

对任意已拉取的 C/C++ 项目运行：

```sh
CODE_BROWSER_PROJECT=/目标/路径 pytest code_browser/test_code_browser_usability.py
```

如果项目没有 `compile_commands.json`，测试会 skip。默认不允许 error/fatal 诊断；可按项目现实情况放宽：

```sh
CODE_BROWSER_PROJECT=/目标/路径 CODE_BROWSER_MAX_FATAL_DIAGS=3 pytest code_browser/test_code_browser_usability.py
```

这些测试验证索引能构建、符号查询能回到定义文件、USR 引用能解析、`context path:line` 能显示源码窗口，以及同名不同 USR 不会被 `refs <name>` 静默合并。它们是可用性测试，不替代项目级 golden test。
