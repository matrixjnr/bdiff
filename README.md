# bdiff

Behavioral diff. Reports what two revisions *do* differently, not what lines changed.
See `bdiff-design.md` for the full design.

Status: v0 — process boundary only (stdout, stderr, exit, filesystem writes,
syscall summary via strace). No source understanding yet.

    cargo build
    target/debug/bdiff dirs fixtures/parse-amount/old fixtures/parse-amount/new
    target/debug/bdiff rev HEAD~1 HEAD        # self-host: bdiff diffing bdiff

Config is `bdiff.toml` in the new revision root (see the two in this repo).

Known v0 limits
- Exit-code heuristic for labels: programs that use non-zero exit as a normal
  result (bdiff itself) get mislabelled "regression?". Per-case expectations TBD.
- strace is a placeholder tracer; nested tracing auto-degrades.
- No scope stage: cannot report "changed code unreachable by corpus".

Roadmap: v1 tree-sitter + LSP scope · v2 DAP capture + coverage-guided corpus
· v3 traffic capture, own sandbox (replaces strace).
