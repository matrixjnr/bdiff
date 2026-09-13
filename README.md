# bdiff

Behavioral diff. Reports what two revisions of a program *do* differently, not
what lines changed. The old revision is the oracle: no tests are required,
disagreement between old and new is the signal.

Status: v0. Observation happens at the process boundary only: exit code,
stdout, stderr, filesystem writes, and a syscall summary via strace. No source
understanding yet.

## Usage

    cargo build
    target/debug/bdiff dirs <old-dir> <new-dir>     # compare two directories
    target/debug/bdiff rev  <old-rev> <new-rev>     # compare two git revisions

    # try it on the bundled fixture
    target/debug/bdiff dirs fixtures/parse-amount/old fixtures/parse-amount/new

    # self-host: bdiff diffing its own last change
    target/debug/bdiff rev HEAD~1 HEAD

Exit code 0 means no behavior change, 1 means changes were found, 2 means
error. Flags: `--json` for machine-readable output, `--repeats N` to control
flakiness detection, `--no-trace` to skip strace, `--config FILE` to override
config discovery.

## Configuration

bdiff reads `bdiff.toml` from the new revision root. Each `[[case]]` is one
invocation to run against both revisions:

    [build]
    cmd = "cargo build -q"          # run once per revision before cases

    [run]
    cmd = "target/debug/app"        # program to run; case args are appended
    repeats = 2                     # runs per case; >1 detects flakiness
    reset = "auto"                  # tree reset per run: auto | git | copy | none

    [[case]]
    name = "help text"
    args = ["--help"]
    expect_exit = [0]               # exit codes that count as success

    [normalise]
    patterns = ['0\.\d{6,}']        # regexes replaced before diffing output

The `bdiff.toml` in this repo is a working example: it runs bdiff on its own
fixtures.

## Accepting intended changes

Findings are labelled unchanged, new behavior, regression candidate, changed,
accepted, or flaky. When a change is intended, record it:

    bdiff rev HEAD~1 HEAD     # review the report
    bdiff accept              # promote the new fingerprints
    git add .bdiff/accepted.json && git commit

Accepted deltas are still reported but no longer fail the run. CI runs
`bdiff rev HEAD~1 HEAD` on every push, so a change to bdiff's own behavior
must be accepted before it can land.

The reset keeps repeats and cases from seeing each other's side effects:
`auto` uses git in rev mode and nothing in dirs mode, `git` runs
`git clean` plus `git checkout`, `copy` restores the tree from a pristine
copy taken before the first run (works anywhere), `none` disables it.

## Known v0 limits

- strace is a placeholder tracer; when bdiff itself runs under a tracer,
  syscall tracing auto-degrades to off (nested ptrace is unsupported).
- Syscall tracing is Linux only. On Windows and macOS bdiff still runs:
  filesystem changes are detected by walking the tree before and after each
  case instead of from the trace.
