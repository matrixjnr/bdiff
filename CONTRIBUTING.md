# Contributing to bdiff

Thanks for helping out. bdiff is small on purpose; contributions should keep
it that way.

## Setup

bdiff currently runs on Linux only (it shells out to `sh`, reads `/proc`, and
traces with `strace`). On Windows or macOS, develop inside a Linux container
or VM.

    sudo apt-get install strace   # optional; bdiff degrades without it
    cargo build
    target/debug/bdiff dirs fixtures/parse-amount/old fixtures/parse-amount/new

## Before opening a PR

bdiff is self-hosting: CI builds your change and runs
`bdiff rev HEAD~1 HEAD`, so bdiff itself must confirm what your change does.
Run it locally first:

    cargo build
    target/debug/bdiff rev master HEAD

If the report shows deltas you intended, accept them and commit the result:

    target/debug/bdiff accept
    git add .bdiff/accepted.json

Unaccepted behavioral changes fail CI. That is the point.

## Pull requests

- `master` is protected: PRs need the `self-diff` check green, one approving
  review, and an up to date branch.
- One logical change per PR. Fill in the PR template, including the
  behavioral impact section.
- Add or extend a `[[case]]` in `bdiff.toml` (or a fixture under `fixtures/`)
  when your change adds observable behavior.

## Style

- Match the surrounding code; the project uses plain `Result<T, String>`
  errors, no async, and few dependencies. Justify any new dependency in the
  PR.
- Plain hyphens only in code, comments, docs, and output; no em or en dashes.
- Keep docs lean and practical.
