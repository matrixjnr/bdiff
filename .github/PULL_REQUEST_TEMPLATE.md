# What

Describe the change and why it is needed.

## Behavioral impact

bdiff runs on every PR (`bdiff rev` against the previous commit). State what
the report shows:

- [ ] No behavior change (report is all `unchanged`)
- [ ] Intended behavior change: deltas reviewed, `bdiff accept` run, and the
      updated `.bdiff/accepted.json` is part of this PR

If behavior changed, paste the relevant report lines here:

```text
(bdiff output)
```

## Checklist

- [ ] `cargo build` passes
- [ ] `target/debug/bdiff dirs fixtures/parse-amount/old fixtures/parse-amount/new` behaves as expected
- [ ] New behavior is covered by a `[[case]]` in `bdiff.toml` or a fixture where practical
- [ ] Docs updated if flags, config, or output changed
