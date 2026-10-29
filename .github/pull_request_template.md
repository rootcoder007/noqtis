## What and why

<!-- What this changes and why it is needed. Link the issue: "Closes #123". -->

## How it was tested

<!-- The tests you added or ran: ctest (full, or with NQSLSUB/NQFAST),
     NQSAN=ON, valgrind, a binding's own tests, the site build. -->

## Checklist

- [ ] Every commit has a `Signed-off-by` line (`git commit -s`) and an
      `area: summary` subject with a body that says why.
- [ ] Tests cover the change (for a parser: what it refuses; for secret
      data: a ctgrind test).
- [ ] No new dependency, ISO C11 only, short names, ASCII sources.
- [ ] Manual page, site page and examples updated for any change to the
      public API or the `noqtis` command.
- [ ] `sh bindings/r/tools/vendor.sh` rerun if `src/` or `include/` changed.

<!-- Security fixes are not proposed here before disclosure: see SECURITY.md. -->
