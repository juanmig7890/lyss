## What and why

<!-- The change, and the risk or problem it addresses. Link the issue if there is one. -->

## Checklist

- [ ] Every commit is signed off (`git commit -s`, see CONTRIBUTING.md: Developer Certificate of Origin)
- [ ] Only synthetic test data (documentation addresses, fake names and hashes), no real configuration
- [ ] Tests pass (`python -m pytest tests -q`); new or changed controls have a pass and a fail case
- [ ] Specification changes: `python tools/build_spec.py` run and CHANGELOG.md updated
