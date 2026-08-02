## Summary

<!-- What changed and why? -->

## Security and failure modes

<!-- Which trust boundaries or fail-closed paths are affected? Write "None" if none. -->

## Compatibility

<!-- Note protocol, configuration, state, or deployment impact. -->

## Validation

- [ ] `PYTHONPATH=src:tests python3 -m unittest discover -s tests -v`
- [ ] `ruff check src tests scripts`
- [ ] `pyright`
- [ ] `shellcheck install.sh bin/tmuxgate src/tmuxgate/assets/*.sh`
- [ ] Branch coverage remains at or above the documented threshold
- [ ] No real addresses, credentials, fingerprints, runtime state, or result data are included
- [ ] Architecture/security documentation is updated when required
