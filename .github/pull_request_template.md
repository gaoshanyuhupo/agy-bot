## Summary

<!-- Briefly describe what this PR changes and why. -->

## Verification Checklist

- [ ] `python3 -m py_compile` passes for all modified/added Python files
- [ ] `ruff check .` passes with zero errors
- [ ] `python3 -m unittest discover -s tests -v` passes offline
- [ ] `python3 scripts/security_audit.py --mode public-release --check-history` passes with zero hits
- [ ] Confirmed zero real tokens, personal IDs, private domains, `/home/<user>` paths, or `.env` artifacts are included
