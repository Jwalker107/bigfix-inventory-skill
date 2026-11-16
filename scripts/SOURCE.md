# Script provenance

| File | Source |
| --- | --- |
| `install_cit.sh`, `install_cit.ps1`, `scanner_test.py`, `win_scanner_test.py`, `signature_harness.py` | Copied unchanged from [jgstew/bigfix-content `scanner_signatures/`](https://github.com/jgstew/bigfix-content/tree/main/scanner_signatures), commit `3af41b5` (2026-11-13). The Unlicense. |
| `lint_signatures.py` | Written for this skill. It covers the static checks in [../reference/validation.md](../reference/validation.md) (levels 1-3 and the conventions). |
| `../examples/*.xml` | Copied unchanged from the same folder and commit. |

To refresh the copied files, download them again from upstream and re-run the linter on the
examples. Keep `signature_harness.py` next to the two harness scripts; they import it.

`install_cit.sh` and `install_cit.ps1` pin the scanner download URL and SHA256 for CIT 11.0.44.0.
They download HCL software from `software.bigfix.com` and install it. Run them only in a test
container or on a dedicated test host or folder.
