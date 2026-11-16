# bigfix-inventory-skill

An agent skill for writing, editing, reviewing, validating and testing HCL BigFix Inventory
(BFI) software signatures (`SoftwareIdentityCatalog` XML with `ExtendedSignature` bodies,
evaluated by the CIT scanner).

Start with [SKILL.md](SKILL.md).

| Path | Contents |
| --- | --- |
| [SKILL.md](SKILL.md) | When to use the skill, key pitfalls, edit and review workflows |
| [reference/catalog.md](reference/catalog.md) | Signature types, Catalog Customization limits (schema 2.7, 4000 characters), GUID and catalog/scan/import rules |
| [reference/file-format.md](reference/file-format.md) | The `SoftwareIdentityCatalog` outer layer and the XSS CDATA body |
| [reference/scanner-behavior.md](reference/scanner-behavior.md) | Verified operator behavior, and where it differs from HCL's documentation |
| [reference/file-visibility.md](reference/file-visibility.md) | Scan scope, exclusions, FSMon vs Provider Cache 2, sample configurations |
| [reference/writing.md](reference/writing.md) | Rules and copy-ready templates |
| [reference/validation.md](reference/validation.md) | The four validation levels |
| [reference/testing.md](reference/testing.md) | Endpoint procedure and the standalone Linux/Windows harnesses |
| [reference/review.md](reference/review.md) | Review steps and checklist |
| [reference/case-studies.md](reference/case-studies.md) | Design decisions from the PHP, Node.js/Electron and Brotli sets |
| [reference/source-AGENTS.md](reference/source-AGENTS.md) | Archived upstream source document (2026-11-16 snapshot), kept for provenance and its full per-container expected results. Not skill guidance |
| [scripts/](scripts/) | `lint_signatures.py` (static checks) and the CIT install and scanner test harnesses |
| [examples/](examples/) | Two verified signature files (PHP CVE, Electron inventory) |

The skill is self-contained; no repository-level `AGENTS.md` is required to use it.

Adapted from [jgstew/bigfix-content `scanner_signatures/`](https://github.com/jgstew/bigfix-content/tree/main/scanner_signatures)
(The Unlicense). See [scripts/SOURCE.md](scripts/SOURCE.md).
