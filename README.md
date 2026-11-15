# bigfix-inventory-skill

An agent skill for writing, editing, reviewing, validating and testing HCL BigFix Inventory
(BFI) software signatures (`SoftwareIdentityCatalog` XML with `ExtendedSignature` bodies,
evaluated by the CIT scanner).

Start with [SKILL.md](SKILL.md).

| Path | Contents |
| --- | --- |
| [SKILL.md](SKILL.md) | When to use the skill, key pitfalls, edit and review workflows |
| [reference/](reference/) | File format, scanner behavior, writing rules and templates, validation, testing, review checklist, case studies |
| [scripts/](scripts/) | `lint_signatures.py` (static checks) and the CIT install and scanner test harnesses |
| [examples/](examples/) | Two verified signature files (PHP CVE, Electron inventory) |

Adapted from [jgstew/bigfix-content `scanner_signatures/`](https://github.com/jgstew/bigfix-content/tree/main/scanner_signatures)
(The Unlicense). See [scripts/SOURCE.md](scripts/SOURCE.md).
