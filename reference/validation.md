# Validation (four levels; run all of them)

The outer schema alone proves almost nothing: it never looks inside the CDATA. A wrong element
name, attribute or `field` value only shows up at levels 3-4.

## Quick path: `scripts/lint_signatures.py`

```bash
python scripts/lint_signatures.py path/to/software_*.xml
python scripts/lint_signatures.py --xsd SoftwareIdentityCatalog.xsd --xss-dir <CIT>/config/xss path/to/*.xml
```

- Always: well-formed outer XML, required attributes, `version` pattern, `uniqueId` format and
  uniqueness across all given files (v1 IDs warned), `created`/`modified` format and order,
  CDATA well-formedness (level 2), body length (error over 3829 characters, warning over 90% of
  it - see [catalog.md](catalog.md#body-length-limits)), the leading comment's
  `ProductName`/`Release` against the `Software` attributes
  ([file-format.md](file-format.md#leading-comment)), and the conventions: guarded `ReadFile`,
  exported `INSTALL_PATH`/`DETAILED_VER`/`IS_INSTALLED`, empty-`DETAILED_VER` skip, exact
  `IS_INSTALLED` skip string, identical `IS_INSTALLED` block per `Software`, empty
  `<Instance>`, known pitfalls (`RpmProductInfo field="version"`, name-like
  `MsiProductList filter`, `XmlValue`, `&#10;` crops without a `&#13;` crop), ASCII-only, final
  newline.
- `--xsd`: level 1 against the outer schema (needs `lxml`). Without it, the linter tries to find
  the schema in an installed `validate_bes_xml` package.
- `--xss-dir`: level 3 against the scanner's schema (needs `lxml` and the HCL files from a CIT
  install; don't commit them). Each body is wrapped as in [file-format.md](file-format.md).
- Errors exit 1. Warnings point at things a reviewer should look at; some shipped signatures
  have them on purpose (e.g. a `version` file known to be LF-only).
- `--json` prints machine-readable findings.

The manual equivalents follow.

## Level 1: outer schema

The schema is `SoftwareIdentityCatalog.xsd`. It's identical to CommunityContent's
`.github/actions/validate-signatures-xsd/signature.xsd`, and ships in the PyPI package
`validate-bes-xml`:

```bash
XSD=$(uvx --from validate-bes-xml python -c "import validate_bes_xml, pathlib; print(pathlib.Path(validate_bes_xml.__file__).parent / 'schemas' / 'SoftwareIdentityCatalog.xsd')")
xmllint --nonet --noout --schema "$XSD" path/to/*.xml
```

## Level 2: every CDATA body is well-formed XML

```bash
python3 - path/to/*.xml <<'EOF'
import re, sys, xml.dom.minidom
for f in sys.argv[1:]:
    for i, body in enumerate(re.findall(r"<!\[CDATA\[(.*?)\]\]>", open(f, encoding="utf-8").read(), re.S), 1):
        xml.dom.minidom.parseString(body)
        print(f"{f}: signature {i} well-formed")
EOF
```

## Level 3: the scanner's own schema (XSS)

Wrap every body in the scanner's input document ([file-format.md](file-format.md)) and validate
against `<CIT>/config/xss/signatures.xsd`. This catches unknown elements, attributes and
`field`/`relation`/`type` values. `scripts/scanner_test.py` and `scripts/win_scanner_test.py` do
this before scanning and exit 1 on failure. By hand:

```bash
xmllint --nonet --noout --schema <CIT>/config/xss/signatures.xsd wrapped.xml
```

The Linux bundle's schema works for Windows signatures too (verified). Copy it out of a test
container: `docker cp <container>:/opt/cit/config/xss <scratch>/xss`.

## Level 4: behavior with the real scanner

The only level that proves the signature finds the software and extracts the right version. See
[testing.md](testing.md).

## Repository hooks

jgstew/bigfix-content's pre-commit config runs `check-xml`, `trailing-whitespace`,
`end-of-file-fixer` and `codespell`. Its PR workflow adds `fix-files-to-ascii`: **non-ASCII
characters fail CI**. CommunityContent's PR workflow runs level 1 only (it installs
`libxml2-utils` with `apt` and can fail on a DNS error before validating; re-run if so). None of
these check signature content.

## Pre-commit: `bes-signature-lint`

[jgstew/pre-commit-bigfix](https://github.com/jgstew/pre-commit-bigfix) v2.5.0 added
`bes-signature-lint`, which checks the CDATA bodies from a pre-commit hook. It covers much the
same ground as `scripts/lint_signatures.py`, and adds repo-wide `uniqueId` uniqueness, which a
per-invocation script cannot. Use the hook to gate a repository; use the script for ad-hoc runs,
`--json`, and levels 1 and 3.

```yaml
  - repo: https://github.com/jgstew/pre-commit-bigfix
    rev: v2.5.0
    hooks:
      - id: bes-schema-validate      # level 1: the outer schema
      - id: bes-signature-lint       # the CDATA bodies
```

| code | default | check |
| --- | --- | --- |
| `E100` | on | a body over `--max-signature-chars` (3829; see [catalog.md](catalog.md#body-length-limits)) |
| `E101` | on | a body that is not well-formed when wrapped as `<r>BODY</r>` (level 2) |
| `E102` | on | a `Signature` `uniqueId` used twice in one file, or by another signature file in the repo |
| `E103` | on | `$(NAME)` or `withVariable="NAME"` with no `Variable`/`Iterator` of that name in the body |
| `E104` | on | an `<Instance>` with no element children |
| `E105` | on | `RpmProductInfo field="version"` |
| `E106` | off | the file is not well-formed XML (`bes-schema-validate` owns file validity) |
| `W100` | on | a body over 90% of the limit |
| `W101` | on | a `Software` `uniqueId` duplicated (a warning only: `Software` IDs are not confirmed global) |
| `W102` | on | `ReadFile` with no `FileInfoCompare field="size"` guard |
| `W103` | on | `ReadFile` plus `StringCrop endString="&#10;"` with no `&#13;` anywhere in the body |
| `W104` | on | a `DETAILED_VER` with no empty-value `SKIP` |
| `W105` | off | a body that does not export all of `INSTALL_PATH`, `DETAILED_VER`, `IS_INSTALLED` |
| `W106` | on | an `RpmProductList filter` that does not end in `*` |
| `W107` | on | an `MsiProductList filter` that is not `*`, does not start with `*`, and is not a `{GUID}` |
| `W108` | on | `XmlValue` |
| `W109` | on | a **new** v1 (time-based) `uniqueId`: one in no signature file of the repo at `HEAD`. Skipped outside git |
| `W110` | on | the leading comment's `ProductName` / `Release` differ from `<Software name>` / `version` |
| `W111` | on | `modified` earlier than `created` |
| `W112` | on | an uppercase hex digit in a `uniqueId` |

Before turning it on:

- It only sees files **directly inside** a `Signatures/` folder
  (`(^|/)Signatures/[^/]+\.xml$`). Signatures kept anywhere else need a `files:` override.
- E-codes fail the hook; warnings fail only under `--strict`. `--disable CODES` and
  `--enable CODES` adjust the set (`E106` and `W105` are off by default).
- `E102` and `W101` compare each file passed in against **every signature file git tracks in
  that file's repository**, but report only on the files passed in. So an existing duplicate
  between two unchanged files surfaces only under `--all-files`, or when one of them is edited.
  IDs are compared ignoring case. Keeping a signature's own ID while editing it in place is how
  the import replaces it, and is never a collision.
- A file opts out of every check with `pre-commit-skip: bes-signature-lint` anywhere in it, and
  a file whose root is not `<SoftwareIdentityCatalog>` is skipped. Nothing is auto-fixed.
- `W109` is narrower than this skill's linter, which warns on **any** v1 ID: the hook warns only
  on one that is new to the repository, so an imported BigFix Inventory export stays quiet.
