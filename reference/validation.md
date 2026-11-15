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
  CDATA well-formedness (level 2), and the conventions: guarded `ReadFile`, exported
  `INSTALL_PATH`/`DETAILED_VER`/`IS_INSTALLED`, empty-`DETAILED_VER` skip, exact `IS_INSTALLED`
  skip string, identical `IS_INSTALLED` block per `Software`, empty `<Instance>`, known pitfalls
  (`RpmProductInfo field="version"`, name-like `MsiProductList filter`, `XmlValue`, `&#10;`
  crops without a `&#13;` crop), ASCII-only, final newline.
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
