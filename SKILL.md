---
name: bigfix-inventory-skill
description: Write, edit, review, validate and test HCL BigFix Inventory (BFI) software signatures, the SoftwareIdentityCatalog XML files with ExtendedSignature CDATA bodies that the CIT scanner (wscanfs, wscansw) evaluates. Use it for custom catalog signatures, bigfix/CommunityContent Signatures/ PRs, software_*.xml files with versions like 0.AFFECTED or 0.any_version, scanner-language elements (MultipleInstance, FindFilePathEx, DpkgProductList, RpmProductInfo, MsiProductList, WinFileInfo, StringCrop, ReadFile), and running signatures through a standalone CIT scanner or a scanner-equipped endpoint. Also covers choosing a BFI signature type (package, file, template or extended), BigFix Inventory Catalog Customization limits (schema 2.7, the 3829-character import limit and the 4000-character UI limit), and why a signature finds nothing: scan scope, exclusions and the file-system cache (FSMon, Provider Cache 2). Do not use it for Fixlet relevance or ActionScript; use bigfix-skill for those.
---

# BigFix Inventory signatures

A BFI software signature is an XML file that tells the BigFix Inventory scanner
(CIT: `wscanfs` indexes files, `wscansw` evaluates signatures) how to recognize a
piece of software and its version on an endpoint, without running the software. The
files are imported into BigFix Inventory as custom catalog content. The same format
is used in [bigfix/CommunityContent `Signatures/`](https://github.com/bigfix/CommunityContent/tree/main/Signatures).

This skill is **self-contained**: everything it needs is in this folder. It is adapted from
[jgstew/bigfix-content `scanner_signatures/AGENTS.md`](https://github.com/jgstew/bigfix-content/blob/main/scanner_signatures/AGENTS.md)
(The Unlicense), last reconciled with that document on **2026-11-16**; that snapshot is archived
at [reference/source-AGENTS.md](reference/source-AGENTS.md) for provenance and for the
per-container expected results the reference pages only summarize. Links to HCL's public
documentation are supporting references for product terminology and workflow; where an
observation here differs from them, both the observation and its scope are recorded (see
[reference/scanner-behavior.md](reference/scanner-behavior.md#where-this-skill-differs-from-hcl-public-documentation)).

Scanner facts were verified with CIT **11.0.44.0** on Debian 12, Ubuntu 24.04, Rocky Linux 9
(amd64 containers) and Windows Server 2022, in October-November 2026; some work also covered
Debian 13/sid, Ubuntu 22.04, Rocky 8, Fedora 42, Amazon Linux 2023, openSUSE Leap 15 and Arch.
Facts marked *(not verified)* weren't. Re-check scanner behavior when the scanner version changes.

## Read first

| Task | Read |
| --- | --- |
| Any signature work | This file, then [reference/scanner-behavior.md](reference/scanner-behavior.md): the scanner quirks decide whether a signature works |
| Choosing a signature type, Catalog Customization, the body length limits (3829 import / 4000 UI), getting a change onto endpoints | [reference/catalog.md](reference/catalog.md) |
| "The signature finds nothing": scan scope, exclusions, FSMon vs Provider Cache 2 | [reference/file-visibility.md](reference/file-visibility.md) |
| Understanding or editing the XML | [reference/file-format.md](reference/file-format.md) |
| Writing a new signature or detection method | [reference/writing.md](reference/writing.md) (rules and templates) |
| Validating | [reference/validation.md](reference/validation.md) |
| Running signatures (on an endpoint, or standalone on Linux/Windows; macOS limits) | [reference/testing.md](reference/testing.md) |
| Reviewing a signature or a CommunityContent PR | [reference/review.md](reference/review.md) |
| Design examples (Node.js/Electron, Brotli, PHP) | [reference/case-studies.md](reference/case-studies.md) and [examples/](examples/) |

## Five facts that break most signatures

1. **The outer schema never looks inside the CDATA.** A file can pass
   `SoftwareIdentityCatalog.xsd` with a misspelled element, attribute or `field` inside the
   signature body. Only the scanner's own XSS schema (level 3) and a real scan (level 4) catch that.
2. **`FindFilePathEx` searches a prepared file-system cache, never the disk.** A name the scan
   catalog doesn't search for is never cached, an excluded directory is invisible, and
   **symlinks are skipped** (Debian's `/usr/bin/php` is a symlink, so `name="php"` doesn't find
   it). Windows normally uses the Scanner Service's FSMon cache; other platforms and the test
   harnesses use Provider Cache 2 ([reference/file-visibility.md](reference/file-visibility.md)).
3. **A failing scalar expression drops the whole instance silently.** `ReadFile` on a missing
   file does this. Guard every `ReadFile` with `FileExists` and a `FileInfoCompare field="size"`.
4. **`RpmProductInfo field="version"` returns `8.0.30.8.el9_8.1`**, which `Compare type="version"`
   can't handle. Use `field="displayVersion"` and crop at `-`. (`displayVersion` drops the epoch.)
5. **CRLF files keep the `\r`.** A crop that ends at `&#10;` returns `4.2.2\r`, `Compare` fails,
   and the instance disappears. Also crop at `&#13;` for any file a user can edit.

More in [reference/scanner-behavior.md](reference/scanner-behavior.md).

## Workflow: editing or writing a signature

1. Read the existing file and the other signatures under the same `Software`. Keep their style.
   For new content, first confirm the software isn't already in the HCL-provided catalog and
   that an extended signature is needed at all ([reference/catalog.md](reference/catalog.md)).
2. Choose evidence in this order: package database (dpkg, RPM, MSI) > Windows version resource
   (`WinFileInfo`) > a small version file next to the binary (`ReadFile` + `StringCrop`, size-guarded).
3. Keep the conventions:
   - Export `INSTALL_PATH`, `DETAILED_VER` and `IS_INSTALLED`.
   - Skip early (missing file, too large, wrong package name, metapackage).
   - Skip an empty `DETAILED_VER` (`<Condition withVariable="DETAILED_VER"><Action do="SKIP" onValue=""/></Condition>`).
   - Crop versions to `X.Y.Z` before `Compare type="version"`.
   - End with exactly `<Condition withVariable="IS_INSTALLED"><Action do="SKIP" onValue="false"/></Condition>`
     (the test harness removes this exact string to build its diag copy).
   - Use an **identical** `IS_INSTALLED` block in every signature of one `Software`.
4. IDs and dates:
   - New `Software`/`Signature` `uniqueId`: a new lowercase `uuid4`
     (`python -c "import uuid; print(uuid.uuid4())"`). Never reuse an ID, and don't create
     time-based (v1) IDs, which embed the machine's MAC address.
   - Set `created` on new signatures and update `modified` whenever a body changes
     (`xs:dateTime`, e.g. `2026-11-14T18:00:00Z`).
5. Keep the file ASCII-only, with a newline at the end (non-ASCII characters fail the upstream
   CI check). Match the line endings already used by the file you are editing, and whatever the
   host repository's `.gitattributes` or editor settings dictate; don't convert a file wholesale
   as a side effect of an edit. Keep every CDATA body **under 3829 characters**, the most
   BigFix Inventory imports from one body; a body destined for Catalog Customization also has
   to stay under the UI's 4000 ([reference/catalog.md](reference/catalog.md#body-length-limits)).
   When the file carries a leading comment, keep its `ProductName` / `Release` equal to
   `<Software name>` / `@version`
   ([reference/file-format.md](reference/file-format.md#leading-comment)).
6. Validate: `python scripts/lint_signatures.py <files>` (levels 1-2 and the conventions), then
   level 3 and 4 with the harness ([reference/validation.md](reference/validation.md),
   [reference/testing.md](reference/testing.md)). A repository that runs pre-commit can gate the
   same ground with `bes-signature-lint` from
   [jgstew/pre-commit-bigfix](https://github.com/jgstew/pre-commit-bigfix) v2.5.0+
   ([reference/validation.md](reference/validation.md#pre-commit-bes-signature-lint)).
7. When an expression's result is uncertain, write a probe signature that exports every
   intermediate variable ([reference/testing.md](reference/testing.md#probing-scanner-behavior))
   instead of guessing.

## Workflow: reviewing a signature

Follow [reference/review.md](reference/review.md). In short: run the linter, run levels 3-4 with a
fixture for every detection method (and both sides of every version threshold), check the
conventions above, and report false negatives, false positives (distro backports), duplicates,
and platforms the signature can't see (for example macOS, which has no signature engine).

## Scripts

All scripts are in [scripts/](scripts/). Python 3.9+. See [scripts/SOURCE.md](scripts/SOURCE.md) for provenance.

| Script | Runs on | What it does |
| --- | --- | --- |
| `lint_signatures.py` | anywhere | Static checks: outer XSD (with `lxml` and a schema), CDATA well-formedness, body length (3829), IDs, dates, guards, conventions, identical `IS_INSTALLED` blocks, leading comment vs `Software` attributes, ASCII. Optional level 3 with `--xss-dir`. Exit 1 on errors. Written for this skill. |
| `install_cit.sh` | inside a Linux machine or container | Downloads (SHA256-pinned) and installs CIT 11.0.44.0 to `$CIT_DIR` (default `/opt/cit`) as a private copy. |
| `install_cit.ps1` | Windows (admin PowerShell) | Same for Windows, into `-T` (default `C:\bfi_sig_test`). |
| `scanner_test.py` | host with `docker` and `xmllint` | Runs signatures (shipped and diag copies) through the scanner in a container; level 3 + 4; prints JSON. |
| `win_scanner_test.py` | host with `ssh`/`scp` and `xmllint` | Same against a Windows host over SSH (`WINHOST=user@host`). |
| `signature_harness.py` | (library) | Shared code for the two harnesses. Keep it next to them. |

## Rules for this content

- **Never commit HCL-licensed files**: scanner binaries, `config/xss/*.xsd`, `config.xml`, `traceCIT.log`.
  Download them when needed.
- Don't claim a signature detects something on a platform where it wasn't tested; say *(not verified)*.
- Don't invent scanner elements, attributes or `field` values. If an element isn't in
  [reference/scanner-behavior.md](reference/scanner-behavior.md) or the examples, check it against the
  scanner's XSS schema (level 3) and a probe.
- Version comparisons flag distro builds with backported fixes. Say so in the description or PR;
  a signature can't tell unless it lists fixed builds explicitly (see the Brotli case study).
- Don't overstate affected ranges. Take them from the vendor advisory and cite it.
- Keep a detection method's GUID when correcting it, so existing discoveries stay associated;
  retire a method by deleting it and adding the replacement under a new GUID
  ([reference/catalog.md](reference/catalog.md#getting-a-change-onto-endpoints)).
- Where an observation here conflicts with HCL's public documentation, don't silently adopt
  either one: state the version, platform and configuration the observation came from, and add
  it to the divergence table in
  [reference/scanner-behavior.md](reference/scanner-behavior.md#where-this-skill-differs-from-hcl-public-documentation).
- A standalone test configuration is not a production scan configuration. Don't recommend one
  as a deployment setting.
