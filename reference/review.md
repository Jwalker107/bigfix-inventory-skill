# Reviewing a signature or a CommunityContent PR

## Steps

1. **Get the exact file under review.** For a CommunityContent PR:
   `git fetch origin pull/<n>/head:pr<n>`, then `git show pr<n>:Signatures/<file> > <scratch>/<file>`.
   Also get the current `main` version to diff against.
2. **Static checks:** `python scripts/lint_signatures.py <file>` (add `--xsd`/`--xss-dir` when
   available). Treat errors as blocking; judge each warning. In a repository with pre-commit,
   `pre-commit run bes-signature-lint --all-files` covers the same ground plus repo-wide
   `uniqueId` collisions ([validation.md](validation.md#pre-commit-bes-signature-lint)).
3. **Behavior (level 4):** run `scripts/scanner_test.py` (Linux) and, for Windows signatures,
   `scripts/win_scanner_test.py`. Add a fixture for each detection method, including:
   - both sides of every version threshold (last affected, first fixed);
   - old releases (file formats change between releases);
   - CRLF and TAB/space variants of any text file that's read;
   - look-alikes that must not match (headers caches, `-dev` packages, metapackages, folders
     whose names contain the same marker).
   Use real releases from the vendor's archive (WordPress plugins:
   `https://downloads.wordpress.org/plugin/<slug>.<version>.zip`).
   Read the diag results: they show the extracted version even when not affected.
4. **Conventions** (see [writing.md](writing.md)): identical `IS_INSTALLED` block across all
   signatures of a `Software`; new `uuid4` IDs; `modified` updated on changed bodies; empty
   `DETAILED_VER` skipped; size-guarded `ReadFile`; ASCII-only; newline at the end of the file.
5. **Correctness of the claim:** affected ranges match the vendor advisory (cite it); fixed builds
   skipped only when sourced from the distro tracker; the description doesn't claim platforms
   that weren't tested (especially macOS, which can't run signatures).
6. **Report**, ranked by impact:
   - False negatives (installs the signature misses) are worse than false positives.
   - False positives: distro backports, later rebuilds of fixed builds.
   - Duplicates with other signatures in the same `Software` (expected or not).
   - Out of reach: what no signature can see (bundled copies, renamed binaries, Alpine, macOS).

## Checklist

- [ ] Outer XML well-formed; `Software@version` like `0.AFFECTED` / `0.any_version`.
- [ ] `uniqueId`s: lowercase, 36 chars, unique across the folder; new ones are v4.
- [ ] `created`/`modified` valid; `modified` bumped where a body changed.
- [ ] A leading comment, if present, has `ProductName` / `Release` equal to `<Software name>` /
      `@version`.
- [ ] Every CDATA body well-formed and passes the scanner XSS schema (level 3).
- [ ] Every `ReadFile` guarded by `FileExists` + `FileInfoCompare field="size"`.
- [ ] Crops of user-editable text also strip `&#13;`.
- [ ] `RpmProductInfo` uses `displayVersion` for versions; versions cropped to `X.Y.Z`.
- [ ] `MsiProductList` isn't filtered by name.
- [ ] `FindFilePathEx` doesn't rely on a symlink (e.g. Debian `/usr/bin/php`).
- [ ] Path-derived versions cropped `seekFrom="right"`, and values with `/` or `\` skipped.
- [ ] Exports `INSTALL_PATH`, `DETAILED_VER`, `IS_INSTALLED`; empty `DETAILED_VER` skipped.
- [ ] `IS_INSTALLED` block identical across the `Software`; ends with the exact skip string.
- [ ] Level 4 run on each target platform, with results recorded (container/host, version, result).
- [ ] Evidence is reachable: not under a default-excluded tree, and the searched names are ones
      the scan catalog actually searches for ([file-visibility.md](file-visibility.md)).
- [ ] An extended signature is warranted - a Package/File/template signature wouldn't do
      ([catalog.md](catalog.md)).
- [ ] Every CDATA body under 3829 characters (what BigFix Inventory imports), and under 4000
      as well if it is meant to be pasted into Catalog Customization
      ([catalog.md](catalog.md#body-length-limits)).
- [ ] A corrected detection method keeps its signature GUID; a retired one is deleted and
      replaced under a *new* GUID.
- [ ] No HCL files (scanner, `config/xss`, `config.xml`) in the change.

## After a merge

If another repository keeps a copy (e.g. jgstew/bigfix-content `scanner_signatures/`), keep the
two identical and update that copy's expected-results tables.

## Suggested CI (not yet implemented upstream)

- **lint** on every PR touching signatures: levels 1-2 plus the conventions (the linter covers these).
- **scanner** matrix: download the CIT bundle by pinned URL + SHA256 (cache by SHA256), one container
  per expected-results row, run `scanner_test.py`, compare JSON with a checked-in
  `tests/<signature file>.expected.json` (container -> `#n` -> `[DETAILED_VER, IS_INSTALLED]` for
  shipped and diag).
- **Windows** job on `windows-latest` with `install_cit.ps1` and the `FSScan` config above.
- Never commit HCL files; download them in CI.
