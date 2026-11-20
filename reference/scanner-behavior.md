# Scanner behavior

These behaviors decide whether a signature works. When in doubt, write a probe signature
([testing.md](testing.md#probing-scanner-behavior)) instead of guessing. The complete element
and attribute list is in the scanner's XSS schema (`<CIT>/config/xss/`).

**Scope of these observations.** Verified with CIT **11.0.44.0**: the Linux x86_64 bundle on
Debian 12, Ubuntu 24.04 and Rocky Linux 9 (amd64 containers), and the Windows bundle on Windows
Server 2022, in October and November 2026. The Brotli work additionally covered Debian 13 and
unstable, Ubuntu 22.04, Rocky Linux 8, Fedora 42, Amazon Linux 2023, openSUSE Leap 15 and Arch.
Items marked *(not verified)* were not tested. Re-check when the scanner version changes, and
do not generalize a platform-specific observation to a platform that was not tested.

## File search

File searches read a **prepared file-system cache**, never the disk directly, and never fall
back to a direct search. Which cache, how it is built, and what is excluded from it is the
subject of [file-visibility.md](file-visibility.md) - read that before concluding a signature
is wrong because it found nothing.

| Construct | Behavior |
|---|---|
| `FindFilePathEx name="..."` / `names="a,b"` | Returns a vector of paths from the prepared cache. Under Provider Cache 2 the cache is built from the names the catalog passed to `wscansw` searches for, so a name no signature searches for is never cached; `maxDataAge="0"` forces a rebuild each run. Wildcards work (`php*`). `appendFileName="false"` (default) returns the folder (`/usr/bin/`); `"true"` returns the full path (`/usr/bin/php8.2`). An optional `filter` is applied to each file found. |
| `FindFilePathEx` and symlinks | In the tested Linux containers **symlinks were skipped**: `name="php"` did not find Debian/Ubuntu `/usr/bin/php` (a symlink to `/etc/alternatives/php`). On RHEL the real file was found. Don't generalize this to untested platforms. |
| `FindFilePathEx` in the standalone Windows harness | The `FSScan` scope must match the `wscansw` `FSScanner` plugin's `excludeDirectory` attributes in the same config. A mismatch made every file query return nothing in that test setup ([testing.md](testing.md#windows)). This describes the standalone harness, **not** the deployed Scanner Service cache. |
| `FindFilePath name=... rootPath=...` | In the tested standalone setup, queries the same cache, limited to `rootPath`. Check the cache qualification above before applying this elsewhere. |
| `Vector filter="..."` | The pattern must match the **whole** string. `*/usr/bin/` matches a folder from `appendFileName="false"`. For full paths use `*/usr/bin/*`. |
| `Vector` with several children | Union: `<Vector><DpkgProductList filter="nodejs"/><DpkgProductList filter="libnode*"/></Vector>` iterates both. |
| `FileExists`, `ReadFile`, `FileInfoCompare` | Operate on a given path: they need neither the cache nor a cached name, and they cannot locate or enumerate files. They still cannot read past endpoint permissions or applicable scan configuration restrictions. |

## Reading files and strings

| Construct | Behavior |
|---|---|
| `ReadFile` | Reads text files. HCL notes it is not for binaries or archives (`.jar`, `.ear`, `.zip`). Always guard with `FileExists` and `FileInfoCompare field="size" relation="le" value="5120000"` (convention: 512 KB-5 MB; the limit is a convention here, not a schema requirement). |
| `ReadFile` on CRLF files | The `\r` is kept. A crop ending at `&#10;` returns `4.2.2\r`; `Compare` fails and the instance is **dropped silently**. Files can have CRLF on Linux too (git `autocrlf`, ASCII-mode FTP). Also crop at `&#13;`. |
| `StringCrop` | `startString`, `endString`, `inputString` required, plus `seekFrom="left"` or `"right"`. Returns the text between the first `startString` and the next `endString`. `startString=""` crops from the beginning: `endString="-"` on `8.2.35-1~deb12u1` gives `8.2.35`. Wrap in `<VectorToScalar>` when used as a scalar. |
| `StringCrop`, separator not found | A missing `startString` crops from the beginning; a missing (or `""`) `endString` runs to the end. Chained crops (`:`, `-`, `+`, `~`) are safe when a separator is absent. On a multi-line file, a missing `startString` returns the **first line**: check with `Contains` first. |
| `StringCrop seekFrom="right"` | `startString="" endString="."` returns the text before the **last** `.`: `22.23.4.0` -> `22.23.4`, but `22.23.4` -> `22.23`. Use only when the part count is known (`WinFileInfo` is always 4). With a non-empty `startString`, the crop starts at its **last** occurrence. |
| Cropping a version out of a path | A higher folder can contain the same marker (`/srv/brotli-app/`): crop with `seekFrom="right"`, and skip results that still contain `/` or `\`. A filter like `*/brotli-*-info/` also matches every `*-info` folder under such a parent. |
| `Contains inputString=... searchedString=... position="contains\|start\|end"` | Boolean. Takes **attributes**, not children. Combine several (or `Compare`s) in `<Or>`/`<And>` inside one `Variable`. |
| `ValueOf value="$(a).$(b).$(c)"` | Joins variables (there's also `Concat`). |
| `XmlValue file=... xpath=...` | Failed on Apple XML plists (DOCTYPE with external DTD). Use `ReadFile` + `StringCrop`. |

## Packages and Windows data

| Construct | Behavior |
|---|---|
| `WinFileInfo absolutePath=... field="version"` | Windows file version, always 4 parts: `8.3.35` -> `8.3.35.0`. |
| `MsiProductList filter="..."` | **`filter` matches the product code** (`{8077DB9D-...}`), not the name: `filter="Node.js"` returns nothing. List all and check `MsiProductInfo field="name"`. |
| `MsiProductInfo code=... field=...` | `name`, `version`, `vendor`, `installDir`, `installDate`. `installDir` can be **empty** (Node.js MSI): read the install path from the registry instead. |
| `RegKeyValue key="HKEY_LOCAL_MACHINE\..." entry="..." section="64or32"` | Returns the value. A missing key or entry returns `""` and doesn't drop the instance. |
| `RegKeyValueEqual` | Boolean registry test; HCL's templates combine several with `And` (all must match) or `Or` (any matches). See [catalog.md](catalog.md#operand-and-operator-vocabulary). |
| `DpkgProductList filter="php*-common" type="any"` | Iterates installed **package names** (`php8.2-common`, `php-common`). A multiarch package installed for two architectures gives **one** instance. |
| `DpkgProductInfo code=... field=...` | `name`, `version`, `displayVersion`, `description`. `version` is the dpkg version (`8.2.35-1~deb12u1`, `8.3.6-0ubuntu0.24.04.13`, metapackage `2:93`). |
| `RpmProductList filter="*php-common-*" type="any"` | Iterates **name-version-release.arch** strings, so a filter needs a trailing `-*` or `*`. A leading `*` works. The filter matches the whole string: `*brotli-*` does **not** match `libbrotlidec1-1.0.7-...`, so add a second `RpmProductList`. |
| `RpmProductInfo field="version"` | **Returns `8.0.30.8.el9_8.1`** (version.release with a dot): unusable for `Compare type="version"`. Use `field="displayVersion"` (`8.0.30-8.el9_8.1`) and crop at `-`. `displayVersion` **omits the epoch** (`1:16.20.2-8.el9_4` -> `16.20.2-8.el9_4`). Other fields: `name`, `release`, `vendor`, `arch`, `installDir` (comma list), `installDate`. |
| `PackageInfoMatch name vendor version` | Boolean match against installed packages. Used by some CommunityContent signatures *(not verified)*. |

## Comparison and errors

| Construct | Behavior |
|---|---|
| `Compare relation="lt\|le\|eq\|ne\|ge\|gt" type="version\|string\|cistring\|integer\|hex\|boolean"` | `version` compares dotted numbers and pads with zeros: `22.23.4.0` **eq** `22.23.4`; `8.3.35.0` < `8.3.36`. Feed it clean `X.Y.Z`. |
| A failing scalar expression | Drops the **whole instance** ("Scalar expression [...] failed" warning): e.g. `ReadFile` on a missing file, `XmlValue`. |
| A provider missing on the OS | E.g. `RpmProductList` on Debian: a *warning* ("Vector expression [...] failed"). That signature matches nothing; the others still run. Expected. `MsiProductList` on Linux: "could not be resolved". |
| An `<Instance>` with no children | Invalid ("Not enough children for [Instance]"); nothing matches. |

## Platforms

- **macOS has no FileSystem Scan and no extended-signature engine.** The BigFix Scanner Service
  on macOS runs only the `bf-scanner` service, which has no signature support (checked
  11.0.43.1). Extended signatures don't run on macOS endpoints. Whether BFI matches macOS
  software another way wasn't checked *(not verified)*. See
  [file-visibility.md](file-visibility.md#macos).
- The Linux CIT bundle is glibc-only: no Alpine/musl, and there's no `apk` provider.

## Where this skill differs from HCL public documentation

HCL's documentation is the reference for product terminology and workflows; the rows below are
observations from the tested versions and configurations, which are the ones this skill's
procedures assume. Keep the scope of each claim rather than treating either side as an
automatic override.

| Topic | Observed here | HCL public documentation |
| --- | --- | --- |
| File lookup and cache | `FindFilePathEx` searches the prepared cache and does not search the file system directly. Under Provider Cache 2, `maxDataAge="0"` forces a cache rebuild each run. | The operator reference describes cache or file-system lookup depending on configuration, and describes `maxDataAge="0"` as searching the file system directly. |
| Cache providers | Windows normally uses the Scanner Service's reusable FSMon cache; Provider Cache 2 is used on other supported CIT platforms and can be selected on Windows as a fallback or for testing. | HCL's File System Monitoring Cache page describes the Windows Scanner Service cache; the Provider Cache 2 scope stated here comes from testing. |
| Exported variables | Convention here: export `IS_INSTALLED`, `INSTALL_PATH` and `DETAILED_VER`. | `IS_INSTALLED` is required; `INSTALL_PATH` and `DETAILED_VER` are optional. |
| `ReadFile` size limits | The 5120000-byte limit and the existence/size guards are safeguards adopted here. | HCL's schema and operator documentation do not require that limit. |
| Signature body length | BigFix Inventory imports at most **3829 characters** from one CDATA body; `scripts/lint_signatures.py` and `bes-signature-lint` (`E100`) enforce it. Source: jgstew/pre-commit-bigfix v2.5.0 *(not re-verified here)*. | HCL documents a 4000-character limit on content pasted into the Catalog Customization UI, and no limit at all in the exported catalog schema. |
