# Scanner behavior

Verified with CIT 11.0.44.0. These behaviors decide whether a signature works. When in
doubt, write a probe signature ([testing.md](testing.md#probing-scanner-behavior)) instead of
guessing. The complete element and attribute list is in the scanner's XSS schema
(`<CIT>/config/xss/`).

## File search

| Construct | Behavior |
|---|---|
| `FindFilePathEx name="..."` / `names="a,b"` | Searches the **file index built by `wscanfs`**, not the disk. A name not in the scan config's `FileMask` list is never found. Wildcards work (`php*`). `appendFileName="false"` (default) returns the folder (`/usr/bin/`); `"true"` returns the full path (`/usr/bin/php8.2`). |
| `FindFilePathEx` and symlinks | **Symlinks are skipped.** `name="php"` never finds Debian/Ubuntu `/usr/bin/php` (a symlink to `/etc/alternatives/php`). On RHEL it's a real file and is found. |
| `FindFilePathEx` on Windows | Works only if the `FSScan` scope matches the `wscansw` `FSScanner` plugin's `excludeDirectory` attributes in the same config. Otherwise every file query returns nothing ([testing.md](testing.md#windows)). Most likely a test-setup issue only *(inferred)*. |
| `FindFilePath name=... rootPath=...` | Also queries the `wscanfs` index (needs `FileMask`), limited to `rootPath`. |
| `Vector filter="..."` | The pattern must match the **whole** string. `*/usr/bin/` matches a folder from `appendFileName="false"`. For full paths use `*/usr/bin/*`. |
| `Vector` with several children | Union: `<Vector><DpkgProductList filter="nodejs"/><DpkgProductList filter="libnode*"/></Vector>` iterates both. |
| `FileExists`, `ReadFile`, `FileInfoCompare` | Read the disk directly. No index or `FileMask` needed. |

## Reading files and strings

| Construct | Behavior |
|---|---|
| `ReadFile` | Always guard with `FileExists` and `FileInfoCompare field="size" relation="le" value="5120000"` (convention: 512 KB-5 MB). |
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

- **macOS has no signature engine.** HCL's "Install or Upgrade Scanner" task deploys only the
  `bf-scanner` service there, which has no signature support (checked 11.0.43.1). Extended
  signatures don't run on macOS endpoints. Whether BFI matches macOS software another way wasn't
  checked *(not verified)*.
- The Linux CIT bundle is glibc-only: no Alpine/musl, and there's no `apk` provider.
