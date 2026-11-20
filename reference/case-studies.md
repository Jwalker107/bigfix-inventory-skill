# Case studies

Design decisions from the signature sets in
[jgstew/bigfix-content `scanner_signatures/`](https://github.com/jgstew/bigfix-content/tree/main/scanner_signatures)
(also in bigfix/CommunityContent `Signatures/`). The CVE numbers are the ones in those files.
Use these as patterns; check the upstream files for the current versions before copying.
The full per-container expected results, fixture recipes and CVE-range reasoning behind these
summaries are in the archived [source-AGENTS.md](source-AGENTS.md) (sections 5, 8 and 9).
Two files are copied into [../examples/](../examples/): the PHP CVE file and the Electron
inventory file.

## PHP (`software_PHP_all_Affected_by_CVE-2026-109618_and_CVE-2026-109619-0.AFFECTED.xml`)

Six signatures: Windows `php.exe` (`WinFileInfo`), Linux `NEWS` file, a PHP source tree
(`main/php.h` + `../NEWS`), Debian/Ubuntu dpkg (`php*-common`, skip the `php-common` metapackage),
RPM (`*php-common-*`, `displayVersion`), Windows `php-cgi.exe` (standalone FastCGI/IIS folders that
have no `php.exe`).

Lessons:
- Debian's `/usr/bin/php` is a symlink, so file search can't find it; the dpkg signature covers it.
- Duplicates are expected: on Windows, `php.exe` and `php-cgi.exe` in one folder both match; on RHEL,
  `NEWS` and the RPM both match. Always the same version.
- Distro backports (RHEL 9 `8.0.30`, Ubuntu `8.3.6`) are flagged by version number.

## Node.js and Electron

Files: `software_Node.js_all_Affected_by_CVE-2026-111497-0.AFFECTED.xml`,
`software_Node.js_ANY-0.any_version.xml`, `software_Electron_ANY-0.any_version.xml`. Vendor
`OpenJS Foundation`. The two Node files share **the same 5 detection bodies** and differ only in
the `IS_INSTALLED` block: a good pattern for a CVE file + inventory file pair.

| # | Evidence | `DETAILED_VER` |
|---|---|---|
| 1 | Windows `node.exe` + `WinFileInfo` | 4-part version cropped right at `.` |
| 2 | Windows MSI: all `MsiProductList`, keep `name` = `Node.js`; path from `HKLM\SOFTWARE\Node.js` `InstallPath` (MSI `installDir` is empty) | `MsiProductInfo version` |
| 3 | `include/node/node_version.h` (4 KB; in every official tarball, nvm, `/usr/local`, Homebrew Cellar, NodeSource), requiring `../../bin/node` | `NODE_MAJOR_VERSION`.`MINOR`.`PATCH` |
| 4 | dpkg `nodejs` + `libnode*`, skip `*-dev` | minus epoch, `-`, `+`, `~` |
| 5 | `RpmProductList filter="nodejs*"`, skip `-devel`, `-docs`, `-full-i18n`, `-packaging`, `-debuginfo`, `-debugsource` | `displayVersion`, same crops |

Lessons:
- **Don't search for the big binary.** `node` is 25-125 MB with its version only inside; find a
  small file shipped next to it instead.
- **Require a sibling file to exclude look-alikes** (`../../bin/node` excludes node-gyp header caches).
- Policy decided for that content: false positives accepted, false negatives must not increase
  (every end-of-life line counts as affected; pre-release `-rc` versions crop to the fixed `X.Y.Z`).
- Electron: macOS framework `Info.plist` (`CFBundleVersion`, read with `ReadFile` + `StringCrop`
  because `XmlValue` fails on Apple plists), and unpacked distributions (`LICENSES.chromium.html` +
  `electron[.exe]` + a `version` file, cropped at `&#10;` and then at `&#13;` so a CRLF copy
  still compares). Packaged Electron apps on Windows/Linux have no readable version file and are
  out of reach.
- Out of reach for all signatures (a YARA scan can see these): Node embedded in Electron apps, Node
  SEA/pkg/nexe single executables, Node as a library, renamed binaries, Alpine.

## Brotli

Files: `software_Brotli_all_Affected_by_CVE-2026-111497-0.AFFECTED.xml`,
`software_Brotli_ANY-0.any_version.xml`. Vendor `Google`. Same 5 bodies in both.

| # | Evidence |
|---|---|
| 1 | dpkg `libbrotli1*`, `brotli`, `python3-brotli` |
| 2 | RPM `*brotli-*`, `libbrotlidec1-*`, `python3*-Brotli-*`, keeping only the exact package names (so `-devel` and debuginfo are ignored) |
| 3 | pip `METADATA`/`PKG-INFO` in `*/Brotli-*-info/` and `*/brotli-*-info/` (both slash forms), skipping `/usr/lib*/python*` |
| 4 | Arch pacman DB `*/pacman/local/brotli-*/desc` |
| 5 | Root pip installs in system `site-packages`: `INSTALLER` file starting with `pip` or `uv` |

Lessons:
- **Skipping distro fixed builds:** the CVE file skips exact full package versions taken from the
  distro trackers (Debian, Ubuntu incl. ESM, Red Hat's JSON `affected_release`, SUSE, Amazon Linux)
  with `Compare type="string"`. Later rebuilds aren't matched and show as false positives.
  Record the source and the date checked; recheck entries listed as "in QA".
- **Statically linked bindings:** the distro Python bindings don't link the system library, so the
  package signatures list the Python package names too.
- **Path cropping:** crop `seekFrom="right"` after `rotli-`, then at `.dist-info`/`.egg-info`/`-py`,
  and skip values containing `/` or `\` (a parent like `/srv/brotli-app/` matches the filter too).
- **Telling pip installs from distro installs** in the same folder: pip and uv write an `INSTALLER`
  file; distro packages don't say `pip`.
- Multiarch dpkg packages (amd64 + i386) give one instance.
- No `Scalar expression [Compare] failed` warnings should remain; they indicated path fragments
  and `-pyN.M` versions reaching `Compare`.
