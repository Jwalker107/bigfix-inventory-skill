# Running and testing signatures

There are two distinct ways to run a signature:

1. **On an endpoint that already has the BigFix client and scanner** - HCL's manual procedure,
   below. It uses the endpoint's own scan configuration and cache.
2. **Standalone**, with no BigFix client or server - the rest of this page. The CIT scanner
   installs and runs on its own and `wscansw -i <file>` evaluates a signature file directly.
   The scripts are in [../scripts/](../scripts/).

Either way, what the scanner can see is governed by scan scope, exclusions and the file cache:
read [file-visibility.md](file-visibility.md) before concluding a signature is wrong.

Prerequisites on the host for the standalone harnesses: Python 3.9+, `xmllint` (libxml2), and
`docker` (Linux) or `ssh`/`scp` with key auth (Windows). On Windows hosts without `xmllint`, run
the harnesses from WSL or a Linux machine.

## Manual test on a real endpoint (HCL's procedure)

Prerequisite: BigFix Scanner installed on a supported endpoint where the signature applies.

1. Create `extended_signature_test.xml` holding only the signature under test: a `<Signatures>`
   root and a `<Signature>` with `guid`, `name` and `type="OtherSignature"`, whose body exports
   `IS_INSTALLED`.
2. Use the `runscanner.sh` / `runscanner.bat` wrappers, which set the environment and run the
   scanner commands.
3. Reset the file-system scanner:

   ```sh
   "/opt/BESClient/tools/scanner/runscanner.sh" "/opt/BESClient" wscanfs -reset
   ```

   ```bat
   "C:\Program Files (x86)\BigFix Enterprise\BES Client\tools\scanner\runscanner.bat" "c:\Program Files (x86)\BigFix Enterprise\BES Client" wscanfs.exe -reset
   ```

4. Run `wscansw` with the test catalog:

   ```sh
   "/opt/BESClient/tools/scanner/runscanner.sh" "/opt/BESClient" wscansw -i extended_signature_test.xml -o output.xml -e warning.xml
   ```

   ```bat
   "C:\Program Files (x86)\BigFix Enterprise\BES Client\tools\scanner\runscanner.bat" "c:\Program Files (x86)\BigFix Enterprise\BES Client" wscansw.exe -i extended_signature_test.xml -o output.xml -e warning.xml
   ```

   **`-c` is deliberately not passed**, so the scanner uses the endpoint's default scan
   configuration and cache - including its exclusions.

5. Expect one `MatchedSignature` in `output.xml` per matching instance; no match produces no
   `MatchedSignature`. Check `warning.xml` for errors.

HCL's own example is Windows-specific (it uses a registry operand). This procedure is separate
from the standalone harness below, which needs no BigFix client.

Reference:
[Testing manually](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/planinconf/Testing_manually.html).

## Install the CIT scanner (Linux)

`scripts/install_cit.sh`: same bundle and `wcitinst` command as HCL's **Install or Upgrade
Scanner (11.0.44.0)** task, SHA256-pinned. Run it **inside** the machine or container that will be
scanned (`CIT_DIR` defaults to `/opt/cit`). Works in any glibc x86_64 Linux; on Apple Silicon use
`--platform linux/amd64` containers. Needs `curl`, `gzip`, `tar`, `sha256sum`.

- An `aarch64` bundle exists (`linux-aarch64_11.0.44.0.tgz`, SHA256
  `366df5cf2d15c757bcb20efc0b4adeeb4b3c241996afd64b65d8e232c1f57a76`) *(not tested)*.
- Run a scanner by hand with
  `LANG=C.UTF-8 LD_LIBRARY_PATH=$CIT_DIR/bin $CIT_DIR/bin/<wscanfs|wscansw> ...`
  (what HCL's `runscanner.sh` does). `-?` prints usage.
- The installed tree is self-contained (bundles its own `libstdc++`): `tar` it, `docker cp` it into
  another container with the target software, untar. No reinstall needed.
- Check `wcitinst`'s exit code, not the log: the log ends with `Done.` even after a failure.
- When the download host changes or the scanner version moves past 11.0.44.0, update the URL and
  SHA256 in the script from HCL's current "Install or Upgrade Scanner" task.

## The Linux harness: `scripts/scanner_test.py`

Runs on the host against a running container that has the scanner and the software under test.
Keep `signature_harness.py` next to it.

1. Wraps every signature twice: **shipped** (as written) and **diag** (the exact string
   `<Condition withVariable="IS_INSTALLED"><Action do="SKIP" onValue="false"/></Condition>`
   removed, so the extracted version shows even when not affected). Warns on stderr when a
   signature lacks that string (diag is then the same as shipped).
2. Validates them against the scanner's XSS schema (level 3).
3. Writes a Linux `FSScan` config (the bundled `bin/config.xml` is a Windows sample): includes
   `/` minus `/proc`, `/sys`, `/dev`, `/run`, with `FileMask`s from the signatures'
   `FindFilePathEx` names.
4. Runs `wscanfs -reset`, `wscanfs`, then `wscansw`, and prints JSON: label -> matched instances
   with exported variables, plus warnings. Labels are `shipped:<file>#n` / `diag:<file>#n`, where
   `#n` is the signature's position in the file.

Exits 1 if a body fails the XSS schema, or if `wscansw` writes no `sw.xml`.

```bash
python3 scripts/scanner_test.py CONTAINER CIT_DIR SIGNATURE.xml [SIGNATURE.xml ...]
```

Example (Debian 12 with PHP):

```bash
docker ps -a        # reuse containers from earlier runs that already have /opt/cit
docker run -d --platform linux/amd64 --name php-debian debian:12 sleep infinity
docker cp scripts/install_cit.sh php-debian:/tmp/
docker exec php-debian sh -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends curl ca-certificates php-cli && sh /tmp/install_cit.sh'
python3 scripts/scanner_test.py php-debian /opt/cit examples/software_PHP_*.xml
```

Expected results for the PHP example (`#n` = signature position; `-` = no match):

| Container (PHP) | #2 Linux NEWS | #3 source tree | #4 dpkg | #5 RPM |
|---|---|---|---|---|
| Debian 12 + `php-cli` (8.2.35, fixed) | - | - | shipped -, diag 8.2.35 / false | - |
| Ubuntu 24.04 + `php-cli` (8.3.6) | - | - | 8.3.6 / true | - |
| Rocky 9 + `php-cli` (8.0.30) | 8.0.30 / true | - | - | 8.0.30 / true |
| Debian 12 + planted `/srv/build/php-src/main/php.h` and `../NEWS` with `21 Nov 2025, PHP 8.3.28` | - | 8.3.28 / true | as above | - |

Expected warnings: `RpmProductList` failed (Debian/Ubuntu), `DpkgProductList` failed (Rocky).
Windows signatures #1/#6 never match on Linux.

Fixture tips:

- Pin an unpatched Debian/Ubuntu build by removing the security and updates sources and installing
  `=<version>` (`apt-cache madison` lists them).
- Fixtures a package manager can't provide (source trees, ESM builds) can be planted files, or
  dummy `.deb`/`.rpm` packages with the exact version strings (`dpkg-deb -b`, `rpmbuild -bb`).
- Some images (`amazonlinux:2023`, `opensuse/leap:15`) need `tar` before the scanner tree can be
  copied in.
- Use real vendor releases for version fixtures, and test both sides of every threshold.

## Probing scanner behavior

To learn what an expression returns, write a signature that **exports every intermediate
variable** and has no `Condition`s, run it through the harness, and read the JSON:

```xml
<MultipleInstance><Iterator export="true" name="PKG"><RpmProductList filter="php*" type="any"/></Iterator><Instance>
<Variable export="true" name="V"><RpmProductInfo code="$(PKG)" field="version"/></Variable>
<Variable export="true" name="DV"><RpmProductInfo code="$(PKG)" field="displayVersion"/></Variable>
</Instance></MultipleInstance>
```

Wrap it in a minimal `SoftwareIdentityCatalog` file (any `Software`/`Signature` with valid IDs)
so the harness can read it. Probes need at least one `Variable` in the `Instance`. This is how
the symlink, `Vector filter` and `RpmProductInfo version` behaviors were found.

## Windows

Verified on Windows Server 2022 over SSH (PowerShell 5.1, as administrator).

**Install:** `scripts/install_cit.ps1` (same steps as HCL's task; installs a private
`BFI-PRIVATE` copy into `-T`, default `C:\bfi_sig_test`; throws if `wcitinst` fails). It fits in one
`-EncodedCommand`:

```bash
ssh <user>@<windows-host> "powershell -NoProfile -NonInteractive -EncodedCommand $(iconv -t UTF-16LE scripts/install_cit.ps1 | base64 | tr -d '\n')"
```

Another test folder (use `printf`, not `echo`: zsh's `echo` turns `\b` into a backspace):

```bash
ssh <user>@<windows-host> "powershell -NoProfile -NonInteractive -EncodedCommand $({ printf '%s\n' '& {'; cat scripts/install_cit.ps1; printf '%s\n' "} -T 'C:\bfi_sig_test_other'"; } | iconv -t UTF-16LE | base64 | tr -d '\n')"
```

Locally on Windows: `powershell -ExecutionPolicy Bypass -File scripts\install_cit.ps1 -T C:\bfi_sig_test`.

- A private install left an existing system CIT (`%WINDIR%\cit`) unchanged (registry not checked).
- Copying an existing `cit\` folder into a new test folder works; no reinstall needed.
- Remove everything: `Remove-Item -Recurse -Force C:\bfi_sig_test`.
- `-EncodedCommand` must fit cmd's 8191-character limit (about a 3 KB script).

**The one config setting that matters:** `wscansw` reads file-search settings from the
`FSScanner` plugin in `config.xml`, whose sample has
`<Attribute name="excludeDirectory" value="C:\dir_to_exclude"/>`. If the `FSScan` element doesn't
exclude the same folders, `wscansw` discards the cached `C:\` tree (`traceCIT.log`:
`Existing tree for 'C:\' in the cache is not valid`) and **every `FindFilePathEx` returns
nothing**. So:

```xml
<FSScan version="1.0" priority="normal"><IncludeDirectory value="C:\"/><ExcludeDirectory value="C:\dir_to_exclude"/>
  <FileMask value="php.exe"/><!-- one per FindFilePathEx name --><Age value="0"/><Timeout value="1800"/><OutputData value="BASIC"/></FSScan>
```

A fuller `FSScanner` plugin configuration, and the Windows provider selection
(`wscancfg.exe -s fscanner.provider provider_cache2` for this test path,
`provider_bfscanner` for the deployed Scanner Service), are in
[file-visibility.md](file-visibility.md). Don't copy a standalone test configuration into
production: a BigFix Inventory deployment writes its own, and the `bf-scanner` service was not
needed for these tests.

**Run by hand:** `wscanfs.exe -c <config> -reset`, `wscanfs.exe -c <config> -o fs.xml`,
`wscansw.exe -i <sigs> -c <config> -o sw.xml -e warn.xml` (use `Start-Process -Wait` with output
redirection). `wscansw -l MAX` traces to stderr; `$T\cit\logs\traceCIT.log` accumulates. A `C:\`
walk takes about 45 s.

**Harness:** `scripts/win_scanner_test.py` does all of this from a Linux/macOS host: shipped and
diag copies, level 3, a config with the plugin's excludes copied into `FSScan`, `scp` up, run, copy
`sw.xml` back.

```bash
WINHOST=<user>@<windows-host> python3 scripts/win_scanner_test.py 'C:\bfi_sig_test' <local copy of CIT config/xss> path/to/*.xml
```

PHP fixture: `https://windows.php.net/downloads/releases/archives/php-8.3.35-nts-Win32-vs16-x64.zip`
(SHA256 `25a8e2ac9ff30f1d768d1447c09a600617fa6e6082729f6e95f008b59c91fe45`) expanded into
`$T\php`; for the `php-cgi.exe`-only case, copy just `php-cgi.exe` into `$T\php_cgi_only`.
Expected: #1 finds `$T\php\` `8.3.35.0` / true; #6 finds both folders. Other copies already on the
host also show up.

## macOS

There's nothing to run: the macOS scanner (`bf-scanner`) has no signature engine (checked
11.0.43.1; its commands are `config`, `dex`, `export hwinventory`, `run`, `service`, `upgrade`).
macOS paths (e.g. `/Applications/<app>.app/...`) can only be tested by planting the files in a
Linux container, and only matter if a macOS endpoint ever runs CIT.

## Optional: through the real BigFix task

[jgstew/bigfix-actionscript-runner](https://github.com/jgstew/bigfix-actionscript-runner) can run
HCL's Install or Upgrade Scanner `.bes` inside a container (with `qna` unpacked into
`/opt/BESClient`; never `dpkg -x` into `/`). Use it to test the task itself; for signatures, the
direct install above is simpler.

## Safety

- These scripts download from `software.bigfix.com` and verify SHA256 before running anything.
- Run scans in disposable containers or dedicated test hosts/folders, not on production endpoints.
- Don't commit the scanner, its `config/xss` schemas, `config.xml`, or scan output.
