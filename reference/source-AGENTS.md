# scanner_signatures: BigFix Inventory and Scanner signatures (archived source)

> **Archived source snapshot - not skill guidance.**
>
> This is a verbatim copy of `scanner_signatures/AGENTS.md` from
> [jgstew/bigfix-content](https://github.com/jgstew/bigfix-content/blob/main/scanner_signatures/AGENTS.md)
> (The Unlicense), taken on 2026-11-16. It is kept for provenance and for the detail
> (per-container expected results, fixture recipes, CVE range decisions) that the skill
> summarizes rather than reproduces.
>
> **Follow [../SKILL.md](../SKILL.md) and the other files in this folder, not this one.** Where
> the two differ, the skill is the maintained version. Nothing in the skill depends on this file.
>
> Its body is unchanged apart from this banner and the title line above, so references to
> "this repository", "this folder" and "this file"
> mean the upstream `scanner_signatures/` folder, and its relative links (`install_cit.sh`,
> `install_cit.ps1`, `signature_harness.py`, `win_scanner_test.py`) point at files that live in
> [../scripts/](../scripts/) here. Section numbers below are the upstream document's own.

This document is the repository's reference for authoring, validating, and
testing BigFix Inventory (BFI) extended signatures evaluated by the BigFix
Scanner `wscansw` command. They are called **signatures** below.

The linked HCL public documentation is supporting material for product
workflows and terminology. Repository conventions and verified CIT behavior
are recorded here and scoped to the versions, platforms, and test setups where
they were observed. When this guide and public documentation differ, preserve
the scope of each claim and record the difference rather than treating a
supporting reference as an automatic override.

**Signatures** are expressions in XML following the BigFix Scanner XSS schema, enabling evaluation against the device file system and registry information to detect software existence or not existence. They are used in the BigFix Inventory catalog and BigFix CISA KEV.

Signature evaluation runs through the BigFix Scanner `wscansw` command and
requires a prepared file-system cache; file searches do not bypass the cache.
The cache path depends on the platform and configuration:

1. On Windows, the normal BigFix Scanner Service path uses the background,
   periodically updated FSMon cache.
2. Provider Cache 2 is used on other supported CIT platforms and is also
   available on Windows as a fallback or for testing. It builds a cache on
   demand from the catalog passed to `wscansw`; names absent from that catalog
   are not cached. If the file system changes or the catalog adds a new search
   name, use `wscanfs -reset` and run the scan to rebuild it. For signature
   tuning, reuse the cache when possible; setting `maxDataAge` to `0` forces a
   cache rebuild on each run.
3. Exclusions affect file visibility in both cache paths, but are configured
   separately: FSMon exclusions belong to the Scanner Service configuration;
   Provider Cache 2 exclusions belong to the scan configuration passed with
   `wscansw -c`.
4. macOS has no FileSystem Scan or extended-signature evaluation engine. The
   BigFix Scanner Service on macOS only runs the `bf-scanner` service.

| Platform/cache path | How file metadata becomes available |
|---|---|
| Windows BigFix Scanner Service (normal path) | FSMon maintains a reusable cache in the background. It periodically updates directory, file, path, and size metadata; configured FSMon exclusions (including default exclusions) are not visible to file searches. |
| Provider Cache 2 (other supported CIT platforms; Windows fallback/test path) | Built on demand from the catalog passed to `wscansw`; names absent from that catalog are not cached. `maxDataAge="0"` forces a rebuild on every run. When the file system changes, the catalog adds search names, or scan configuration changes, use `wscanfs -reset` and run the scan. |



The **signatures** should be wrapped into:
1. BigFix Scanner Catalog XML file with root element `Signatures`, used on the
   device, during signature validation, and for direct testing with `wscansw`.
2. BigFix Inventory Custom Catalog XML file with root `SoftwareIdentityCatalog` : used in BigFix Inventory as custom catalog content [bigfix/CommunityContent `Signatures/`](https://github.com/bigfix/CommunityContent/tree/main/Signatures).


The scanner-specific behavior and signature test results below were verified with the CIT scanner **11.0.44.0**
(`linux-x86_64_11.0.44.0.tgz`) on Debian 12, Ubuntu 24.04 and Rocky Linux 9
(amd64 containers), and with `w64-ix86_11.0.44.0.zip` on Windows Server 2022
(section 5.6), in October and November 2026. The Brotli files (section 9) were also run on
Debian 13 and unstable, Ubuntu 22.04, Rocky Linux 8, Fedora 42, Amazon Linux 2023,
openSUSE Leap 15 and Arch. Facts marked *(not verified)* weren't.

| File | What it detects |
|---|---|
| `software_PHP_all_Affected_by_CVE-2026-109618_and_CVE-2026-109619-0.AFFECTED.xml` | PHP affected by CVE-2026-109618 / CVE-2026-109619: 6 signatures (Windows `php.exe`, Linux `NEWS`, PHP source tree, Debian/Ubuntu dpkg, RPM, Windows `php-cgi.exe`). Sections 5.3 and 5.6. |
| `software_Node.js_all_Affected_by_CVE-2026-111497-0.AFFECTED.xml` | Node.js affected by CVE-2026-111497 (Brotli): 5 signatures (Windows `node.exe`, Windows MSI, `include/node/node_version.h` layouts, dpkg, RPM). Section 8. |
| `software_Node.js_ANY-0.any_version.xml` | Every Node.js found, with its version: the same 5 signatures, no version filter. Section 8. |
| `software_Electron_ANY-0.any_version.xml` | Electron (embeds Node.js), with the Electron version: 2 signatures (a macOS-layout framework `Info.plist` fixture tested on Linux, and an unpacked Electron distribution). The first is not a macOS endpoint detection. Section 8. |
| `software_Brotli_all_Affected_by_CVE-2026-111497-0.AFFECTED.xml` | Brotli (the library, CLI and Python package) affected by CVE-2026-111497: 5 signatures (dpkg, RPM, pip `dist-info`/`egg-info`, Arch pacman, root pip installs in the system `site-packages`), with distro fixed builds skipped. Section 9. |
| `software_Brotli_ANY-0.any_version.xml` | Every Brotli found, with its version: the same 5 signatures, no version filter and no fixed-build skip. Section 9. |

## BigFix Inventory Signature creation

When creating a signature for Software Asset Management, use the repository
guidance here and consult HCL's [Creating signatures](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/softinv/t_creating_catalog_entries.html)
and [catalog customization process](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/softinv/c_catalog_modeling_process.html)
as supporting references.


1. The server side signatures are available in the BigFix Inventory catalog and can be used in the custom catalog as well.
2. Confirm the software is missing from the current HCL catalog and identify the
   product and evidence to detect. Custom and HCL-provided catalogs are independent;
   duplicate signatures can report duplicate instances.
3. In **Management > Catalog Customization > New**, create the publisher and
   product. Package, File, and Extended signatures require a release number;
   Package Template and File Template signatures do not.
4. Choose the simplest signature type that can reliably identify the software:
   - **Package Template signature:** one package with an auto-detected version and
     optional files. **File Template signature:** one `.exe` with an auto-detected
     version and optional packages. Template-derived component versions are
     created when scans find new versions. A template component uses release `*`;
     only one template signature is allowed for it, and changing or deleting a
     template can recreate or remove its derived signatures, components, and
     discovery results. See [Template signature support](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/softinv/template-signature.html).
   - **Package or File signature:** specify package vendor/name/version or file
        name/version/size. Multiple packages or files within one selected condition
        are alternatives (any one can match); selecting both package and file
        conditions requires at least one match of each.
   - **Extended signature:** use when package/file rules are insufficient or
     detection needs additional data such as registry values, file contents,
     paths, or architecture. Create XML signature content and paste it into the
     entry. The supported schema version is 2.7 and the signature content must
     not exceed 4000 characters.
5. Use [HCL's component-signature guidelines](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/softinv/c_create_component_signatures.html)
   as supporting context:
   base detection on the software's main executable and combine it with package
   evidence when available. Prefer generic templates whenever possible. If a
   template is not possible, scope a signature to one release while allowing
   its mod-releases/fix packs where appropriate: use release wildcards, avoid
   volatile full file versions or file sizes unless they are meaningful, and
   use **Any size or version** when neither is a reliable discriminator.
6. After adding or correcting a signature, allow the updated catalog to reach the
   endpoint and complete the required scan / data import sequence.
7. When correcting a detection method, keep its signature GUID if existing
   discoveries should remain associated with it through the next catalog,
   scan, and import cycle. To retire a method, delete the old signature and
   add its replacement with a different GUID; removal is reflected through the
   normal catalog/scan/import cycle and is not guaranteed to be immediate.
8. File Template matching is limited to `.exe` files because their version
   metadata is Windows-specific; other platforms do not provide this
   executable metadata.
9. Package Templates can use other file extensions, but non-standard
   extensions are matched only when listed in Scanned File Data.
10. Package names can vary by platform; do not assume that a rule working on
    one operating system works identically on another.

### Extended-signature contract and operators

An extended signature is an expression made from **operands** (the values being
read) and **operators** (the operations combining them). Either can be scalar
(one string value) or vector (a set of strings). The supported Inventory schema
is version 2.7. Consult [Extended signature templates](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/softinv/r_extended_signatures.html)
for patterns and [Extended signature operators](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/softinv/r_extended_signatures_operators.html)
for the supported operands, operators, and attributes.

Inventory interprets these variables:

- `IS_INSTALLED` is mandatory and must evaluate to `true` when the product is
  detected/is expected to be reported in BFI and `false` otherwise.
- `INSTALL_PATH` is optional and supplies an installation path.
- `DETAILED_VER` is optional and supplies the component detailed version; the
  component release is taken from the catalog entry.

The local files in this folder follow the stricter repository convention of
exporting all three variables. In XSS, `Variable@export` defaults to `true`; set
it explicitly for internal variables and exported values to make intent clear.
`MultipleInstance` models software with multiple installations using an
`Iterator` and an `Instance`. `Condition` selects a variable to test, and
`Action do="SKIP"` drops a non-matching result. `And`, `Or`, and `Not` combine
conditions; `Compare` and `Contains` evaluate values; `Vector` combines vector
results and `VectorToScalar` converts a vector when a scalar expression is
required. `FindFilePathEx` returns a vector of paths.


`FindFilePathEx` searches the prepared file-system cache; it does not switch to
a direct file-system search. In Provider Cache 2, setting `maxDataAge` to `0`
forces a cache rebuild on each run. Its optional `filter` is applied to each
found file. The difference between this observed behavior and the wording in
HCL's operator reference is recorded in section 10.

Common HCL template patterns include:

| Detection goal | Template pattern |
|---|---|
| A named file exists | Compare `VectorToScalar(FindFilePathEx)` with an empty string. |
| All registry values match | Combine `RegKeyValueEqual` operands with `And`. |
| Any registry key/value matches | Combine `RegKeyValueEqual` operands with `Or`. |
| Report a registry version | Read the key into `DETAILED_VER`, then compare the required part of that value in `IS_INSTALLED`. |
| A file contains an identifier | Find the file, `ReadFile` its text, and apply a `Vector` filter to the contents. HCL notes that this reads text files, not binary files or archives such as `.jar`, `.ear`, or `.zip`. |
| Match package evidence | Use `PackageInfoMatch` with the package vendor, name, and version pattern. |

Treat examples on the HCL template page as patterns, not as a substitute for
checking the installed CIT XSS schema. In particular, the repository's tested
rules about `ReadFile`, provider availability, and individual operator edge
cases are version- and platform-specific.

### Manual test from HCL's [Testing manually page](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/planinconf/Testing_manually.html)

Prerequisite: BigFix Scanner must be installed on a supported endpoint where
the signature is defined. The example uses a Windows registry operand and is
Windows-specific.

1. Create `extended_signature_test.xml` containing only the signature being
   tested. HCL's example has a `<Signatures>` root and a `<Signature>` with
   `guid`, `name`, and `type="OtherSignature"`; its body contains an exported
   `IS_INSTALLED` variable.
2. Use the `runscanner.bat` / `runscanner.sh` wrappers to set the environment
   and run the scanner commands.
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

   **Important:** `-c` is not used, so the scanner uses the endpoint's default
   scan configuration and cache. Its configured exclusions still apply.

5. In `output.xml`, expect a `MatchedSignature` for each matching instance; no
   match produces no `MatchedSignature` element. Check `warning.xml` for errors.

This is distinct from the standalone container/SSH harness in section 5, which
wraps and runs repository catalog files without a BigFix client.

#### Windows Scanner Service (FSMon) configuration

The normal Windows Scanner Service path uses the background FSMon cache.
Configure its excluded directories through the service, not through the
Provider Cache 2 test XML:

1. Add an exclusion: `bf-scanner.exe config add FSMon.ExcludeDirectories <directory>`
2. Remove an exclusion: `bf-scanner.exe config remove FSMon.ExcludeDirectories <directory>`
3. Restart the service: `bf-scanner.exe service restart`
4. Allow time for the cache to refresh before testing.

The Windows provider selection is global. Use
`wscancfg.exe -s fscanner.provider provider_bfscanner` for the Scanner Service
provider or `wscancfg.exe -s fscanner.provider provider_cache2` for the
Provider Cache 2 fallback/test path. Use Provider Cache 2 when investigating
issues with the Scanner Service provider or when signature testing should wait
for Provider Cache 2 to build its catalog-scoped cache.

#### Standalone Provider Cache 2 test configurations

The following `FSScanner` configurations are for standalone `wscansw` tests
that pass the configuration with `-c`. They control the Provider Cache 2
test's scan scope and exclusions; they do not configure the Windows Scanner
Service's FSMon cache. Use `wscanfs -reset` when a test needs a fresh cache, and
reuse the cache during signature tuning when the file system and catalog search
names have not changed.

Windows:
```XML
<?xml version="1.0" encoding="UTF-8"?>
<IBM>
<CIT>
<XSE priority="low" version="1.0">
<Plugins>
<Plugin name="FSScanner">
<Attribute name="includeDirectory" value="$local::*"/>

<Attribute name="excludeDirectory" value="?:/System Volume Information/*"/>
<Attribute name="excludeDirectory" value="?:/$Recycle.Bin/*"/>
<Attribute name="excludeDirectory" value="?:/RECYCLER/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/System32/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/SysWOW64/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/winsxs/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/ServicePackFiles/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/installer/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/$NtUninstall/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/$NtServicePackUninstall*$/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/$hf_mig$/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/servicing/*"/>
<Attribute name="excludeDirectory" value="%CSIDL_WINDOWS%/SoftwareDistribution/*"/>
<Attribute name="excludeDirectory" value="*/Windows.old/*"/>
<Attribute name="excludeDirectory" value="?:/$WINDOWS.~BT/*"/>
<Attribute name="excludeDirectory" value="?:/Windows/servicing/*"/>
<Attribute name="excludeDirectory" value="?:/ProgramData/Docker/windowsfilter/*"/>
<Attribute name="excludeDirectory" value="?:/ProgramData/Package Cache/*"/>
<Attribute name="excludeDirectory" value="*/tmp/*"/>
<Attribute name="excludeDirectory" value="*/temp/*"/>
<Attribute name="excludeDirectory" value="*/cache/out-of-date/*"/>
<Attribute name="excludeDirectory" value="*/Temporary Internet Files/*"/>

<Attribute name="excludeGuestDirectories" value="true"/>
<Attribute name="maxDataAge" value="7200"/>
<Attribute name="provider" value="provider_cache2"/>
<Attribute name="maxQueryTime" value="43200"/>
<Attribute name="interruptOnTimeout" value="true"/>
<Attribute name="assumeAutoFS" value="remote"/>
<Attribute name="extensionToCache" value="*.exe"/>
<Attribute name="extensionToCache" value="*.sys"/>
<Attribute name="extensionToCache" value="*.com"/>
<Attribute name="extensionToCache" value="*.ear"/>
<Attribute name="extensionToCache" value="*.ocx"/>
<Attribute name="extensionToCache" value="*.swidtag"/>
<Attribute name="extensionToCache" value="*.slmtag"/>
<Attribute name="extensionToCache" value="*.gguf"/>
<Attribute name="extensionToCache" value="*.safetensors"/>
<Attribute name="extensionToCache" value="*.GGUF"/>
<Attribute name="extensionToCache" value="*.SAFETENSORS"/>
</Plugin>
</Plugins>
</XSE>
</CIT>
</IBM>
````



Linux:
```XML
<?xml version="1.0" encoding="UTF-8"?>
<IBM>
<CIT>
<XSE version="1.0">
<Plugins>
<Plugin name="FSScanner">
<Attribute name="includeDirectory" value="$local::*"/>

<Attribute name="excludeDirectory" value="/proc/*"/>
<Attribute name="excludeDirectory" value="*/tmp/*"/>
<Attribute name="excludeDirectory" value="*/eznim/*"/>
<Attribute name="excludeDirectory" value="*/unicore/lib/*"/>
<Attribute name="excludeDirectory" value="*/perl/lib/*"/>
<Attribute name="excludeDirectory" value="*/perl5/*"/>
<Attribute name="excludeDirectory" value="/usr/src/kernels/*"/>

<Attribute name="excludeDirectory" value="/var/opt/BESClient/LMT/CIT/docker/images/*"/>
<Attribute name="excludeDirectory" value="*/work/docker_scan/images/*"/>
<Attribute name="excludeDirectory" value="/var/lib/docker/*"/>
<Attribute name="excludeDirectory" value="/var/lib/containers*"/>
<Attribute name="excludeGuestDirectories" value="true"/>
<Attribute name="extensionToCache" value="*.sh"/>
<Attribute name="extensionToCache" value="*.bin"/>
<Attribute name="extensionToCache" value="*.pl"/>
<Attribute name="extensionToCache" value="*.ear"/>
<Attribute name="extensionToCache" value="*.SH"/>
<Attribute name="extensionToCache" value="*.BIN"/>
<Attribute name="extensionToCache" value="*.PL"/>
<Attribute name="extensionToCache" value="*.EAR"/>
<Attribute name="extensionToCache" value="*.swidtag"/>
<Attribute name="extensionToCache" value="*.slmtag"/>
<Attribute name="extensionToCache" value="*.gguf"/>
<Attribute name="extensionToCache" value="*.safetensors"/>
<Attribute name="extensionToCache" value="*.GGUF"/>
<Attribute name="extensionToCache" value="*.SAFETENSORS"/>
<Attribute name="maxDataAge" value="7200"/>
<Attribute name="provider" value="provider_cache2"/>
<Attribute name="maxQueryTime" value="43200"/>
<Attribute name="interruptOnTimeout" value="true"/>
<Attribute name="assumeAutoFS" value="remote"/>
</Plugin>
</Plugins>
</XSE>
</CIT>
</IBM>
```

### File visibility and cache behavior

An extended signature cannot match a file that is outside the configured scan
scope or inside a configured exclusion. Review the endpoint scan configuration
before changing a signature; exclusions in the configuration govern visibility.
See [manual scan configuration](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/planinconf/c_manual_scan_configuration.html)
and HCL's [Windows File System Monitoring Cache](https://help.hcl-software.com/bigfix/11.0/BigFix_Scanner/BigFix_Scanner/Configuration/file_system_monitoring_cache.html?hl=file%2Csystem%2Cmonitoring%2Ccache)
documentation.

This guide's observed behavior is that `FindFilePathEx` searches the prepared
cache on the tested CIT platforms; it does not search the file system directly.
The cache provider determines how the cache is built and refreshed. See the
provider-specific configuration guidance above and the public-documentation
difference recorded in section 10.

## 1. File format

A signature file has two layers.

### Outer layer: `SoftwareIdentityCatalog`

```xml
<?xml version="1.0" encoding="utf-8"?>
<SoftwareIdentityCatalog exportTimeStamp="2026-10-26T16:54:24Z">
   <Software name="..." vendor="..." uniqueId="<uuid>" version="0.AFFECTED">
    <Signature uniqueId="<uuid>" modified="<dateTime>" created="<dateTime>">
      <ExtendedSignature>
        <![CDATA[<MultipleInstance>...</MultipleInstance>]]>
      </ExtendedSignature>
    </Signature>
    <!-- more <Signature> elements: one Software can have many detection methods -->
   </Software>
</SoftwareIdentityCatalog>
```

Rules from the outer schema (`SoftwareIdentityCatalog.xsd`, see section 3):

- `Software@name`, `@vendor`: 1-250 characters, required. `@version`: required, and must match `([0-9]{1,18}\..*)|\*`. `0.AFFECTED`, `0.SAFE` and `0.any_version` are the usual pseudo-versions for vulnerability signatures.
- `uniqueId` (on `Software` and `Signature`): exactly 36 characters, lowercase `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`. New signatures get a new `uuid.uuid4()`. Time-based (version 1) IDs, like the ones BigFix Inventory exports and most of the PHP file's, are also valid, but they embed the generating machine's MAC address, so don't create new ones. Never reuse another signature's ID.
- `created` / `modified`: `xs:dateTime`, e.g. `2026-10-26T23:53:39Z`. Update `modified` whenever a signature's body changes.
- A `Signature` holds **either** a basic `<AND><OR><File .../></OR></AND>` (or `PackageFilter`) rule **or** one `<ExtendedSignature>`. All signatures here are extended.
- The outer schema types `ExtendedSignature` as "anything": **it doesn't check the CDATA at all.**
- HCL's Catalog Customization UI accepts Extended Signature XML using schema version 2.7 and limits the signature content to 4000 characters. That UI limit is separate from the outer `SoftwareIdentityCatalog` export schema.

### Inner layer: the CDATA body (the XSS signature language)

The CDATA is itself XML, in the scanner's signature language. It's parsed by
the scanner, so entities inside it work (`&#10;` is a newline). Its schema
ships with the scanner, in `<CIT>/config/xss/` (`signatures.xsd` plus
`coreplugin.xsd`, `fssplugin.xsd`, `regplugin.xsd`, `csplugin.xsd`,
`xmlplugin.xsd`), with namespace `http://www.ibm.com/Tivoli/Signatures`.
Those files and the scanner are **HCL-licensed: don't commit them here**.
Download them when needed (section 4.1).

Shape of a body:

```xml
<MultipleInstance>
  <Iterator export="true" name="INSTALL_PATH"> <!-- one Instance per value -->
    <Vector filter="*/usr/bin/"><FindFilePathEx appendFileName="false" name="php"/></Vector>
  </Iterator>
  <Instance>
    <Variable export="false" name="x"> ...expression... </Variable>
    <Condition withVariable="x"><Action do="SKIP" onValue="false"/></Condition>
    <Variable export="true" name="DETAILED_VER"> ... </Variable>
    <Variable export="true" name="IS_INSTALLED"> ...version-range test... </Variable>
    <Condition withVariable="IS_INSTALLED"><Action do="SKIP" onValue="false"/></Condition>
  </Instance>
</MultipleInstance>
```

- `export="true"` variables are reported for each instance that isn't skipped. HCL requires `IS_INSTALLED`; `INSTALL_PATH` and `DETAILED_VER` are optional. This repository convention exports all three.
- `Condition` + `Action do="SKIP" onValue="false"` (or `"true"`, or `""` for empty) drops the instance. Skip as early as possible: missing file, too large, wrong package.
- Variables are substituted as `$(NAME)` inside any attribute, including in the middle of strings: `absolutePath="$(INSTALL_PATH)../NEWS"`, `searchedString="Package: $(file_name)-cli"`.

## 2. Scanner behavior (verified local observations; platform-specific)

| Construct | Behavior |
|---|---|
| `FindFilePathEx name="..."` / `names="a,b"` | Returns a vector of matching paths from the prepared cache; it does not search the file system directly. Provider Cache 2 is built from names in the catalog passed to `wscansw`. Setting `maxDataAge="0"` forces a rebuild on every run. Normally reuse the cache while tuning a signature; use `wscanfs -reset` after the file system changes or the catalog adds search names. `appendFileName="false"` returns the folder; `"true"` returns the full path. |
| Cache visibility | Windows normally uses the Scanner Service's reusable, background-maintained FSMon cache. Provider Cache 2 is used on other supported CIT platforms and is available on Windows as a fallback/test path; it is built on demand from the catalog passed to `wscansw`. |
| `FindFilePathEx` and symlinks | In the tested Linux containers, symlinks were skipped: `name="php"` did not find Debian/Ubuntu `/usr/bin/php`, a symlink to `/etc/alternatives/php`; on RHEL the real file was found. Do not generalize this Linux observation to untested platforms. |
| `FindFilePathEx` on Windows standalone tests | In the `wscanfs` harness, `FSScan` scope must match the `wscansw` `FSScanner` plugin's `excludeDirectory` attributes in the same config. A mismatch made every file query return nothing in that test setup (section 5.6). This does not describe the deployed Scanner Service cache. |
| `FindFilePath name=... rootPath=...` | In the tested standalone `wscanfs` setup, queries the file index and is limited to `rootPath`; see the cache qualification above before applying this observation to other configurations. |
| `WinFileInfo absolutePath=... field="version"` | Windows file version, always 4 parts: `php.exe` 8.3.35 gives `8.3.35.0`, `node.exe` 22.23.3 gives `22.23.3.0`. `Compare type="version"` pads with zeros: `22.23.4.0` **eq** `22.23.4`, and `8.3.35.0` < `8.3.36`. |
| `MsiProductList filter="..."` | Windows Installer products. **`filter` matches the product code** (`{8077DB9D-...}`), not the name: `filter="Node.js"` and `"Node*"` return nothing. List them all and check `MsiProductInfo field="name"`. |
| `MsiProductInfo code=... field=...` | `name`, `version`, `vendor`, `installDir`, `installDate`. The Node.js MSI gives `version` `22.23.3` and an **empty** `installDir`. |
| `RegKeyValue key="HKEY_LOCAL_MACHINE\..." entry="..." section="64or32"` | Returns the value. A missing key or entry returns `""` and doesn't drop the instance. |
| `Vector filter="..."` | The pattern must match the **whole** string. `*/usr/bin/` matches the folder returned with `appendFileName="false"`. To filter full paths (`appendFileName="true"`), use `*/usr/bin/*`. |
| `FileExists`, `ReadFile`, `FileInfoCompare` | In the tested CIT versions, these operate on a specified path and do not require the cache's file index or a `FileMask`; they do not locate or enumerate files. They still cannot read outside endpoint permissions or applicable scan/configuration restrictions. |
| `ReadFile` safety | The repository convention is to verify existence and size before reading (`FileInfoCompare field="size"`). The 5120000-byte limit is a local safeguard, not an HCL schema requirement. |
| `ReadFile` on CRLF files | The `\r` is kept. A crop that ends at `&#10;` returns `4.2.2\r`, `Compare` fails and the instance is **dropped silently** in the shipped file. Any file a user can edit or upload can have CRLF endings (git `autocrlf`, ASCII-mode FTP), on Linux too. Crop at `&#13;` as well (section 3). |
| `StringCrop` | `startString`, `endString`, `inputString` are required, plus `seekFrom="left"` or `"right"`. Returns the text between the first `startString` and the next `endString`. `startString=""` crops from the beginning: `StringCrop endString="-" startString=""` on `8.2.35-1~deb12u1` gives `8.2.35`. Wrap it in `<VectorToScalar>` when the result is used as a scalar (the majority pattern). |
| `StringCrop`: separator not found | A `startString` that isn't there crops from the beginning; an `endString` that isn't there (or `""`) runs to the end. So `start=":" end=""` on `18.20.4+dfsg` returns it unchanged, and chained crops (`:`, `-`, `+`, `~`) are safe when a separator is absent. On a multi-line file, a missing `startString` returns the first line, so check with `Contains` first. |
| `StringCrop seekFrom="right"` | `startString="" endString="."` returns the text before the **last** `.`: `22.23.4.0` gives `22.23.4`, but `22.23.4` gives `22.23`. Use it only when the part count is known (`WinFileInfo` is always 4). `endString="include/node/"` on `/opt/node/include/node/` gives `/opt/node/`. With a non-empty `startString`, the crop starts at its **last** occurrence: `startString="rotli-" endString=".dist-info"` on `/srv/brotli-app/venv/.../Brotli-1.1.0.dist-info/` gives `1.1.0`, where `seekFrom="left"` gives `app/venv/.../Brotli-1.1.0`. |
| Cropping a version out of a path | A folder higher up the path can contain the same marker (`/srv/brotli-app/`), so crop with `seekFrom="right"`. Also skip results that still contain `/` or `\`: a `Vector filter` like `*/brotli-*-info/` also matches **every** `*-info` folder under such a parent (`pip-...`, `setuptools-...`). |
| `Contains inputString=... searchedString=... position="contains\|start\|end"` | Boolean. Takes **attributes**, not child elements. Several of them (or `Compare`s) can be combined in an `<Or>`/`<And>` inside one `Variable`. |
| `ValueOf value="$(a).$(b).$(c)"` | Joins variables (there's also `Concat`). |
| `Vector` with several children | Union: `<Vector><DpkgProductList filter="nodejs"/><DpkgProductList filter="libnode*"/></Vector>` iterates both. |
| A failing scalar expression | Drops the **whole instance** (with a "Scalar expression [...] failed" warning): e.g. `ReadFile` on a missing file, or `XmlValue`. That's why every `ReadFile` is guarded. |
| `XmlValue file=... xpath=...` | Failed on Apple XML plists (which have a `DOCTYPE` with an external DTD), with a simple `following-sibling` XPath. Use `ReadFile` + `StringCrop` instead. |
| An `<Instance>` with no children | Invalid: "Not enough children for [Instance]", and nothing matches. Probes need at least one `Variable`. |
| `DpkgProductList filter="php*-common" type="any"` | Native dpkg provider. Iterates **package names** (`php8.2-common`, `php-common`). Only installed packages: Debian's known-but-absent `libnode64`/`libnode72`/... aren't listed. A multiarch package installed for two architectures (`libbrotli1:amd64` + `libbrotli1:i386`) gives **one** instance. |
| `DpkgProductInfo code=... field=...` | `field` is one of `name`, `version`, `displayVersion`, `description`. `version` = dpkg version, e.g. `8.2.35-1~deb12u1`, `8.3.6-0ubuntu0.24.04.13`, metapackage `2:93`. |
| `RpmProductList filter="*php-common-*" type="any"` | Iterates **name-version-release.arch** strings (`php-common-8.0.30-8.el9_8.1.x86_64`), so a filter needs a trailing `-*` or `*`. A leading `*` works (it also matches Remi `php83-php-common-...`). The filter matches that whole string, so `*brotli-*` does **not** match SUSE's `libbrotlidec1-1.0.7-...`: add a second `RpmProductList` for names like that. |
| `RpmProductInfo field="version"` | **Returns `8.0.30.8.el9_8.1`** (version.release joined with a dot), which `Compare type="version"` **can't** handle. Use `field="displayVersion"` (`8.0.30-8.el9_8.1`) and crop at `-`. `displayVersion` **leaves out the epoch**: RHEL's `nodejs` is `1:16.20.2-8.el9_4` and gives `16.20.2-8.el9_4`. Other fields: `name`, `release`, `vendor`, `arch`, `installDir` (comma list, e.g. `/etc/,/usr/,/var/lib/`), `installDate`, ... |
| `Compare relation="lt\|le\|eq\|ne\|ge\|gt" type="version\|string\|cistring\|integer\|hex\|boolean"` | `version` compares dotted numbers. Feed it clean `X.Y.Z` (crop distro suffixes first). |
| A provider missing on the OS | E.g. `RpmProductList` on Debian or `DpkgProductList` on RHEL: a *warning* ("Vector expression [...] failed"). That signature matches nothing, and the others still run. This is expected. |
| `PackageInfoMatch name vendor version` | Boolean match against installed packages. Used by some CommunityContent signatures *(behavior not verified here)*. |

The complete element and attribute list is in the XSS schema (section 3, level 3).
When in doubt, write a probe signature that exports intermediate values
(section 4.3) instead of guessing.

## 3. Writing a signature

1. **Follow this repository's detection guidance** and use HCL's component-signature
   guidance as supporting context: prefer the main executable, combine it with
   package evidence when available, and identify one release while allowing
   supported mod-releases/fix packs. Use stable version fields and wildcarding
   rather than volatile full file versions or sizes.
2. **Choose evidence that can actually be read on the target platform.** Package databases, executable version resources, and small adjacent text files are common inputs, but platform, scan scope, exclusions, and cache configuration determine visibility.
3. **Make the version test identical across signatures of one software entry.** For vulnerability files in this repository, copy the `IS_INSTALLED` version-range test verbatim (or generate it) so detection methods use the same affected ranges.
4. **Crop versions to `X.Y.Z`** before `Compare type="version"` where appropriate: dpkg `8.3.6-0ubuntu0.24.04.13` becomes `8.3.6`, RPM `displayVersion` `8.0.30-8.el9_8.1` becomes `8.0.30`.
5. **Skip metapackages and non-matching names explicitly.** Debian's `php-common` is version `2:93`; skip it with `Compare relation="ne" type="string"`.
6. **Remember distro backports.** A version comparison flags Debian/Ubuntu/RHEL builds whose security fixes were backported into an old version number (e.g. RHEL 9 PHP `8.0.30`, Ubuntu `8.3.6`). Say so in the PR or description. A signature can't tell.
7. **One software entry can be reported by several signatures on one machine** (e.g. RHEL: the `NEWS` signature and the RPM signature both report PHP). Check for duplicates against both the custom and HCL-provided catalogs.
8. **Skip an empty `DETAILED_VER`** in inventory (`0.any_version`) files too. Otherwise an unparsed value is reported as an install: CommunityContent#56's first version reported `<?php`.
9. **Test old releases and odd formatting, not only the current release.** File formats change between releases: Enable Media Replace <= 3.4.0 has `Version: 3.3.0` without the ` * ` prefix that later releases use. For a text file, also test a CRLF copy and one with spaces instead of TABs.
10. **Validate and test** (sections 4 and 5) before publishing.

Templates (the first two from the PHP file; `<IS_INSTALLED block>` is the shared version-range test):

```xml
<!-- Debian/Ubuntu: dpkg package version -->
<MultipleInstance><Iterator export="false" name="PKG"><DpkgProductList filter="php*-common" type="any"/></Iterator><Instance>
<Variable export="false" name="not_meta"><Compare relation="ne" type="string"><ValueOf value="$(PKG)"/><ValueOf value="php-common"/></Compare></Variable><Condition withVariable="not_meta"><Action do="SKIP" onValue="false"/></Condition>
<Variable export="false" name="package_version"><DpkgProductInfo code="$(PKG)" field="version"/></Variable>
<Variable export="true" name="DETAILED_VER"><VectorToScalar><StringCrop endString="-" inputString="$(package_version)" seekFrom="left" startString=""/></VectorToScalar></Variable><Condition withVariable="DETAILED_VER"><Action do="SKIP" onValue=""/></Condition>
<Variable export="true" name="INSTALL_PATH"><ValueOf value="/usr/lib/php/"/></Variable>
<IS_INSTALLED block></Instance></MultipleInstance>

<!-- RPM: displayVersion, not version -->
<MultipleInstance><Iterator export="false" name="PKG"><RpmProductList filter="*php-common-*" type="any"/></Iterator><Instance>
<Variable export="false" name="package_version"><RpmProductInfo code="$(PKG)" field="displayVersion"/></Variable>
<Variable export="true" name="DETAILED_VER"><VectorToScalar><StringCrop endString="-" inputString="$(package_version)" seekFrom="left" startString=""/></VectorToScalar></Variable><Condition withVariable="DETAILED_VER"><Action do="SKIP" onValue=""/></Condition>
<Variable export="true" name="INSTALL_PATH"><RpmProductInfo code="$(PKG)" field="installDir"/></Variable>
<IS_INSTALLED block></Instance></MultipleInstance>
```

A `Version: X.Y.Z` line in a text header (e.g. a WordPress plugin's main `.php` file). The
crops take the first `Version:` line, remove a trailing CR, then keep what's after the last space
and after the last TAB. They handle ` * Version: `, a plain `Version: `, TABs and CRLF.
Verified on Linux and Windows with the CommunityContent#56 fixtures:

```xml
<MultipleInstance><Iterator export="true" name="INSTALL_PATH"><FindFilePathEx names="plugin.php"/></Iterator><Instance>
<Variable export="false" name="size"><FileInfoCompare absolutePath="$(INSTALL_PATH)plugin.php" field="size" relation="le" value="512000"/></Variable><Condition withVariable="size"><Action do="SKIP" onValue="false"/></Condition>
<Variable export="false" name="file_read"><ReadFile path="$(INSTALL_PATH)plugin.php"/></Variable>
<Variable export="false" name="version_line"><StringCrop endString="&#10;" inputString="$(file_read)" seekFrom="left" startString="Version:"/></Variable>
<Variable export="false" name="version_no_cr"><StringCrop endString="&#13;" inputString="$(version_line)" seekFrom="left" startString=""/></Variable>
<Variable export="false" name="version_no_space"><StringCrop endString="" inputString="$(version_no_cr)" seekFrom="right" startString=" "/></Variable>
<Variable export="true" name="DETAILED_VER"><StringCrop endString="" inputString="$(version_no_space)" seekFrom="right" startString="&#9;"/></Variable><Condition withVariable="DETAILED_VER"><Action do="SKIP" onValue=""/></Condition>
<IS_INSTALLED block></Instance></MultipleInstance>
```

If the file has no `Version:` line at all, `version_line` is the file's first line (section 2,
`StringCrop`), so require the marker with `Contains` first when that's possible.

## 4. Validation (four levels; run all of them)

The outer schema alone proves almost nothing: it never looks inside the CDATA.
A wrong element name, attribute or `field` value only shows up at levels 3-4.
HCL documents schema version 2.7 and a 4000-character maximum for signature
content entered through Catalog Customization; keep those constraints in mind
when authoring UI content as well as validating the exported XML.

### Level 1: outer schema

The schema is `SoftwareIdentityCatalog.xsd`. The same file is
CommunityContent's `.github/actions/validate-signatures-xsd/signature.xsd`
(identical), and it ships in the PyPI package `validate-bes-xml`:

```bash
XSD=$(uvx --from validate-bes-xml python -c "import validate_bes_xml, pathlib; print(pathlib.Path(validate_bes_xml.__file__).parent / 'schemas' / 'SoftwareIdentityCatalog.xsd')")
xmllint --nonet --noout --schema "$XSD" scanner_signatures/*.xml
```

### Level 2: every CDATA body is well-formed XML

```bash
python3 - scanner_signatures/*.xml <<'EOF'
import re, sys, xml.dom.minidom
for f in sys.argv[1:]:
    for i, body in enumerate(re.findall(r"<!\[CDATA\[(.*?)\]\]>", open(f, encoding="utf-8").read(), re.S), 1):
        xml.dom.minidom.parseString(body)
        print(f"{f}: signature {i} well-formed")
EOF
```

### Level 3: the scanner's own signature schema (XSS)

Wrap every body in the scanner's input document and validate it against
`<CIT>/config/xss/signatures.xsd`. This catches unknown elements, attributes and
`field`/`relation`/`type` values. The test harness (section 5.2) does this
automatically before scanning and exits 1 on failure. By hand:

```xml
<Signatures xmlns="http://www.ibm.com/Tivoli/Signatures" version="1.0">
  <Signature guid="<32 hex chars>"><Metadata><AnyMetadataTag>label</AnyMetadataTag></Metadata>
    <Platforms><Platform type="LINUX"/></Platforms>   <!-- WINDOWS, LINUX, AIX, SOLARIS, HPUX, ... -->
    <MultipleInstance>...the CDATA body...</MultipleInstance>
  </Signature>
</Signatures>
```

```bash
xmllint --nonet --noout --schema <CIT>/config/xss/signatures.xsd wrapped.xml
```

### Level 4: behavior with the real scanner (section 5)

The only level that proves the signature finds the software and extracts the right version.

### Repo hooks that also run

The `bigfix-content` pre-commit config runs `check-xml`, `trailing-whitespace`,
`end-of-file-fixer` and `codespell` on these files. `.github/workflows/pre-commit.yaml`
runs the same hooks on every PR with `--hook-stage manual`, which adds `fix-files-to-ascii`:
**non-ASCII characters (including in this file) fail CI**. `.github/workflows/xmlvalidate.yaml`
checks XML syntax. None of them check signature content.

## 5. Running and testing signatures

There are two distinct test workflows. The HCL manual endpoint procedure
described in the supporting-reference section above uses a BigFix client
installed on the target platform.
The standalone CIT harness below does not require a BigFix client or server; it
runs repository signatures in a container or a Windows test host.

### 5.1 Install the CIT scanner

Same bundle and `wcitinst` command as HCL's **Install or Upgrade Scanner (11.0.44.0)** task.
Works in any glibc x86_64 Linux. On Apple Silicon, use `--platform linux/amd64`
containers. An `aarch64` bundle exists too
(`linux-aarch64_11.0.44.0.tgz`, SHA256 `366df5cf2d15c757bcb20efc0b4adeeb4b3c241996afd64b65d8e232c1f57a76`) *(not tested)*.
Needs `curl`, `gzip`, `tar` and `sha256sum`.

The script is [`install_cit.sh`](install_cit.sh) in this folder. Run it inside the Linux machine or
container that will be scanned (`CIT_DIR` defaults to `/opt/cit`). Section 5.2 has an example.

Run a scanner with `LANG=C.UTF-8 LD_LIBRARY_PATH=$CIT_DIR/bin $CIT_DIR/bin/<wscanfs|wscansw> ...`
(this is what HCL's `runscanner.sh` does). `wscansw -?` and `wscanfs -?` print usage.

The installed tree (`$CIT_DIR`) is self-contained (it bundles its own `libstdc++`). Copying it
(`tar` it up, `docker cp`, untar) into another container with the target software
works. That's how the Ubuntu and Rocky tests below were run.

### 5.2 The test harness

`scanner_test.py` runs on the host (needs Python 3.9+, `docker`, `xmllint`) against a
running container that has the scanner and the software under test.

Before creating new containers, check `docker ps -a`: containers from earlier runs (e.g.
`php-debian`) may still be running with the scanner at `/opt/cit`, and can be reused as they are.

1. It wraps every signature twice: **shipped** (as written) and **diag** (with the
   `IS_INSTALLED` skip removed, so the extracted version shows even when it isn't affected).
   It removes the exact string `<Condition withVariable="IS_INSTALLED"><Action do="SKIP" onValue="false"/></Condition>`
   and warns on stderr when a signature doesn't contain it (its diag copy is then the same as shipped).
2. It validates them against the scanner's XSS schema (level 3).
3. It writes a Linux `FSScan` config. The bundled `bin/config.xml` is a Windows sample.
   The new config includes `/` (minus `/proc`, `/sys`, `/dev`, `/run`), with `FileMask`s
   taken from the signatures' own `FindFilePathEx` names.
4. It runs `wscanfs -reset`, `wscanfs`, then `wscansw`, and prints JSON results per signature.

Usage, from the repo root: `python3 scanner_signatures/scanner_test.py CONTAINER CIT_DIR SIGNATURE.xml [SIGNATURE.xml ...]`.
It prints one JSON object (label -> matched instances with their exported variables) and exits 1
if a signature body fails the scanner's own schema, or if `wscansw` writes no `sw.xml` (it deletes
the previous run's output first). The code it shares with `win_scanner_test.py` (signature
collection, the `FSScan` element, result parsing) is in [`signature_harness.py`](signature_harness.py).

Example (container `php-debian`, with the scanner installed at `/opt/cit`):

```bash
docker run -d --platform linux/amd64 --name php-debian debian:12 sleep infinity
docker cp scanner_signatures/install_cit.sh php-debian:/tmp/
docker exec php-debian sh -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends curl ca-certificates php-cli && sh /tmp/install_cit.sh'
python3 scanner_signatures/scanner_test.py php-debian /opt/cit scanner_signatures/software_PHP_*.xml
```

### 5.3 Expected results for the PHP file (verified)

`#n` is the signature's position in the file. A dash means no match.

| Container (PHP) | #2 Linux NEWS | #3 source tree | #4 dpkg | #5 RPM |
|---|---|---|---|---|
| Debian 12 `debian:12` + `php-cli` (8.2.35, **fixed**) | - | - | shipped -, **diag 8.2.35 / false** | - |
| Ubuntu 24.04 `ubuntu:24.04` + `php-cli` (8.3.6) | - | - | **8.3.6 / true** | - |
| Rocky 9 `rockylinux:9` + `php-cli` (8.0.30) | **8.0.30 / true** | - | - | **8.0.30 / true** |
| Debian 12 + a planted `/srv/build/php-src/main/php.h` and `../NEWS` with `21 Nov 2025, PHP 8.3.28` | - | **8.3.28 / true** | as above | - |

The Windows signatures #1 (`php.exe`) and #6 (`php-cgi.exe`) never match on Linux (`WinFileInfo`
is Windows-only; #6 was checked on the first Debian row). Their results are in section 5.6.

Expected warnings: `RpmProductList` failed (Debian/Ubuntu) and `DpkgProductList` failed (Rocky).

**Duplicates (expected).** One PHP install can be reported more than once, always with the same version:
- Windows: the official zip ships `php.exe` and `php-cgi.exe` in the same folder, so #1 and #6
  both match with the same `INSTALL_PATH`. #6 exists for folders that have only `php-cgi.exe`
  (standalone FastCGI / IIS handler deployments), which #1 misses.
- RHEL/Rocky: `NEWS` (#2) and the RPM (#5).

Whether BigFix Inventory merges these into one record on the server side wasn't checked
*(not verified)*. The scanner output contains every match.

### 5.4 Probing scanner behavior

To learn what an expression returns, write a signature that **exports every intermediate
variable** and has no `Condition`s, run it through the harness, and read the JSON. For example:

```xml
<MultipleInstance><Iterator export="true" name="PKG"><RpmProductList filter="php*" type="any"/></Iterator><Instance>
<Variable export="true" name="V"><RpmProductInfo code="$(PKG)" field="version"/></Variable>
<Variable export="true" name="DV"><RpmProductInfo code="$(PKG)" field="displayVersion"/></Variable>
</Instance></MultipleInstance>
```

That's how the symlink, `Vector filter` and `RpmProductInfo version` behaviors in section 2 were found.

### 5.5 Installing through the real BigFix task instead (optional)

[bigfix-actionscript-runner](https://github.com/jgstew/bigfix-actionscript-runner) can run
HCL's **Install or Upgrade Scanner (11.0.44.0)** `.bes` inside a container, with `qna` from the
BigFix client package unpacked into `/opt/BESClient` (`dpkg -x` into a temp folder; never into `/`,
which breaks Debian's `/lib` symlinks; [jgstew/bigfix-actionscript-runner#28](https://github.com/jgstew/bigfix-actionscript-runner/issues/28)
would remove that step). With the runner checkout mounted read-only, give `uv` a writable
environment: `UV_PROJECT_ENVIRONMENT=/opt/runner-venv uv run --frozen bigfix-actionscript-runner ...`.
Options used:

- `--no-preflight`: [jgstew/pre-commit-bigfix#54](https://github.com/jgstew/pre-commit-bigfix/issues/54) (false E302/E500 on indented `createfile` end markers).
- `--sandbox /tmp/bfsandbox --set '(parameter "scannerdatasfolder" as string) & "/" & computer id as string & "changeCacheAndLogsFolder.log"=>/tmp/bfsandbox/tools/scanner/1234567changeCacheAndLogsFolder.log'`: `computer id` needs a running client ([jgstew/bigfix-actionscript-runner#29](https://github.com/jgstew/bigfix-actionscript-runner/issues/29) asks for a built-in value).
- `--force` when the scanner is already installed: the task is then not relevant.
- `--execute`. The scanner then lives in `/opt/BESClient/tools/scanner/internal`, and `runscanner.sh /opt/BESClient <scanner> <args>` runs it.

The unmodified task works: the runner downloads every platform's top-level prefetches before
line 1 (like a client's cache; 27 files, 162 MB for this task), but places only the ones in branches that run.
On Debian 12 x86_64, only `linux-x86_64_11.0.44.0.tgz` and its `bzip2` reached `__Download`
(checked by SHA1, 2026-11-13, runner `df8b850`). Before
[jgstew/bigfix-actionscript-runner#8](https://github.com/jgstew/bigfix-actionscript-runner/issues/8)
was fixed, same-name prefetches overwrote each other, and the other platforms' lines had to be
removed from a copy of the task.

Use this to test the task itself. For testing signatures, section 5.1 is simpler.

### 5.6 Windows (verified)

Tested on Windows Server 2022 over SSH (PowerShell 5.1, run as an administrator). Send multi-line
scripts as `powershell -NoProfile -NonInteractive -EncodedCommand <base64 of the UTF-16LE script>`
to avoid quoting problems. The encoded command must fit cmd's 8191-character line limit (about a
3 KB script); split longer scripts into parts. All paths stay under one test folder.

**Install (verified).** The script is [`install_cit.ps1`](install_cit.ps1) in this folder: the same
steps as HCL's task, which extracts the bundle flat (`7za e`) and only adds its redistributable DLLs
when `api-ms-win-crt*` is missing from System32. It installs into `-T` (default `C:\bfi_sig_test`),
prints `wcitinst exit code: 0`, and throws if the exit code isn't 0. Check the exit code, not the
log `$T\installer\installCITlog.txt`: it ends with `Done.` even after a failed install (verified:
`RC: 11`, exit code 1, with `$T\cit` blocked by a file; the Linux `install.log` does the same). At about 2 KB it fits in one `-EncodedCommand`:

```bash
ssh <user>@<windows-host> "powershell -NoProfile -NonInteractive -EncodedCommand $(iconv -t UTF-16LE scanner_signatures/install_cit.ps1 | base64 | tr -d '\n')"
```

For another test folder, wrap the script in a script block and pass `-T` (use `printf`, not
`echo`: zsh's `echo` turns the `\b` of `C:\bfi...` into a backspace):

```bash
ssh <user>@<windows-host> "powershell -NoProfile -NonInteractive -EncodedCommand $({ printf '%s\n' '& {'; cat scanner_signatures/install_cit.ps1; printf '%s\n' "} -T 'C:\bfi_sig_test_other'"; } | iconv -t UTF-16LE | base64 | tr -d '\n')"
```

- `BFI-PRIVATE` installs a private copy. On a host that already had a system CIT 9.2.23
  (`%WINDIR%\cit\cit.ini`, from an existing BigFix client), `%WINDIR%\cit` was unchanged
  (same files and hashes before and after). Registry changes weren't checked.
- The private standalone Windows CIT test used `$T\cit\cache_data\__<user>` for
  local cache files. This is a test-install detail, not the Windows Scanner
  Service's FSMon cache model described above.
- To remove everything: `Remove-Item -Recurse -Force C:\bfi_sig_test`.

**Test fixture (verified):** the official
`https://windows.php.net/downloads/releases/archives/php-8.3.35-nts-Win32-vs16-x64.zip`
(SHA256 `25a8e2ac9ff30f1d768d1447c09a600617fa6e6082729f6e95f008b59c91fe45`), expanded into
`$T\php`. Its `php.exe` and `php-cgi.exe` have `FileVersion 8.3.35`, which is in the affected range.
For signature #6's standalone case, copy only `php-cgi.exe` into a second folder:
`New-Item -ItemType Directory -Force "$T\php_cgi_only"; Copy-Item "$T\php\php-cgi.exe" "$T\php_cgi_only\"`.

**Standalone `wscanfs` test config.** In this test setup, `wscansw` reads its file-search settings from the
`FSScanner` plugin in the same `config.xml`. The sample has
`<Attribute name="excludeDirectory" value="C:\dir_to_exclude"/>`. If the `FSScan` element
(`wscanfs`) doesn't exclude the same folders, `wscansw` decides the cached `C:\` tree doesn't match
(`traceCIT.log`: `FS_Cache2::executeQueryCacheOnlyEx - Existing tree for 'C:\' in the cache is not valid. Removing it, then recreating.`),
and **every `FindFilePathEx` returns nothing**. So the `FSScan` element must be:

```xml
<FSScan version="1.0" priority="normal"><IncludeDirectory value="C:\"/><ExcludeDirectory value="C:\dir_to_exclude"/>
  <FileMask value="php.exe"/><!-- one per FindFilePathEx name --><Age value="0"/><Timeout value="1800"/><OutputData value="BASIC"/></FSScan>
```

A real BigFix Inventory deployment writes its own scan configuration and
normally uses the Windows Scanner Service's FSMon cache. Provider Cache 2 can
also be selected on Windows as a fallback or for testing. Do not copy this
standalone `FSScan`/`FSScanner` recipe as a production cache configuration. The
`bf-scanner` service was not needed for these tests.

**Run:** `wscanfs.exe -c <config> -reset`, `wscanfs.exe -c <config> -o fs.xml`, then
`wscansw.exe -i <sigs> -c <config> -o sw.xml -e warn.xml`. Use `Start-Process -Wait` with
`-RedirectStandardOutput` and `-RedirectStandardError`. `wscansw -l MAX` writes a detailed trace
to stderr, and `$T\cit\logs\traceCIT.log` accumulates across runs. The `wscanfs` walk of `C:\` took
about 45 seconds. "path too long" messages for very deep folders are just skipped paths.

**Harness.** [`win_scanner_test.py`](win_scanner_test.py) (in this folder) does all of this from the
Mac/Linux side, the same way as `scanner_test.py`: shipped and diag copies, level-3 validation, a
config with the plugin's excludes copied into `FSScan`, `scp` both files to the test folder, run,
copy `sw.xml` back. `TESTDIR` is the Windows test folder holding the CIT install in `TESTDIR\cit`;
`XSS_DIR` is a local copy of the scanner's `config/xss` folder. Like `scanner_test.py`, it exits 1
if `wscansw` writes no `sw.xml`:

```bash
WINHOST=<user>@<windows-host> python3 scanner_signatures/win_scanner_test.py 'C:\bfi_sig_test' <local copy of CIT config/xss> scanner_signatures/software_PHP_*.xml
```

- **`WINHOST`:** if you use [bigfix-remote-client-relevance](https://github.com/jgstew/bigfix-remote-client-relevance),
  its inventory (`~/.bigfix/remote_clients.toml`) lists the SSH test hosts. Use the one with
  `transport = "ssh"` and `platform = "windows"`. The PHP fixture and a CIT install are in `C:\bfi_sig_test`.
- **A new test folder:** copying an existing `cit\` folder into it works, so a reinstall isn't
  needed (verified: `C:\bfi_sig_test\cit` copied to `C:\bfi_sig_test_wp\cit`).
- **`XSS_DIR`:** the Linux bundle's schema works for Windows signatures too (verified, level 3).
  Copy it out of any Linux test container: `docker cp php-debian:/opt/cit/config/xss <scratch>/xss`.

**Results for the PHP file** (fixture: `$T\php` and `$T\php_cgi_only`, above):

| What | Result |
|---|---|
| Signature #1 as shipped and diag, with the fixed config | **`C:\bfi_sig_test\php\` `8.3.35.0` / true**, plus other `php.exe` copies already on the host (8.3.35 / true, 8.3.36 / false in diag). `php_cgi_only\` isn't found (it has no `php.exe`) |
| Signature #6 as shipped and diag (2026-11-02) | **`C:\bfi_sig_test\php\` and `C:\bfi_sig_test\php_cgi_only\`, both `8.3.35.0` / true**, plus other `php-cgi.exe` copies already on the host (8.3.35 / true, 8.3.36 / false in diag) |
Node.js and Electron results on Windows are in section 8.4, and Brotli results in section 9.4.


## 6. CI (future)

Everything above runs unattended on a GitHub `ubuntu-latest` (x86_64) runner. Suggested jobs:

1. **lint** (fast, every PR touching `scanner_signatures/**`):
   - Level 1 (outer XSD via `validate-bes-xml`) and level 2 (CDATA well-formed).
   - Repo conventions: unique lowercase UUIDs across the whole folder, `modified` updated on changed signatures, a size guard before every `ReadFile`, and an identical `IS_INSTALLED` block within each file. Each is a short Python check.
2. **scanner** (behavior):
   - Download and verify the CIT bundle with section 5.1's pinned URL and SHA256. Cache it with `actions/cache`, keyed on the SHA256. Install it once on the runner, then `tar` the tree.
   - Use a matrix of containers, one per expected-results row: `debian:12`, `ubuntu:24.04`, `rockylinux:9`, each with the software installed and the scanner tree copied in (for Node, also the section 8.3 rows: official tarballs, NodeSource, the Rocky `nodejs:22` module). Run `scanner_test.py` in each; it also performs level 3.
   - Compare the JSON with a checked-in expectations file, e.g. `scanner_signatures/tests/<signature file>.expected.json`, mapping container to signature `#n` to `[DETAILED_VER, IS_INSTALLED]` for shipped and diag. Fail on any difference.
   - Fixtures that a package manager can't provide (e.g. a source tree) are planted by a small setup script per row.
3. **Never commit HCL files** (scanner binaries, `config/xss/*.xsd`, `config.xml`). Download them in CI.
4. **Windows:** a `windows-latest` job can install the scanner with section 5.6's verified
   PowerShell and run the signatures with the section 5.6 config (`FSScan` excludes matching the
   `FSScanner` plugin's), including `FindFilePathEx`. Fixtures: the PHP zip and the Node zips and
   MSI from section 8.4.
5. **Brotli:** the section 9.4 matrix (19 images, several of them in two states: patched and
   unpatched, or library-only). Fixtures a mirror can't provide (Ubuntu ESM builds, a patched SUSE
   build before the mirror has it) are dummy `.deb`/`.rpm` packages with the exact version
   strings, built with `dpkg-deb -b` / `rpmbuild -bb`.

## 7. Publishing to CommunityContent

CommunityContent keeps signatures as top-level `Signatures/*.xml`. Its PR workflow validates
them against `signature.xsd` (level 1 only). That job installs `libxml2-utils` with `apt` and can
fail on a DNS error before validating anything (seen on CommunityContent#56): read the log, and
re-run it if that's the cause. Run levels 2-4 here first, and keep the two copies identical. As of 2026-11-13, every file here is identical to CommunityContent `main`:

- PHP: includes signature #6 (`php-cgi.exe`), from
  [bigfix/CommunityContent#52](https://github.com/bigfix/CommunityContent/pull/52) (merged 2026-11-02).
- Brotli: the versions from
  [bigfix/CommunityContent#51](https://github.com/bigfix/CommunityContent/pull/51) (merged 2026-10-29).
- Node.js and Electron: unchanged.

### 7.1 Reviewing a CommunityContent PR

Changes also arrive the other way, as PRs to CommunityContent. To review one:

1. Fetch the PR's version of the file: `git fetch origin pull/<n>/head:pr<n>`, then
   `git show pr<n>:Signatures/<file> > <scratch>/<file>`.
2. Run levels 1-3 (section 4) on that copy, then level 4 with `scanner_test.py` and, for
   Windows signatures, `win_scanner_test.py`. Add a fixture for each new detection case, as
   with `php_cgi_only` above, plus the old-release and formatting cases from section 3.
   Use real releases from the vendor's archive: for WordPress plugins,
   `https://downloads.wordpress.org/plugin/<slug>.<version>.zip` (`api.wordpress.org` returned 403
   from the test machine). Test both sides of each version threshold.
3. Check the conventions in section 3: an identical `IS_INSTALLED` block across all signatures,
   new `uuid4` IDs, `modified` updated, an empty `DETAILED_VER` skipped, a newline at the end of
   each file, and duplicates with existing signatures noted.
4. After the merge, if this folder keeps that file, copy it here and update this file's tables
   and expected results.

## 8. Node.js and Electron

Three files share one design:

- `software_Node.js_all_Affected_by_CVE-2026-111497-0.AFFECTED.xml` (CVE)
- `software_Node.js_ANY-0.any_version.xml` (inventory)
- `software_Electron_ANY-0.any_version.xml`

The two Node files have the **same 5 detection bodies** and differ only in the `IS_INSTALLED` block.
All three use vendor `OpenJS Foundation`. They're meant to complement the YARA scan
(jgstew/tools `YARA/node/`), not replace it: see section 8.5 for what only YARA sees.

### 8.1 What they report

**CVE-2026-111497** (Brotli decoder out-of-bounds write). Source: the nodejs.org
"October 2026 security releases" advisory. It says the flaw "affects Node.js 26.x, 24.x, and
22.x", lists the releases 22.23.4, 24.22.1 and 26.12.1, and says "End-of-Life versions are
always affected when a security release occurs". As decided for this content, every end-of-life
line counts as affected:

| Affected (`IS_INSTALLED=true`) | Not affected |
|---|---|
| `< 22.23.4` (every older line, including 20.x and earlier) | `22.23.4`-`22.x` |
| `23.0.0`-`< 24.22.1` (all of 23.x) | `24.22.1`-`24.x` |
| `25.0.0`-`< 26.12.1` (all of 25.x) | `26.12.1` and later, including 27+ |

- **False positives are accepted, but false negatives must not increase.** So:
  - Very old Node with no Brotli support at all is also flagged.
  - Distro packages are compared by version number only. They may backport the fix, or build
    against the system Brotli library, so a flagged distro build (e.g. RHEL's `nodejs:22` module
    `22.23.2`) needs the distro's advisory *(not checked per distro)*.
- Versions are cropped to `X.Y.Z` before comparing, so a `22.23.4-rc.1` pre-release counts as fixed.
- **Electron isn't in the CVE file.** Electron builds Node against Chromium's Brotli *(reported in
  the reference YARA content; not verified here)*, so Node's fixed versions don't apply to it.

**Inventory** (`Node.js ANY`, `Electron ANY`, version `0.any_version`): every instance found,
`IS_INSTALLED` is `true` whenever `DETAILED_VER` isn't empty.

**Electron's embedded Node version isn't readable** without the YARA scan. The Electron version
is, and `https://releases.electronjs.org/releases.json` maps it to Node (its `node` field):
44.7.0 -> 24.21.0, 43.7.7 -> 24.21.0, 39.8.8 -> 22.22.1, 19.1.8 -> 16.14.2 (checked October 2026).

### 8.2 Detection methods

| # | Node.js | Evidence | `DETAILED_VER` | `INSTALL_PATH` |
|---|---|---|---|---|
| 1 | Windows `node.exe` (zip, MSI, any copy in the scan scope) | `FindFilePathEx name="node.exe"` + `WinFileInfo field="version"` | `22.23.3.0` cropped right at `.` -> `22.23.3` | folder of `node.exe` |
| 2 | Windows MSI from nodejs.org (also winget and Chocolatey, which run it *(not verified)*) | `MsiProductList` (all), keep `name` = `Node.js`; `MsiProductInfo field="version"` | `22.23.3` | `HKLM\SOFTWARE\Node.js` `InstallPath` (the MSI's `installDir` is empty) |
| 3 | Linux official layouts: tarball, nvm, `/usr/local` (Docker `node` images, `n`), NodeSource `.deb`. macOS Homebrew/`.pkg` layouts are Linux fixtures only; macOS has no signature engine. Also expected on supported Linux layouts that unpack the same tarball: fnm, Volta, asdf. | `FindFilePathEx name="node_version.h"` in `*/include/node/`, require `../../bin/node`, read it (4 KB) | `NODE_MAJOR_VERSION`.`MINOR`.`PATCH` | `<root>/bin/` |
| 4 | Debian/Ubuntu, NodeSource `.deb` | `DpkgProductList` `nodejs` + `libnode*`, skip `*-dev` | dpkg version minus epoch, `-...`, `+...`, `~...` | `/usr/` |
| 5 | RHEL/Rocky/Alma (appstream and modules), Fedora, NodeSource `.rpm`, `nodejs<NN>` names | `RpmProductList filter="nodejs*"`, skip names ending `-devel`, `-docs`, `-full-i18n`, `-packaging`, `-debuginfo`, `-debugsource` | `displayVersion`, cropped the same way | `RpmProductInfo installDir` |

| # | Electron | Evidence | `DETAILED_VER` | `INSTALL_PATH` |
|---|---|---|---|---|
| 1 | macOS-layout Electron framework fixture, tested on Linux only; not a macOS endpoint detection | `FindFilePathEx name="Info.plist"` in `*/Electron Framework.framework/Versions/*/Resources/`, `CFBundleVersion` from the XML plist | Electron version as written (`43.7.7`, GoTo's `39.8.8-29`) | the `.app` folder |
| 2 | Windows/Linux: an unpacked Electron distribution (`node_modules/electron/dist`, the release zips) | `FindFilePathEx name="LICENSES.chromium.html"`, require `electron` or `electron.exe` and a `version` file next to it | contents of `version` | that folder |

Why these:
- **The `node` binary itself isn't searched for.** It's 25-125 MB with the version only inside
  (`node.js/v<ver>`, which the scanner can't pattern-search), and distro `node` is a 26 KB
  launcher.
- **`node_version.h` has been in every official tarball checked** (8.17.0 to 26.12.1) and in
  Homebrew's Cellar. It's only 4 KB.
- **Requiring `../../bin/node`** keeps node-gyp's header caches (`~/.cache/node-gyp/<ver>/include/node`)
  out. Those are headers, not runtimes.
- **The Windows zips have no `include/`**, so signature #1 uses the version resource.
- **Packaged Electron apps on Windows/Linux** (VS Code, Slack, ...) have **no `version` file**
  (checked: the VS Code Linux build) and no other small file with a version, so they're out of
  reach (section 8.5).

### 8.3 Expected results on Linux (verified)

Scanner 11.0.44.0, `scanner_test.py`. Containers: `debian:12`, `ubuntu:24.04`, `rockylinux:9`, `node:24.10.0`
(amd64). Official builds were checked against each release's `SHASUMS256.txt`, and the Electron
zip against Electron's `SHASUMS256.txt`. The CVE column shows shipped `IS_INSTALLED`. The ones
marked false show only in the diag copy. The inventory file reports every row with
`IS_INSTALLED=true`.

**Header layouts** (Node #3), all in the Debian container:

| Fixture (planted) | `DETAILED_VER` | CVE |
|---|---|---|
| Official tarballs in `/opt/node-v<ver>-linux-x64`: 8.17.0, 16.20.2, 18.20.8, 20.20.2, 22.23.3, 23.11.1, 24.22.0, 25.9.0, 26.12.0 | same as the release | true |
| Official tarballs 22.23.4, 24.22.1, 26.12.1 | same | **false** (fixed) |
| nvm layout `/root/.nvm/versions/node/v22.23.3` (copy of the tarball) | 22.23.3 | true |
| `/usr/local/bin/node` + `/usr/local/include/node` (Docker image / `n` layout, 20.20.2) | 20.20.2 | true |
| Homebrew-style `/home/linuxbrew/.linuxbrew/Cellar/node/26.12.1/{bin,include}` (simulated with the official build) | 26.12.1 | false |
| Debian `libnode-dev` (`/usr/include/node` + `/usr/bin/node`) | 18.20.4 | true |
| Official Docker image `node:24.10.0` (amd64, its own container: `/usr/local/bin/node` + `/usr/local/include/node`) | 24.10.0 | true |
| node-gyp header cache `/root/.cache/node-gyp/24.22.0/include/node` (no `bin/node`) | no match | - |

**Packages** (Node #4 dpkg, #5 RPM):

| Container (packages) | Matches | CVE |
|---|---|---|
| Debian 12 + `nodejs` `18.20.4+dfsg-1~deb12u3`, `libnode108`, `libnode-dev` | #4: 2 * `18.20.4` (`nodejs`, `libnode108`; `-dev` skipped), #3: 1 * 18.20.4 (above) | true |
| Ubuntu 24.04 + `nodejs` `18.19.1+dfsg-6ubuntu5` (`libnode109`) | #4: 2 * `18.19.1` | true |
| Debian 12 + NodeSource 22.x `nodejs` `22.23.4-1nodesource1` | #4: `22.23.4`, #3: `22.23.4` (`/usr/include/node`) | false |
| Rocky 9 + `nodejs` `1:16.20.2-8.el9_4` (`nodejs-libs`, `nodejs-docs`, `nodejs-full-i18n`) | #5: 2 * `16.20.2` (`nodejs`, `nodejs-libs`) | true |
| Rocky 9 + module `nodejs:22` `1:22.23.2-2.module+el9.8.0+...` | #5: 2 * `22.23.2` | true (see backports, 8.1) |
| Rocky 9 + NodeSource 24.x `nodejs` `24.22.1-1nodesource` | #5: `24.22.1` | false |

**Electron**, in the Debian container:

| Fixture | Electron # | `DETAILED_VER` |
|---|---|---|
| macOS-layout framework `Info.plist` fixtures copied from VS Code and GoTo into a Linux test container under `/Applications/<app>.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/` (not macOS endpoint detections) | 1 | `43.7.7`, `39.8.8-29` (`INSTALL_PATH` `/Applications/<app>.app/`) |
| Official `electron-v44.7.0-linux-x64.zip` unpacked in `/opt/electron-44.7.0` and `/root/proj/node_modules/electron/dist` | 2 | `44.7.0` (both) |
| VS Code Linux build in `/opt/VSCode` (packaged app, no `version` file) | - | no match |

Expected warnings: the providers missing on each OS (`MsiProductList` "could not be resolved",
`RpmProductList`/`DpkgProductList` "failed").

### 8.4 Windows results (verified)

Windows Server 2022, scanner 11.0.44.0, `win_scanner_test.py` (section 5.6). Test folder
`C:\bfi_sig_test_node`, with a separate CIT install in `cit\`. Fixtures:

- **Zips:** official `node-v<ver>-win-x64.zip` (8.17.0, 20.20.2, 22.23.3, 24.22.1, 26.12.0),
  SHA256-checked against `SHASUMS256.txt`, in `node\`.
- **MSI:** `node-v22.23.3-x64.msi`, installed with
  `msiexec /i <msi> /qn ADDLOCAL=NodeRuntime INSTALLDIR=C:\bfi_sig_test_node\msi\nodejs\`
  (runtime only, no PATH change). This registers an Uninstall entry (`{8077DB9D-18D9-4DAF-8CA6-B8CAE42EB734}`, `Node.js`, publisher
  `Node.js Foundation`) and `HKLM\SOFTWARE\Node.js` (`InstallPath`, `Version`). It's left installed:
  remove it with `msiexec /x {8077DB9D-18D9-4DAF-8CA6-B8CAE42EB734} /qn`.
- **Electron:** `electron-v44.7.0-win32-x64.zip` (SHA256-checked), in `electron\`.

| Signature | Result |
|---|---|
| Node #1 `node.exe` | 6 instances: the 5 zips and the MSI copy, `DETAILED_VER` = release version (`WinFileInfo` `X.Y.Z.0` cropped). CVE: 24.22.1 false, the rest true |
| Node #2 MSI | `22.23.3`, `INSTALL_PATH` `C:\bfi_sig_test_node\msi\nodejs\`, CVE true |
| Node #3-#5 | no match (no such files or packages on Windows) |
| Electron #2 | `44.7.0`, `INSTALL_PATH` the unpacked zip |

### 8.5 What these signatures can't see (the YARA scan can)

| Case | Why it's out of reach | YARA (`YARA/node/node_detect.yar`) |
|---|---|---|
| Electron apps on Windows/Linux (VS Code, Slack, Teams, ...) | No small file with the Electron or Node version | `Node_Electron_Version`: Electron and embedded Node versions |
| Node version inside any Electron app (all platforms) | Only in the binary (`node.js/v<ver>`) | `Node_Electron_Version` |
| Node SEA (single-executable apps, e.g. GitHub Copilot CLI), vercel/pkg, nexe | One renamed executable, no headers | `Node_Runtime_Version` (`node.js/v`, or release URL + ABI symbol for pkg) |
| Node embedded as a library (Adobe `libnode.dylib`, VMware Fusion, Adobe's `*.node` runtime) | No headers or package | `Node_Runtime_Version` / `Node_Binary_Broad` |
| A bare `node` / `node.exe` copied without its `include/` (Linux/macOS), or renamed | Nothing readable next to it (Windows: only if named `node.exe`) | `Node_Runtime_Version` |
| Alpine (`apk`) packages, musl | No `apk` provider; the Linux CIT bundle is glibc-only | `Node_Runtime_Version` |
| Bun, Deno | Not Node.js; not detected (like the YARA rules, which report Bun only as `node unknown`) | `Node_Binary_Broad` |

Native addons (`*.node` in `node_modules`) aren't runtimes and aren't reported, as in the YARA
rules' version output.

### 8.6 Duplicates (expected)

One install can be reported more than once, always with the same version:
- dpkg `nodejs` + `libnode<ABI>`, and RPM `nodejs` + `nodejs-libs`, on the same machine.
- A NodeSource `.deb` or Debian `libnode-dev` adds signature #3 (`/usr/include/node`).
- On Windows, an MSI install is found by #1 (its `node.exe`) and #2.

### 8.7 Not tested
- winget/Chocolatey/Scoop installs; the 32-bit (`x86`) MSI; `nodejs<NN>` RPM names (SUSE, Amazon
  Linux 2023); Fedora; snap.
- A real BigFix Inventory deployment (all results here are from standalone CIT).

## 9. Brotli

Two files share one design:

- `software_Brotli_all_Affected_by_CVE-2026-111497-0.AFFECTED.xml` (CVE)
- `software_Brotli_ANY-0.any_version.xml` (inventory)

They have the **same 5 detection bodies**. They differ in the `IS_INSTALLED` block and in the
CVE file's fixed-build skip lists. Vendor `Google`. They cover the system library, the CLI and the
Python package. Node.js's embedded Brotli is covered by the Node files (section 8).

### 9.1 What they report

CVE-2026-111497 is the same Brotli decoder flaw as section 8. Affected (`IS_INSTALLED=true`):
`1.0.3`-`< 1.0.10`, `1.1.0`-`< 1.1.1`, `1.2.0`-`< 1.2.1`. These ranges match the Ubuntu and Debian
trackers, and the upstream fixes are tagged v1.0.10, v1.1.1 and v1.2.1.

Unlike the Node files, the CVE file **skips distro fixed builds** with an exact
`Compare type="string"` on the full package version. Sources (October 2026):

| Distro | Fixed builds skipped | Source |
|---|---|---|
| Debian | `1.0.9-2+deb12u1`, `1.1.0-2+deb13u1`, `1.2.0-4.1` (unstable) | security-tracker.debian.org |
| Ubuntu | `1.0.9-2ubuntu0.1`, `1.1.0-2ubuntu0.1`, `1.2.0-3ubuntu0.1`, `1.2.0-4ubuntu0.1`, ESM `1.0.7-6ubuntu0.1+esm1`, `1.0.3-1ubuntu1.3+esm1`, `1.0.3-1ubuntu1~16.04.2+esm1` | ubuntu.com/security |
| RHEL (and rebuilds) | `1.0.6-5.el8_10`, `1.0.6-4.el8_4.1`, `1.0.6-4.el8_6.1`, `1.0.6-4.el8_8.1`, `1.0.9-10.el9_8.1`, `1.0.9-6.el9_2.3`, `1.0.9-6.el9_4.3`, `1.0.9-7.el9_6.3`, `1.1.0-8.el10_2.1`, `1.1.0-6.el10_0.3` | `access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json` (`affected_release`) |
| SLE / openSUSE Leap 15 | `1.0.7-150200.3.8.1` | suse.com/security/cve |
| Amazon Linux 2023 | `1.1.0-1.amzn2023.0.2` | ALAS2023-2026-3334 |

- **An exact match misses later rebuilds** (Debian binNMU `+bN`, a newer RPM release), which are
  then flagged by version number (a false positive). Fedora and Arch aren't listed: Fedora 44 and
  Arch ship 1.2.1.
- SUSE's CVE page listed `1.0.7-150200.3.8.1` under "packages in QA", not as released, when
  checked on 2026-10-29. Recheck before relying on it.
- The Red Hat JSON is easier to parse than the HTML pages. SUSE's page also lists SUSE Liberty
  Linux (RHEL rebuild) builds, which matched Red Hat's.

### 9.2 Detection methods

| # | Evidence | `DETAILED_VER` | `INSTALL_PATH` |
|---|---|---|---|
| 1 | `DpkgProductList` `libbrotli1*`, `brotli`, `python3-brotli` | dpkg version up to the first `-`, then after any `:` | `/usr/lib/` |
| 2 | `RpmProductList` `*brotli-*`, `libbrotlidec1-*` and `python3*-Brotli-*`, keeping only names `libbrotli`, `brotli`, `libbrotlidec1`, `python3-brotli` and `python3*-Brotli` (SUSE) (so `-devel` and debuginfo are ignored) | `displayVersion` up to `-` | `RpmProductInfo installDir` |
| 3 | pip: `FindFilePathEx names="METADATA,PKG-INFO"` in `*/Brotli-*-info/`, `*/brotli-*-info/` and the `\` forms; skips `/usr/lib/python*` and `/usr/lib64/python*` (distro packages there are covered by #1/#2, root pip installs by #5) | crop `seekFrom="right"` after `rotli-`, then at `.dist-info`, `.egg-info` and `-py`; skip any value containing `/` or `\` | the `*-info` folder |
| 4 | Arch: `FindFilePathEx name="desc"` in `*/pacman/local/brotli-*` | crop after `/pacman/local/brotli-` up to `-` | the pacman DB folder |
| 5 | Root pip installs in the system `site-packages`: `FindFilePathEx name="INSTALLER"` in `/usr/lib/python*/` and `/usr/lib64/python*/` `Brotli-*-info/` / `brotli-*-info/`, kept only when `INSTALLER` starts with `pip` or `uv` (size-guarded `ReadFile`) | same as #3 | the `*-info` folder |

Why these:

- **The distro Python bindings are statically linked everywhere checked.** `ldd` on `_brotli*.so`
  shows no `libbrotli`, and the package doesn't require the library: Debian/Ubuntu `python3-brotli`
  (and the Debian `brotli` CLI), Rocky 8/9 and Fedora 42 `python3-brotli`, Amazon Linux 2023
  `python3-brotli`, SUSE `python3-Brotli` (`rpm -qR`). A host with only the bindings has the
  vulnerable decoder and no library package, so #1 and #2 list the Python package names too. On
  RHEL, `python3-brotli` comes from the same source package as `libbrotli`, so the fixed-build list
  applies. SUSE's `python-Brotli` is a separate source package (`1.0.7-1.6`), and SUSE lists no SLE
  15 fix for it (October 2026), so it's judged by version number.
- **pip wheels are self-contained** (`_brotli*.so` links no `libbrotli`), so they're reported
  separately from the system library.
- **`/usr/lib*/python*` is skipped by #3** so that a distro `python3-brotli` (Debian
  `Brotli-*.egg-info`, RPM `Brotli-X.Y.Z-pyN.M.egg-info`, Fedora `Brotli-*.dist-info`) is judged by
  the package signatures and their fixed-build lists, not by its version number alone.
- **But a root `pip install` also lands there** on some distros: Arch
  (`/usr/lib/python3.14/site-packages/brotli-1.2.0.dist-info`, with `--break-system-packages`) and
  openSUSE Leap 15 (`/usr/lib64/python3.6/site-packages/Brotli-1.0.9.dist-info`). Debian, Ubuntu,
  Fedora and RHEL use `/usr/local` for that. #5 catches these by the `INSTALLER` file that pip
  (`pip`) and uv (`uv`) write. Distro builds don't say `pip`: the egg-info ones have no `INSTALLER`,
  Fedora's dist-info has `rpm`, and Arch's `python-brotli` dist-info has none.

### 9.3 Duplicates (expected)

- dpkg: up to 3 instances per host (`libbrotli1`, `brotli`, `python3-brotli`), all from one source
  package and one version. RPM: `libbrotli` + `brotli` + `python3-brotli` (on SUSE,
  `python3-Brotli` has its own version).
- A `Brotli-X.dist-info` under a parent folder whose name contains `brotli-` is reported twice,
  because both the `Brotli-` and `brotli-` filters match the path.
- A host with both the package and pip installs reports each of them.

### 9.4 Expected results (verified)

`scanner_test.py` on amd64 containers and `win_scanner_test.py` on Windows Server 2022, at
CommunityContent `11bbbd6c` (every row was re-run there, or at `d08aea55` and then again at
`11bbbd6c` with the old and new files compared). "CVE" is the shipped CVE file. The inventory file reports every row,
including the skipped ones, with `IS_INSTALLED=true`.

| Host / fixture | CVE |
|---|---|
| `debian:12` unpatched `libbrotli1` `1.0.9-2+b6` | 1.0.9 / true |
| `debian:12` unpatched `brotli` + `python3-brotli` `1.0.9-2+b6` only (no `libbrotli1`) | 1.0.9 / true (*2) |
| `debian:12` patched `1.0.9-2+deb12u1`; venvs `Brotli-1.1.0`, `brotli-1.2.0`, `brotlicffi`; a copy of the `Brotli-1.1.0` venv under `/srv/brotli-app/` | package skipped; pip 1.1.0 *3, 1.2.0; `brotlicffi` and the other packages ignored |
| `debian:12` dummy packages `1.0.3-1ubuntu1~16.04.2+esm1`, `1.2.0-4.1`, `1.0.7-6ubuntu0.1+esm1` and a `1.0.7-6ubuntu0.1` control | fixed builds skipped; control 1.0.7 / true |
| `debian:13` unpatched `1.1.0-2+b7` (amd64 + i386) / patched `+deb13u1` | 1.1.0 / true (one instance) / skipped |
| `debian:sid` `1.2.0-4.1` (real packages) | skipped |
| `ubuntu:24.04` patched `1.1.0-2ubuntu0.1` / unpatched `1.1.0-2build2`, `python3-brotli` only | skipped / 1.1.0 / true |
| `ubuntu:22.04` patched `1.0.9-2ubuntu0.1` | skipped |
| `rockylinux:9` `libbrotli` `1.0.9-10.el9_8` (also with `brotli`, `python3-brotli`, `brotli-devel`) + pip `Brotli-1.1.0` in `/usr/local/lib64` | 1.0.9 / true, pip 1.1.0 / true; distro `Brotli-1.0.9-py3.9.egg-info` ignored |
| `rockylinux:9` unpatched `python3-brotli` `1.0.9-10.el9_8` only (no `libbrotli`), planted `/usr/lib64/.../Brotli-1.0.8.dist-info` (`INSTALLER` `rpm`), `/usr/lib/.../brotli-1.1.0.dist-info` (`uv`), `/usr/lib64/.../brotli-app/x/setuptools-69.0.dist-info` (`pip`) | #2 1.0.9 / true; #5 1.1.0 / true only. Upgraded to `el9_8.1`: #2 skipped |
| `rockylinux:9` patched `1.0.9-10.el9_8.1` / `rockylinux:8` patched `1.0.6-5.el8_10` | skipped / skipped |
| `fedora:42` `1.2.0-1.fc42` (`libbrotli`, `brotli`, `python3-brotli`) | 1.2.0 / true (*3; no fixed build listed); the `rpm` dist-info isn't reported by #5 |
| `amazonlinux:2023` unpatched `1.1.0-1.amzn2023.0.1` (`libbrotli`, `brotli`, `python3-brotli`) | 1.1.0 / true (*3) |
| `opensuse/leap:15` `libbrotlidec1` only, unpatched `1.0.7-150200.3.5.1`, plus a planted `/usr/local/lib/python3.6/site-packages/Brotli-1.0.7-py3.6.egg-info` | 1.0.7 / true (RPM), 1.0.7 / true (pip) |
| `opensuse/leap:15` patched `libbrotlidec1` `1.0.7-150200.3.8.1` (dummy RPM) | skipped |
| `opensuse/leap:15` `python3-Brotli` `1.0.7-1.6` with `libbrotlidec1` removed, + root `pip3 install Brotli==1.0.9` (`/usr/lib64/python3.6/site-packages/Brotli-1.0.9.dist-info`) | #2 1.0.7 / true, #5 1.0.9 / true (the PR's earlier `d08aea55` files: nothing) |
| `archlinux` `brotli-1.2.1-1` + planted `brotli-1.1.0-3`, `lib32-brotli-...`, `python-brotli-...` | 1.1.0 / true only |
| `archlinux` `brotli-1.2.1-1` + root `pip install --break-system-packages Brotli==1.2.0` (`/usr/lib/python3.14/site-packages/brotli-1.2.0.dist-info`) / pacman `python-brotli` `1.2.1-1` instead | #5 1.2.0 / true / nothing (no `INSTALLER`) |
| Windows: pip `Brotli-1.1.0`, `brotli-1.2.0` in `C:\bfi_sig_test_brotli\py\Lib\site-packages`, a copy under `...\brotli-app\Lib\site-packages`, and a planted `pip-24.0.dist-info` there | 1.1.0 *3, 1.2.0 *2; `pip` ignored |

Notes on the fixtures:

- Pin an unpatched Debian/Ubuntu build by removing the security and updates sources and
  installing `=<version>` (`apt-cache madison` lists them).
- Under amd64 emulation on Apple Silicon, `fedora:latest` (44) couldn't create directories
  ("Function not implemented"), so `fedora:42` was used.
- `amazonlinux:2023` and `opensuse/leap:15` need `tar` before the scanner tree can be copied in.

Expected warnings: the providers missing on each OS. There should be no `Scalar expression
[Compare] failed` warning. Before #51 that warning came from path fragments and `-pyN.M` versions.

### 9.5 Not covered / not tested

- **Bundled copies:** Node.js (section 8), Electron/Chromium, statically linked curl; also conda,
  vcpkg, Alpine (`apk`) and `brotlicffi` (its own version scheme).
- **Arch `python-brotli`** (statically linked, dist-info with no `INSTALLER`): skipped by #3 and
  #5, and #4 only reads `brotli-*`. Arch ships the fixed 1.2.1.
- **Legacy root `setup.py install` / egg-info** under `/usr/lib*/python*`: no `INSTALLER`, so not
  reported.
- **Not tested:** real Ubuntu Pro ESM systems (dummy packages only), arm64, RHEL itself (Rocky was
  used), a real BigFix Inventory deployment.

## 10. Repository guidance compared with HCL public documentation

This section records differences between repository-specific guidance or
observed behavior and HCL's public documentation. This file is the reference
for this repository; HCL links elsewhere in the guide support product
terminology and workflows. Local observations are limited to the versions,
platforms, and configurations stated in this document and should not be
generalized beyond them.

| Topic | Repository guidance / observed behavior | HCL public documentation |
|---|---|---|
| File lookup and cache | On the tested CIT versions, `FindFilePathEx` searches the prepared cache and does not search the file system directly. Provider Cache 2 setting `maxDataAge="0"` forces a cache rebuild on each run. | The operator reference describes cache or file-system lookup depending on configuration and describes `maxDataAge="0"` as direct file-system searching. That description does not match the behavior documented here; use the repository's cache procedure for this work. |
| Cache providers | Windows normally uses the Scanner Service's reusable FSMon cache. Provider Cache 2 is used on other supported CIT platforms and can be selected on Windows as a fallback or for testing. | HCL's File System Monitoring Cache page describes the Windows Scanner Service cache. The specific Provider Cache 2 scope here reflects repository testing and configuration. |
| Exported variables | This repository convention exports `IS_INSTALLED`, `INSTALL_PATH`, and `DETAILED_VER`. | HCL requires `IS_INSTALLED`; `INSTALL_PATH` and `DETAILED_VER` are optional. |
| Read size limits | The 5120000-byte `ReadFile` limit and existence/size guards are repository safeguards. | HCL's schema and operator documentation do not require that particular size limit. |
