# Writing a signature

## Before the first line of XML

- **Check the software isn't already in the HCL-provided catalog.** The custom catalog is
  independent of it, so a duplicate produces duplicate instances.
- **Check an extended signature is actually needed.** A Package, File, Package Template or File
  Template signature is simpler and is the right answer when package or file rules alone
  identify the software. [catalog.md](catalog.md) compares the types and lists what each one
  requires.
- **Check what the scanner can see on the target platform** - scan scope, exclusions and the
  file cache ([file-visibility.md](file-visibility.md)). Evidence under a temp directory, a
  container image store or an excluded system tree is invisible by default.
- **Keep a UI-pasted body under 4000 characters** (Inventory schema 2.7). Exported catalog
  files have no such limit, but a signature meant for Catalog Customization does.

## Rules

1. **Pick evidence the scanner can read without running the software**, in this order:
   - A package database: `DpkgProductList`/`RpmProductList` + `*Info`, Windows
     `MsiProductList` + `MsiProductInfo`. Reliable versions, no file search.
   - Version resources: `WinFileInfo absolutePath=... field="version"` on Windows.
   - A small version file next to the binary (`ReadFile` + `StringCrop`), size-guarded.
     Don't search for large binaries whose version is only inside them; the scanner can't
     pattern-search binaries.
2. **Make the version test identical across all signatures of one `Software`.** Write the
   `IS_INSTALLED` block once and copy it verbatim (or generate it).
3. **Crop versions to `X.Y.Z`** before `Compare type="version"`: dpkg `8.3.6-0ubuntu0.24.04.13`
   -> `8.3.6`, RPM `displayVersion` `8.0.30-8.el9_8.1` -> `8.0.30`. For dpkg, also remove an epoch
   (`2:`), and `+dfsg`/`~` suffixes when present.
4. **Skip metapackages and non-matching names explicitly.** Debian's `php-common` is version
   `2:93`: skip it with `Compare relation="ne" type="string"`. Skip `-dev`/`-devel`/`-docs`/
   `-debuginfo` packages when they aren't the software.
5. **Remember distro backports.** A version comparison flags Debian/Ubuntu/RHEL builds whose
   fixes were backported into an old version number. Either say so, or skip known fixed builds
   with an exact `Compare type="string"` on the full package version (see the Brotli case study),
   and note that later rebuilds (`+bN`, newer RPM release) then show as false positives.
6. **One `Software` can be reported by several signatures on one machine** (e.g. RHEL: a file
   signature and the RPM signature). Decide whether that's acceptable and document it.
7. **Skip an empty `DETAILED_VER`**, in inventory (`0.any_version`) files too. Otherwise an
   unparsed value is reported as an install (CommunityContent#56's first version reported `<?php`).
8. **Test old releases and odd formatting**, not only the current release. File formats change
   between releases. For text files, also test a CRLF copy and one with TABs vs spaces.
9. **Guard every `ReadFile`** with `FileExists` + `FileInfoCompare field="size" relation="le"`.
10. **Exclude look-alikes.** Example: requiring `../../bin/node` next to `include/node/node_version.h`
    keeps node-gyp header caches out.
11. **Validate and test** ([validation.md](validation.md), [testing.md](testing.md)) before publishing.

## Version-range test (`IS_INSTALLED`)

CVE file: true when the version is in an affected range. Inventory file (`0.any_version`): true
whenever `DETAILED_VER` isn't empty:

```xml
<Variable export="true" name="IS_INSTALLED"><Compare relation="ne" type="string"><ValueOf value="$(DETAILED_VER)"/><ValueOf value=""/></Compare></Variable><Condition withVariable="IS_INSTALLED"><Action do="SKIP" onValue="false"/></Condition>
```

For affected ranges, combine `Compare type="version"` elements in `<Or>`/`<And>` inside one
`Variable`. Copy the exact block from [../examples/](../examples/) (PHP file) rather than writing
it from scratch, and always end with the exact `IS_INSTALLED` skip string above.

## Templates

`<IS_INSTALLED block>` is the shared version-range test.

Debian/Ubuntu dpkg package:

```xml
<MultipleInstance><Iterator export="false" name="PKG"><DpkgProductList filter="php*-common" type="any"/></Iterator><Instance>
<Variable export="false" name="not_meta"><Compare relation="ne" type="string"><ValueOf value="$(PKG)"/><ValueOf value="php-common"/></Compare></Variable><Condition withVariable="not_meta"><Action do="SKIP" onValue="false"/></Condition>
<Variable export="false" name="package_version"><DpkgProductInfo code="$(PKG)" field="version"/></Variable>
<Variable export="true" name="DETAILED_VER"><VectorToScalar><StringCrop endString="-" inputString="$(package_version)" seekFrom="left" startString=""/></VectorToScalar></Variable><Condition withVariable="DETAILED_VER"><Action do="SKIP" onValue=""/></Condition>
<Variable export="true" name="INSTALL_PATH"><ValueOf value="/usr/lib/php/"/></Variable>
<IS_INSTALLED block></Instance></MultipleInstance>
```

RPM (`displayVersion`, not `version`):

```xml
<MultipleInstance><Iterator export="false" name="PKG"><RpmProductList filter="*php-common-*" type="any"/></Iterator><Instance>
<Variable export="false" name="package_version"><RpmProductInfo code="$(PKG)" field="displayVersion"/></Variable>
<Variable export="true" name="DETAILED_VER"><VectorToScalar><StringCrop endString="-" inputString="$(package_version)" seekFrom="left" startString=""/></VectorToScalar></Variable><Condition withVariable="DETAILED_VER"><Action do="SKIP" onValue=""/></Condition>
<Variable export="true" name="INSTALL_PATH"><RpmProductInfo code="$(PKG)" field="installDir"/></Variable>
<IS_INSTALLED block></Instance></MultipleInstance>
```

A `Version: X.Y.Z` line in a text header (e.g. a WordPress plugin's main `.php` file). The crops
take the first `Version:` line, remove a trailing CR, then keep what follows the last space and
the last TAB. They handle ` * Version: `, plain `Version: `, TABs and CRLF (verified on Linux and
Windows):

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

If the file has no `Version:` line, `version_line` is the file's first line, so require the
marker with `Contains` first when possible. (The template's size guard has no `FileExists`; the
file was just found by `FindFilePathEx`, but add one if the path is derived.)

Windows MSI, from `software_Node.js_ANY-0.any_version.xml` #2 (verified). `MsiProductList`'s
filter matches product codes, so list everything and check the name; the Node.js MSI's
`installDir` is empty, so the path comes from the registry:

```xml
<MultipleInstance><Iterator export="false" name="NODE_MSI_CODE"><MsiProductList type="any"/></Iterator><Instance>
<Variable export="false" name="is_node_msi"><Compare relation="eq" type="string"><MsiProductInfo code="$(NODE_MSI_CODE)" field="name"/><ValueOf value="Node.js"/></Compare></Variable><Condition withVariable="is_node_msi"><Action do="SKIP" onValue="false"/></Condition>
<Variable export="false" name="msi_version"><MsiProductInfo code="$(NODE_MSI_CODE)" field="version"/></Variable>
<Variable export="true" name="DETAILED_VER"><VectorToScalar><StringCrop endString="-" inputString="$(msi_version)" seekFrom="left" startString=""/></VectorToScalar></Variable><Condition withVariable="DETAILED_VER"><Action do="SKIP" onValue=""/></Condition>
<Variable export="true" name="INSTALL_PATH"><RegKeyValue entry="InstallPath" key="HKEY_LOCAL_MACHINE\SOFTWARE\Node.js" section="64or32"/></Variable>
<IS_INSTALLED block></Instance></MultipleInstance>
```

Windows version resource, from `software_Node.js_ANY-0.any_version.xml` #1 (verified).
`WinFileInfo` always returns 4 parts, so crop the last one:

```xml
<MultipleInstance><Iterator export="true" name="INSTALL_PATH"><FindFilePathEx appendFileName="false" name="node.exe"/></Iterator><Instance>
<Variable export="false" name="file_version"><WinFileInfo absolutePath="$(INSTALL_PATH)node.exe" field="version"/></Variable>
<Variable export="true" name="DETAILED_VER"><VectorToScalar><StringCrop endString="." inputString="$(file_version)" seekFrom="right" startString=""/></VectorToScalar></Variable><Condition withVariable="DETAILED_VER"><Action do="SKIP" onValue=""/></Condition>
<IS_INSTALLED block></Instance></MultipleInstance>
```

(The PHP file's `php.exe` signature #1 in [../examples/](../examples/) exports the 4-part version
uncropped and has no empty-version skip; `Compare type="version"` still works because it pads
with zeros, but the Node.js form is the cleaner pattern.)

Affected-range `IS_INSTALLED` block, from the PHP file (several ranges in one `<Or>`):

```xml
<Variable export="true" name="IS_INSTALLED"><Or><And><Compare relation="ge" type="version"><ValueOf value="$(DETAILED_VER)"/><ValueOf value="5.4.0"/></Compare><Compare relation="lt" type="version"><ValueOf value="$(DETAILED_VER)"/><ValueOf value="8.2.35"/></Compare></And><And><Compare relation="ge" type="version"><ValueOf value="$(DETAILED_VER)"/><ValueOf value="8.3.0"/></Compare><Compare relation="lt" type="version"><ValueOf value="$(DETAILED_VER)"/><ValueOf value="8.3.36"/></Compare></And></Or></Variable><Condition withVariable="IS_INSTALLED"><Action do="SKIP" onValue="false"/></Condition>
```

(Shortened to two ranges; the shipped block has four.)
