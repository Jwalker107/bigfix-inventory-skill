# Signature file format

A signature file has two layers: an outer `SoftwareIdentityCatalog` document, and inside each
`ExtendedSignature` a CDATA body written in the scanner's signature language (XSS).

## Outer layer: `SoftwareIdentityCatalog`

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

Rules from the outer schema (`SoftwareIdentityCatalog.xsd`):

- `Software@name`, `@vendor`: 1-250 characters, required.
- `Software@version`: required, must match `([0-9]{1,18}\..*)|\*`. The usual pseudo-versions
  for vulnerability content are `0.AFFECTED`, `0.SAFE` and `0.any_version` (inventory: every
  install, with its version).
- `uniqueId` (on `Software` and `Signature`): exactly 36 characters, lowercase,
  `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`.
  - New IDs: `uuid.uuid4()`.
  - Time-based (v1) IDs, like the ones BigFix Inventory exports, are valid but embed the
    generating machine's MAC address: don't create new ones.
  - Never reuse another signature's ID.
- `created` / `modified`: `xs:dateTime`, e.g. `2026-10-26T23:53:39Z`. Update `modified` when a
  signature's body changes.
- A `Signature` holds **either** a basic rule (`<AND><OR><File .../></OR></AND>` or
  `PackageFilter`) **or** one `<ExtendedSignature>`. All the reference content uses extended
  signatures.
- The outer schema types `ExtendedSignature` as "anything". **It doesn't check the CDATA.**

File naming used in CommunityContent and jgstew/bigfix-content:
`software_<Name>_<description>-<version>.xml`, e.g.
`software_Node.js_all_Affected_by_CVE-2026-111497-0.AFFECTED.xml`,
`software_Node.js_ANY-0.any_version.xml`.

## Inner layer: the CDATA body

The CDATA is XML in the scanner's signature language. The scanner parses it, so entities work
inside it (`&#10;` newline, `&#13;` CR, `&#9;` TAB, `&lt;`).

Its schema ships with the scanner in `<CIT>/config/xss/`: `signatures.xsd` plus
`coreplugin.xsd`, `fssplugin.xsd`, `regplugin.xsd`, `csplugin.xsd`, `xmlplugin.xsd`. Namespace
`http://www.ibm.com/Tivoli/Signatures`. These files are **HCL-licensed: don't commit them**.

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

- `export="true"` variables are reported for each instance that isn't skipped. Convention:
  export `INSTALL_PATH`, `DETAILED_VER` and `IS_INSTALLED`.
- `Condition` + `Action do="SKIP" onValue="false"` (or `"true"`, or `""` for empty) drops the
  instance. Skip as early as possible.
- Variables are substituted as `$(NAME)` in any attribute, also mid-string:
  `absolutePath="$(INSTALL_PATH)../NEWS"`, `searchedString="Package: $(file_name)-cli"`.
- An `<Instance>` must have at least one child.

The bodies are usually written on one line. When editing, keep that form so diffs stay
comparable with CommunityContent; pretty-print a scratch copy to read it.

## The scanner's input document (used for testing)

`wscansw -i` takes a different wrapper. The harness builds it from each CDATA body:

```xml
<Signatures xmlns="http://www.ibm.com/Tivoli/Signatures" version="1.0">
  <Signature guid="<32 hex chars>"><Metadata><AnyMetadataTag>label</AnyMetadataTag></Metadata>
    <Platforms><Platform type="LINUX"/></Platforms>   <!-- WINDOWS, LINUX, AIX, SOLARIS, HPUX, ... -->
    <MultipleInstance>...the CDATA body...</MultipleInstance>
  </Signature>
</Signatures>
```
