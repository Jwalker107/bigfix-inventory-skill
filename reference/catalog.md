# BigFix Inventory catalog: signature types and the custom catalog

This page is the product side: choosing a signature type, what BigFix Inventory requires of an
extended signature, and how a signature reaches an endpoint. The XML details are in
[file-format.md](file-format.md); the scanner's behavior is in
[scanner-behavior.md](scanner-behavior.md).

## Before writing anything

1. **Confirm the software is missing from the current HCL catalog.** The custom catalog and the
   HCL-provided catalog are independent: a duplicate signature produces duplicate instances.
2. **Decide what evidence identifies the product**, and on which platforms. Package names vary
   by platform; a rule that works on one operating system may not work identically on another.
3. **Create the publisher and product** under **Management > Catalog Customization > New**.
   Package, File and Extended signatures require a release number. Package Template and File
   Template signatures do not.

## Choose the simplest type that identifies the software reliably

| Type | What it does | Notes |
| --- | --- | --- |
| **Package Template** | One package, version auto-detected, optional files | Component versions are created as scans find new versions. The template component uses release `*`; only one template signature is allowed for it. Non-standard file extensions match only when listed in Scanned File Data. |
| **File Template** | One `.exe`, version auto-detected, optional packages | Limited to `.exe`: the auto-detected version comes from Windows executable version metadata, which other platforms do not provide. |
| **Package or File** | Explicit package vendor/name/version, or file name/version/size | Several packages (or several files) inside one selected condition are alternatives - any one matches. Selecting both a package and a file condition requires at least one match of each. |
| **Extended** | An XSS expression evaluated by the scanner | Use when package/file rules are not enough, or detection needs registry values, file contents, paths or architecture. This is what the rest of this skill is about. |

Changing or deleting a template signature can recreate or remove its derived signatures,
components and discovery results, so treat template edits as higher-risk than an extended
signature edit. See HCL's
[Template signature support](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/softinv/template-signature.html).

HCL's [component-signature guidelines](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/softinv/c_create_component_signatures.html),
as supporting context: base detection on the software's main executable and combine it with
package evidence where available; prefer a generic template when one is possible. When a
template is not possible, scope the signature to one release while allowing its
mod-releases/fix packs - use release wildcards, avoid volatile full file versions or file
sizes unless they are meaningful, and choose **Any size or version** when neither is a reliable
discriminator.

## Extended signature constraints in the Catalog Customization UI

- The supported Inventory schema version is **2.7**.
- Signature content pasted into the UI **must not exceed 4000 characters**. This is a UI limit,
  separate from the exported `SoftwareIdentityCatalog` schema, which has no such limit. A body
  that exceeds it has to be split into more than one detection method, or simplified.
- `IS_INSTALLED` is **mandatory** and must be `true` exactly when the product should be reported.
  `INSTALL_PATH` and `DETAILED_VER` are optional in HCL's model; the convention used throughout
  this skill is to export all three.
- The component **release** comes from the catalog entry; `DETAILED_VER` supplies the detailed
  version.

## Operand and operator vocabulary

An extended signature is built from **operands** (values being read) and **operators**
(operations combining them). Either can be scalar (one string) or vector (a set of strings).
`Variable@export` defaults to `true` in XSS, so set it explicitly on internal variables to keep
the intent clear.

| Detection goal | Usual pattern |
| --- | --- |
| A named file exists | Compare `VectorToScalar(FindFilePathEx)` with an empty string |
| All registry values match | `RegKeyValueEqual` operands combined with `And` |
| Any registry key/value matches | `RegKeyValueEqual` operands combined with `Or` |
| Report a registry version | Read the key into `DETAILED_VER`, then compare the relevant part in `IS_INSTALLED` |
| A file contains an identifier | Find the file, `ReadFile` its text, apply a `Vector` filter to the contents. HCL notes this reads text files - not binaries or archives such as `.jar`, `.ear`, `.zip` |
| Match package evidence | `PackageInfoMatch` with package vendor, name and version pattern |

`MultipleInstance` models software with several installations via `Iterator` + `Instance`;
`Condition` selects a variable to test and `Action do="SKIP"` drops a non-matching result;
`And`/`Or`/`Not` combine conditions; `Compare` and `Contains` evaluate values; `Vector` unions
vector results and `VectorToScalar` converts one where a scalar is required.

Treat the examples on HCL's template page as patterns, not as a substitute for checking the
installed CIT XSS schema: the tested rules in [scanner-behavior.md](scanner-behavior.md) about
`ReadFile`, provider availability and individual operator edge cases are version- and
platform-specific.

## Getting a change onto endpoints

- After adding or correcting a signature, the updated catalog has to reach the endpoint and the
  scan / data import sequence has to complete before results change.
- **Keep a detection method's signature GUID** when existing discoveries should stay associated
  with it across the next catalog, scan and import cycle.
- **To retire a method**, delete the old signature and add its replacement with a *different*
  GUID. Removal is reflected through the normal catalog/scan/import cycle and is not guaranteed
  to be immediate.
- One software entry can legitimately be reported by several signatures on one machine (for
  example a file signature and a package signature on RHEL). Check for duplicates against both
  the custom and the HCL-provided catalog.

## HCL references

- [Creating signatures](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/softinv/t_creating_catalog_entries.html)
- [Catalog customization process](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/softinv/c_catalog_modeling_process.html)
- [Extended signature templates](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/softinv/r_extended_signatures.html)
- [Extended signature operators](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/softinv/r_extended_signatures_operators.html)
- [Template signature support](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/softinv/template-signature.html)
- [Component signature guidelines](https://help.hcl-software.com/bigfix/11.0/inventory/Inventory/softinv/c_create_component_signatures.html)
