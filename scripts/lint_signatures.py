#!/usr/bin/env python3
"""Static checks for BigFix Inventory (BFI) software signature files.

    python lint_signatures.py [--xsd SoftwareIdentityCatalog.xsd] [--xss-dir CIT/config/xss]
                              [--json] [--no-warnings] SIGNATURE.xml [SIGNATURE.xml ...]

Checks (level numbers as in reference/validation.md):
  level 1  outer schema, when lxml is installed and a schema is given with --xsd or found in an
           installed validate_bes_xml package
  level 2  every ExtendedSignature CDATA body is well-formed XML
  level 3  bodies against the scanner's own XSS schema, with --xss-dir (needs lxml and the
           HCL-licensed CIT config/xss folder; never commit those files)
  plus     uniqueId format/uniqueness across all files, created/modified, Software attributes,
           repo conventions (guarded ReadFile, exported variables, empty-version skip, exact
           IS_INSTALLED skip string, identical IS_INSTALLED block per Software) and known scanner
           pitfalls (RpmProductInfo field="version", name filters on MsiProductList, XmlValue,
           newline crops without a CR crop, empty <Instance>), ASCII-only, final newline.

Signatures are numbered #n in file order, the same way scanner_test.py labels them.
Exit 0: no errors (warnings allowed). Exit 1: errors. Exit 2: bad usage or unreadable input.
Standard library only, except lxml for --xsd / --xss-dir.
"""

import argparse
import json
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
VERSION_RE = re.compile(r"^(([0-9]{1,18}\..*)|\*)$")
DATETIME_RE = re.compile(r"^-?\d{4,}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$")
IS_INSTALLED_SKIP = '<Condition withVariable="IS_INSTALLED"><Action do="SKIP" onValue="false"/></Condition>'
XSS_NS = "http://www.ibm.com/Tivoli/Signatures"
CDATA_RE = re.compile(r"<!\[CDATA\[(.*?)\]\]>", re.S)
EXPECTED_EXPORTS = ("INSTALL_PATH", "DETAILED_VER", "IS_INSTALLED")
SIZE_GUARD_MIN, SIZE_GUARD_MAX = 512000, 5120000


class Report:
    def __init__(self):
        self.findings = []

    def add(self, level, file, sig, msg):
        self.findings.append({"level": level, "file": file, "signature": sig, "message": msg})

    def error(self, file, sig, msg):
        self.add("error", file, sig, msg)

    def warn(self, file, sig, msg):
        self.add("warning", file, sig, msg)

    @property
    def errors(self):
        return [f for f in self.findings if f["level"] == "error"]


def parse_dt(value):
    if not value or not DATETIME_RE.match(value):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def check_uuid(rep, fname, sig, what, value, seen):
    if value is None:
        rep.error(fname, sig, f"{what} has no uniqueId")
        return
    if not UUID_RE.match(value):
        rep.error(fname, sig, f"{what} uniqueId {value!r} is not a 36-character lowercase UUID")
        return
    if value in seen:
        rep.error(fname, sig, f"{what} uniqueId {value} is also used by {seen[value]}")
    else:
        seen[value] = f"{fname} {sig or what}"
    if uuid.UUID(value).version == 1:
        rep.warn(fname, sig, f"{what} uniqueId {value} is time-based (v1, embeds a MAC address); "
                             "fine to keep, but new IDs should be uuid4")


def local(tag):
    return tag.rsplit("}", 1)[-1]


def is_installed_block(raw_body):
    """The raw text of the IS_INSTALLED Variable element (bodies never nest Variables)."""
    m = re.search(r'<Variable\b[^>]*\bname="IS_INSTALLED"[^>]*>.*?</Variable>', raw_body, re.S)
    return re.sub(r"\s+", " ", m.group(0)).strip() if m else None


def check_body(rep, fname, sig, raw_body):
    """Level 2 + conventions + pitfalls for one CDATA body. Returns the parsed root or None."""
    try:
        root = ET.fromstring(raw_body)
    except ET.ParseError as e:
        rep.error(fname, sig, f"CDATA body is not well-formed XML: {e}")
        return None
    if local(root.tag) != "MultipleInstance":
        rep.warn(fname, sig, f"body root is <{local(root.tag)}>, expected <MultipleInstance>")

    for inst in root.iter("Instance"):
        if len(inst) == 0:
            rep.error(fname, sig, "<Instance> has no children (scanner: 'Not enough children'; nothing matches)")

    exported = {v.get("name") for v in root.iter("Variable") if v.get("export") == "true"}
    exported |= {i.get("name") for i in root.iter("Iterator") if i.get("export") == "true"}
    missing = [n for n in EXPECTED_EXPORTS if n not in exported]
    if missing:
        rep.warn(fname, sig, f"does not export {', '.join(missing)} (convention: INSTALL_PATH, DETAILED_VER, IS_INSTALLED)")

    skips = {(c.get("withVariable"), a.get("onValue"))
             for c in root.iter("Condition") for a in c.iter("Action") if a.get("do") == "SKIP"}
    if "DETAILED_VER" in exported and ("DETAILED_VER", "") not in skips:
        rep.warn(fname, sig, 'no skip on an empty DETAILED_VER (<Condition withVariable="DETAILED_VER">'
                             '<Action do="SKIP" onValue=""/></Condition>)')
    if IS_INSTALLED_SKIP not in raw_body:
        rep.warn(fname, sig, "missing the exact IS_INSTALLED skip string; the test harness's diag copy "
                             "will equal the shipped copy")

    # Every ReadFile needs FileExists (or a size check, which also fails on a missing file) and a size guard.
    exists = {e.get("absolutePath") for e in root.iter("FileExists")}
    sizes = {}
    for e in root.iter("FileInfoCompare"):
        if e.get("field") == "size" and e.get("relation") in ("le", "lt"):
            sizes[e.get("absolutePath")] = e.get("value")
    for rf in root.iter("ReadFile"):
        path = rf.get("path")
        if path not in sizes:
            rep.error(fname, sig, f'ReadFile path="{path}" has no FileInfoCompare field="size" relation="le" guard on the same path')
        else:
            try:
                limit = int(sizes[path])
                if not SIZE_GUARD_MIN <= limit <= SIZE_GUARD_MAX:
                    rep.warn(fname, sig, f"ReadFile size guard {limit} is outside the convention ({SIZE_GUARD_MIN}-{SIZE_GUARD_MAX})")
            except (TypeError, ValueError):
                rep.warn(fname, sig, f"ReadFile size guard value {sizes[path]!r} is not an integer")
        if path not in exists and path not in sizes:
            rep.warn(fname, sig, f'ReadFile path="{path}" has no FileExists check')

    crops = list(root.iter("StringCrop"))
    if any(c.get("endString") == "\n" for c in crops) and not any(
            "\r" in (c.get("endString") or "") or "\r" in (c.get("startString") or "") for c in crops):
        rep.warn(fname, sig, "crops at a newline (&#10;) but never at a CR (&#13;); a CRLF file leaves "
                             "'\\r' in the value and the instance is dropped silently. Fine only for files known to be LF")

    for e in root.iter("RpmProductInfo"):
        if e.get("field") == "version":
            rep.warn(fname, sig, 'RpmProductInfo field="version" returns version.release joined by a dot '
                                 '(unusable for Compare type="version"); use field="displayVersion" and crop at "-"')
    for e in root.iter("MsiProductList"):
        f = e.get("filter")
        if f and not re.match(r"^[{*?]", f):
            rep.warn(fname, sig, f'MsiProductList filter="{f}" looks like a name; the filter matches product codes ({{GUID}})')
    if any(True for _ in root.iter("XmlValue")):
        rep.warn(fname, sig, "XmlValue failed on Apple plists (external DTD) and drops the instance when it fails; "
                             "consider ReadFile + StringCrop")
    for e in root.iter("Compare"):
        if e.get("type") == "version":
            for v in e.iter("ValueOf"):
                val = v.get("value") or ""
                if "$(" not in val and val and not re.match(r"^\d+(\.\d+)*$", val):
                    rep.warn(fname, sig, f'Compare type="version" against non-numeric literal {val!r}')
    return root


def load_lxml():
    try:
        from lxml import etree  # noqa: PLC0415
        return etree
    except ImportError:
        return None


def find_outer_xsd():
    try:
        import validate_bes_xml  # noqa: PLC0415
    except ImportError:
        return None
    p = Path(validate_bes_xml.__file__).parent / "schemas" / "SoftwareIdentityCatalog.xsd"
    return p if p.exists() else None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--xsd", type=Path, help="SoftwareIdentityCatalog.xsd for level 1 (needs lxml)")
    ap.add_argument("--xss-dir", type=Path, help="the scanner's config/xss folder for level 3 (needs lxml)")
    ap.add_argument("--json", action="store_true", help="print findings as JSON")
    ap.add_argument("--no-warnings", action="store_true", help="print errors only")
    args = ap.parse_args()

    rep = Report()
    notes = []
    etree = load_lxml()
    outer_schema = xss_schema = None
    xsd = args.xsd or find_outer_xsd()
    if xsd:
        if etree is None:
            notes.append("level 1 skipped: lxml is not installed (pip install lxml)")
        else:
            outer_schema = etree.XMLSchema(etree.parse(str(xsd)))
    else:
        notes.append("level 1 skipped: no --xsd and no validate_bes_xml package found")
    if args.xss_dir:
        if etree is None:
            notes.append("level 3 skipped: lxml is not installed (pip install lxml)")
        else:
            xss_schema = etree.XMLSchema(etree.parse(str(args.xss_dir / "signatures.xsd")))
    else:
        notes.append("level 3 skipped: no --xss-dir (or run scanner_test.py, which does it)")

    seen_ids = {}
    for path in args.files:
        fname = path.name
        try:
            data = path.read_bytes()
        except OSError as e:
            print(f"cannot read {path}: {e}", file=sys.stderr)
            return 2
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as e:
            rep.error(fname, None, f"not UTF-8: {e}")
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            bad = sorted({c for c in line if ord(c) > 127})
            if bad:
                rep.error(fname, None, f"line {lineno}: non-ASCII characters {''.join(bad)!r} (fail the repo CI)")
            if line != line.rstrip():
                rep.warn(fname, None, f"line {lineno}: trailing whitespace")
        if not text.endswith("\n"):
            rep.warn(fname, None, "no newline at end of file")

        try:
            doc = ET.fromstring(data)
        except ET.ParseError as e:
            rep.error(fname, None, f"outer XML is not well-formed: {e}")
            continue
        if outer_schema is not None:
            if not outer_schema.validate(etree.fromstring(data)):
                for err in outer_schema.error_log:
                    rep.error(fname, None, f"level 1 (outer XSD) line {err.line}: {err.message}")
        if doc.tag != "SoftwareIdentityCatalog":
            rep.error(fname, None, f"root element is <{doc.tag}>, expected <SoftwareIdentityCatalog>")

        bodies = CDATA_RE.findall(text)
        n = bi = 0   # n: Signature position (#n); bi: ExtendedSignature/CDATA position
        for sw in doc.iter("Software"):
            label = f"Software {sw.get('name')!r}"
            for attr in ("name", "vendor"):
                v = sw.get(attr)
                if not v or not 1 <= len(v) <= 250:
                    rep.error(fname, None, f"{label}: @{attr} must be 1-250 characters")
            ver = sw.get("version")
            if ver is None or not VERSION_RE.match(ver):
                rep.error(fname, None, f"{label}: @version {ver!r} must match ([0-9]{{1,18}}\\..*)|\\*")
            check_uuid(rep, fname, None, label, sw.get("uniqueId"), seen_ids)

            blocks = {}
            for s in sw.findall("Signature"):
                n += 1
                sig = f"#{n}"
                check_uuid(rep, fname, sig, "Signature", s.get("uniqueId"), seen_ids)
                created, modified = s.get("created"), s.get("modified")
                c, m = parse_dt(created), parse_dt(modified)
                if created is not None and c is None:
                    rep.error(fname, sig, f"created {created!r} is not an xs:dateTime")
                if modified is not None and m is None:
                    rep.error(fname, sig, f"modified {modified!r} is not an xs:dateTime")
                if c and m and (c.tzinfo is None) == (m.tzinfo is None) and m < c:
                    rep.error(fname, sig, f"modified {modified} is before created {created}")
                ext = s.find("ExtendedSignature")
                if ext is None:
                    rep.warn(fname, sig, "not an ExtendedSignature (basic rule); body checks skipped")
                    continue
                bi += 1
                if bi > len(bodies):
                    rep.error(fname, sig, "ExtendedSignature without a CDATA body")
                    continue
                raw = bodies[bi - 1]
                root = check_body(rep, fname, sig, raw)
                if root is not None and xss_schema is not None:
                    wrapped = (f'<Signatures xmlns="{XSS_NS}" version="1.0"><Signature guid="{uuid.uuid4().hex}">'
                               f'<Metadata><AnyMetadataTag>{fname}{sig}</AnyMetadataTag></Metadata>'
                               f'<Platforms><Platform type="LINUX"/></Platforms>{raw}</Signature></Signatures>')
                    if not xss_schema.validate(etree.fromstring(wrapped.encode("utf-8"))):
                        for err in xss_schema.error_log:
                            rep.error(fname, sig, f"level 3 (scanner XSS): {err.message}")
                blk = is_installed_block(raw)
                if blk:
                    blocks.setdefault(blk, []).append(sig)
            if len(blocks) > 1:
                groups = "; ".join(", ".join(v) for v in blocks.values())
                rep.error(fname, None, f"{label}: IS_INSTALLED blocks differ between signatures (groups: {groups}); "
                                       "every detection method should use the same version test")
        if bi != len(bodies):
            rep.warn(fname, None, f"{len(bodies)} CDATA sections but {bi} ExtendedSignature elements")

    shown = rep.errors if args.no_warnings else rep.findings
    if args.json:
        print(json.dumps({"notes": notes, "errors": len(rep.errors),
                          "warnings": len(rep.findings) - len(rep.errors), "findings": shown}, indent=1))
    else:
        for note in notes:
            print(f"note: {note}")
        for f in shown:
            where = f["file"] + (f" {f['signature']}" if f["signature"] else "")
            print(f"{f['level']}: {where}: {f['message']}")
        print(f"{len(rep.errors)} error(s), {len(rep.findings) - len(rep.errors)} warning(s) in {len(args.files)} file(s)")
    return 1 if rep.errors else 0


if __name__ == "__main__":
    sys.exit(main())
