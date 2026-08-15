"""
Chain of custody, evidence preservation and the portable evidence package.

Everything observed is written to disk the moment it is observed, not at
the end of the run.  If the tool crashes, is killed, or loses network halfway
through, whatever was already collected remains intact and verifiable.

Layout of a case directory
--------------------------
    <case_id>/
        README_EVIDENCE.txt      how to verify this package
        case.json                case metadata + findings + tool provenance
        audit.jsonl              append-only, one JSON object per line
        manifest.json            every file, its size and its SHA-256
        MANIFEST.sha256          the single root hash of the manifest
        verify_evidence.py       standalone re-verification script
        exhibits/
            0001_apple.wloc/     one directory per HTTP transaction
                meta.json
                request.headers.txt
                request.body.bin
                response.headers.txt
                response.body.wire.bin      (as received, still compressed)
                response.body.decoded.*     (after Content-Encoding removal)
        artifacts/               scan results, resolved positions, the report
        exports/                 CSV / GeoJSON / KML

Integrity model
---------------
Each file is hashed with SHA-256.  The manifest lists `<sha256>  <relpath>`
for every file, sorted by path.  The root hash in MANIFEST.sha256 is the
SHA-256 of that sorted listing.  Changing any byte of any file, adding a file
or removing a file changes the root hash.  `verify_evidence.py` recomputes the
whole tree and reports precisely which files disagree.
"""

from __future__ import annotations

import datetime as dt
import getpass
import hashlib
import json
import os
import platform
import socket
import sys
import time
import uuid
import zipfile
from typing import Any, Dict, List, Optional

from . import TOOL_NAME, __version__
from .net import Exchange, _decode_body

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def local_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="microseconds")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _slug(text: str, limit: int = 40) -> str:
    keep = [c if (c.isalnum() or c in "._-") else "_" for c in text]
    return "".join(keep)[:limit].strip("_") or "item"


def _looks_textual(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    printable = sum(1 for b in sample if b in _PRINTABLE)
    return printable / len(sample) > 0.90


def _text_extension(data: bytes, content_type: str) -> str:
    ct = (content_type or "").lower()
    head = data[:200].lstrip()
    if "xml" in ct or head.startswith(b"<?xml") or head.startswith(b"<"):
        return ".xml"
    if "json" in ct or head[:1] in (b"{", b"["):
        return ".json"
    if "html" in ct:
        return ".html"
    return ".txt"


class Case:
    """One investigation.  Owns its directory and its chain of custody."""

    def __init__(self, root: str, case_id: Optional[str] = None,
                 examiner: str = "", organisation: str = "",
                 reference: str = "", notes: str = ""):
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.case_id = case_id or "CASE-%s-%s" % (stamp, uuid.uuid4().hex[:6].upper())
        self.dir = os.path.join(root, self.case_id)
        self.exhibits_dir = os.path.join(self.dir, "exhibits")
        self.artifacts_dir = os.path.join(self.dir, "artifacts")
        self.exports_dir = os.path.join(self.dir, "exports")
        for d in (self.exhibits_dir, self.artifacts_dir, self.exports_dir):
            os.makedirs(d, exist_ok=True)

        self.examiner = examiner or _safe_user()
        self.organisation = organisation
        self.reference = reference
        self.notes = notes
        self.opened_utc = utc_iso()
        self.opened_local = local_iso()
        self._t0 = time.monotonic()

        self.exchanges: List[Exchange] = []
        self.findings: Dict[str, Any] = {}
        self._audit_path = os.path.join(self.dir, "audit.jsonl")
        #: Once sealed, nothing may be appended. The manifest hashes the audit
        #: log, so a single further line would invalidate the package - and a
        #: log that keeps growing after the seal is not a sealed log anyway.
        self._sealed = False
        self.post_seal_events: List[Dict[str, Any]] = []

        self.log("case.opened", case_id=self.case_id, examiner=self.examiner,
                 organisation=self.organisation, reference=self.reference)
        self.log("environment", **self.environment())

    # -- provenance --------------------------------------------------------
    def environment(self) -> Dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "tool_version": __version__,
            "python": sys.version.split()[0],
            "python_build": " ".join(platform.python_build()),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
            "os": platform.platform(),
            "machine": platform.machine(),
            "hostname": _safe_host(),
            "user": _safe_user(),
            "cwd": os.getcwd(),
            "tz": dt.datetime.now().astimezone().tzname(),
            "utc_offset_seconds": int(
                dt.datetime.now().astimezone().utcoffset().total_seconds()
            ),
        }

    # -- audit log ---------------------------------------------------------
    def log(self, event: str, **fields: Any) -> None:
        """
        Append one event to the tamper-evident audit trail.

        Once the case is sealed this stops writing to disk and keeps the event
        in memory instead. The manifest hashes audit.jsonl, so one further line
        changes that hash and the package no longer verifies - and a log that
        keeps growing after the seal was never sealed in the first place. The
        tool must not be the thing that breaks its own evidence.
        """
        entry = {
            "utc": utc_iso(),
            "elapsed_s": round(time.monotonic() - self._t0, 6),
            "event": event,
        }
        entry.update(fields)
        if self._sealed:
            self.post_seal_events.append(entry)
            return
        with open(self._audit_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")

    # -- exhibits ----------------------------------------------------------
    def record(self, ex: Exchange) -> str:
        """Persist a complete HTTP transaction.  Returns the exhibit path."""
        name = "%04d_%s" % (ex.seq, _slug(ex.label))
        path = os.path.join(self.exhibits_dir, name)
        os.makedirs(path, exist_ok=True)

        def _write(fn: str, data: bytes) -> None:
            with open(os.path.join(path, fn), "wb") as fh:
                fh.write(data)

        req_hdr = "%s %s\n%s\n" % (
            ex.method, ex.url,
            "\n".join("%s: %s" % kv for kv in sorted(ex.request_headers.items())),
        )
        _write("request.headers.txt", req_hdr.encode("utf-8"))
        _write("request.body.bin", ex.request_body)

        # A request body we compressed before sending is stored verbatim above,
        # which preserves it exactly but leaves a reviewer holding gzip. Write
        # the decoded form alongside it so the request can be read without
        # tooling. The .bin remains the authoritative artefact; this is a
        # convenience copy and is hashed in the manifest like everything else.
        req_readable = ex.request_body
        enc = ex.request_headers.get("Content-Encoding", "")
        if enc:
            decoded = _decode_body(ex.request_body, enc)
            if decoded != ex.request_body:
                req_readable = decoded
                _write("request.body.decoded.bin", decoded)
        if _looks_textual(req_readable):
            suffix = ".decoded" if req_readable is not ex.request_body else ""
            _write("request.body%s%s" % (suffix, _text_extension(
                req_readable, ex.request_headers.get("Content-Type", ""))),
                req_readable)

        resp_hdr = "HTTP %s %s\n%s\n" % (
            ex.status, ex.reason,
            "\n".join("%s: %s" % kv for kv in sorted(ex.response_headers.items())),
        )
        _write("response.headers.txt", resp_hdr.encode("utf-8"))
        _write("response.body.wire.bin", ex.response_raw)
        if ex.response_body != ex.response_raw:
            _write("response.body.decoded.bin", ex.response_body)
        if _looks_textual(ex.response_body):
            ext = _text_extension(ex.response_body,
                                  ex.response_headers.get("Content-Type", ""))
            _write("response.body.decoded" + ext, ex.response_body)

        meta = ex.summary()
        meta["exhibit"] = name
        meta["request_headers"] = ex.request_headers
        meta["response_headers"] = ex.response_headers
        _write("meta.json", json.dumps(meta, indent=2, default=str).encode("utf-8"))

        self.exchanges.append(ex)
        self.log("http.exchange", **ex.summary())
        return path

    # -- artifacts ---------------------------------------------------------
    def write_artifact(self, filename: str, data: Any, subdir: str = "artifacts") -> str:
        base = {"artifacts": self.artifacts_dir, "exports": self.exports_dir}.get(
            subdir, self.artifacts_dir)
        path = os.path.join(base, filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if isinstance(data, bytes):
            payload = data
        elif isinstance(data, str):
            payload = data.encode("utf-8")
        else:
            payload = json.dumps(data, indent=2, ensure_ascii=False,
                                 default=str).encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(payload)
        self.log("artifact.written", path=os.path.relpath(path, self.dir),
                 bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
        return path

    # -- sealing -----------------------------------------------------------
    def build_manifest(self) -> Dict[str, Any]:
        """Hash every file in the case, then hash the listing itself."""
        entries: List[Dict[str, Any]] = []
        for dirpath, _dirs, files in os.walk(self.dir):
            for fn in files:
                if fn in ("manifest.json", "MANIFEST.sha256"):
                    continue
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, self.dir).replace(os.sep, "/")
                entries.append({
                    "path": rel,
                    "bytes": os.path.getsize(full),
                    "sha256": sha256_file(full),
                })
        entries.sort(key=lambda e: e["path"])
        listing = "\n".join("%s  %s" % (e["sha256"], e["path"]) for e in entries)
        root = hashlib.sha256(listing.encode("utf-8")).hexdigest()
        return {
            "case_id": self.case_id,
            "sealed_utc": utc_iso(),
            "algorithm": "SHA-256",
            "root_hash_definition":
                "sha256( '\\n'.join( '<sha256>  <relative/path>' ) sorted by path )",
            "root_hash": root,
            "file_count": len(entries),
            "total_bytes": sum(e["bytes"] for e in entries),
            "files": entries,
        }

    def seal(self, findings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Write case.json, the verifier, the manifest and the root hash."""
        if findings is not None:
            self.findings = findings

        case_doc = {
            "case_id": self.case_id,
            "reference": self.reference,
            "examiner": self.examiner,
            "organisation": self.organisation,
            "notes": self.notes,
            "opened_utc": self.opened_utc,
            "opened_local": self.opened_local,
            "sealed_utc": utc_iso(),
            "sealed_local": local_iso(),
            "duration_s": round(time.monotonic() - self._t0, 3),
            "environment": self.environment(),
            "exchange_count": len(self.exchanges),
            "exchanges": [e.summary() for e in self.exchanges],
            "findings": self.findings,
        }
        with open(os.path.join(self.dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(case_doc, fh, indent=2, ensure_ascii=False, default=str)

        verifier = os.path.join(self.dir, "verify_evidence.py")
        # newline="\n" is not cosmetic. Written on Windows with the default
        # translation the file gets CRLF endings, so the `#!/usr/bin/env python3`
        # shebang ends with a carriage return and a POSIX recipient running
        # ./verify_evidence.py gets: env: 'python3\r': No such file or directory.
        with open(verifier, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(VERIFIER_SOURCE)
        # The verifier carries a `#!/usr/bin/env python3` shebang, so advertise
        # it honestly: without the executable bit a recipient on Linux who runs
        # ./verify_evidence.py gets "Permission denied" on the one step that
        # establishes chain of custody. The manifest hashes content only, so the
        # mode does not affect the root hash.
        try:
            os.chmod(verifier, 0o755)
        except OSError:                                   # pragma: no cover
            pass                                          # Windows, or odd FS
        with open(os.path.join(self.dir, "README_EVIDENCE.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write(README_EVIDENCE.format(
                case_id=self.case_id, tool=TOOL_NAME, version=__version__,
                sealed=utc_iso()))

        self.log("case.sealed", exchanges=len(self.exchanges))
        self._sealed = True

        manifest = self.build_manifest()
        with open(os.path.join(self.dir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        with open(os.path.join(self.dir, "MANIFEST.sha256"), "w", encoding="utf-8") as fh:
            fh.write("%s  (root hash of manifest.json listing)\n" % manifest["root_hash"])
        return manifest

    def package(self, findings: Optional[Dict[str, Any]] = None,
                out_dir: Optional[str] = None) -> Dict[str, Any]:
        """Seal the case and compress it into a single portable ZIP."""
        manifest = self.seal(findings)
        out_dir = out_dir or os.path.dirname(self.dir)
        zip_path = os.path.join(out_dir, "%s_EVIDENCE.zip" % self.case_id)

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for dirpath, _dirs, files in os.walk(self.dir):
                for fn in sorted(files):
                    full = os.path.join(dirpath, fn)
                    arc = os.path.join(self.case_id,
                                       os.path.relpath(full, self.dir)).replace(os.sep, "/")
                    if fn == "verify_evidence.py":
                        # Carry the executable bit through the archive. A ZIP
                        # written on Windows records no POSIX mode at all, so
                        # without this the verifier extracts as 0644 on Linux
                        # and its shebang is useless to the recipient.
                        info = zipfile.ZipInfo.from_file(full, arc)
                        info.external_attr = (0o755 << 16) | 0o600
                        info.compress_type = zipfile.ZIP_DEFLATED
                        # unzip only honours the Unix permission bits when the
                        # archive says a Unix system created the entry. Built on
                        # Windows, ZipInfo.from_file stamps create_system = 0
                        # (FAT), the mode above is ignored, and the verifier
                        # still extracts as 0644 - which is exactly the failure
                        # this is meant to prevent.
                        info.create_system = 3
                        with open(full, "rb") as src:
                            zf.writestr(info, src.read())
                    else:
                        zf.write(full, arc)

        return {
            "zip_path": zip_path,
            "zip_bytes": os.path.getsize(zip_path),
            "zip_sha256": sha256_file(zip_path),
            "root_hash": manifest["root_hash"],
            "file_count": manifest["file_count"],
            "case_dir": self.dir,
        }


def _safe_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _safe_host() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


README_EVIDENCE = """\
EVIDENCE PACKAGE
======================
Case            : {case_id}
Produced by     : {tool} v{version}
Sealed (UTC)    : {sealed}

WHAT IS IN HERE
---------------
  case.json        Case metadata, tool/host provenance, an index of every
                   network transaction, and the analytical findings.
  audit.jsonl      Append-only activity log. One JSON object per line, in
                   the order events occurred, with UTC and elapsed times.
  exhibits/        One directory per HTTP transaction. Each contains the
                   request headers, the request body, the response headers,
                   the response body exactly as received on the wire, and
                   the decoded response body. Nothing is edited or filtered.
  artifacts/       Intermediate and final analysis products, including the
                   HTML report.
  exports/         Machine-readable position exports (CSV, GeoJSON, KML).
  manifest.json    SHA-256 of every file in this package.
  MANIFEST.sha256  A single root hash covering the entire manifest.

HOW TO VERIFY INTEGRITY
-----------------------
Extract the package, then from inside the case directory run:

    python3 verify_evidence.py        (Linux / macOS)
    py verify_evidence.py             (Windows)

It recomputes the SHA-256 of every file, compares against manifest.json,
recomputes the root hash, and reports any file that was added, removed or
modified. Exit code 0 means the package is intact; 1 means it is not.

The root hash is defined as:

    sha256( "\\n".join( "<sha256>  <relative/path>" ) sorted by path )

so it can be reproduced independently without this tool.

EVIDENTIAL LIMITATIONS
----------------------
Positions in this package are derived from crowd-sourced wireless
positioning databases operated by third parties. They indicate where an
access point was observed by contributing devices, at some unspecified
earlier time. They are not a direct measurement made by this tool, and an
access point can be moved, replaced, or spoofed. Treat every position as
an investigative lead requiring corroboration, not as a fact.
"""


VERIFIER_SOURCE = '''\
#!/usr/bin/env python3
"""Standalone integrity verifier for an evidence package.

Requires nothing but a Python 3 interpreter. Run it from inside the case
directory (the one containing manifest.json).
"""
import hashlib, json, os, sys

SKIP = {"manifest.json", "MANIFEST.sha256"}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    mpath = os.path.join(here, "manifest.json")
    if not os.path.exists(mpath):
        print("FAIL: manifest.json not found next to this script")
        return 1
    with open(mpath, encoding="utf-8") as fh:
        manifest = json.load(fh)

    expected = {e["path"]: e for e in manifest["files"]}
    actual = {}
    for dirpath, _dirs, files in os.walk(here):
        for fn in files:
            if fn in SKIP:
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, here).replace(os.sep, "/")
            actual[rel] = full

    modified, missing, added = [], [], []
    for rel, meta in expected.items():
        if rel not in actual:
            missing.append(rel)
        elif sha256_file(actual[rel]) != meta["sha256"]:
            modified.append(rel)
    for rel in actual:
        if rel not in expected:
            added.append(rel)

    entries = sorted(
        ({"path": r, "sha256": sha256_file(p)} for r, p in actual.items()),
        key=lambda e: e["path"],
    )
    listing = "\\n".join("%s  %s" % (e["sha256"], e["path"]) for e in entries)
    root = hashlib.sha256(listing.encode("utf-8")).hexdigest()

    print("Case          :", manifest.get("case_id"))
    print("Sealed (UTC)  :", manifest.get("sealed_utc"))
    print("Files expected:", len(expected))
    print("Files present :", len(actual))
    print()
    print("Root hash expected:", manifest["root_hash"])
    print("Root hash computed:", root)
    print()

    ok = not (modified or missing or added) and root == manifest["root_hash"]
    for rel in missing:
        print("MISSING :", rel)
    for rel in added:
        print("ADDED   :", rel)
    for rel in modified:
        print("MODIFIED:", rel)

    print()
    print("RESULT: %s" % ("INTACT - package verifies" if ok
                          else "FAILED - package does not verify"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
'''
