"""
Local web application: a stdlib HTTP server and a small JSON API.

No web framework.  `http.server` is enough for a single-operator tool bound to
loopback, and avoiding Flask keeps the portable build to nothing but CPython.

Security posture: the server binds to 127.0.0.1 only, requires a per-session
token on every API call, and checks the Origin/Host headers.  A local tool that
performs network lookups on demand should not be reachable by a web page the
operator happens to have open in another tab.
"""

from __future__ import annotations

import json
import mimetypes
import os
import secrets
import socket
import subprocess
import sys
import threading
import traceback
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse

from . import TOOL_NAME, __version__, apple, ingest, scan
from .engine import Investigation, Options

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

#: One token per process, handed to the page in its URL.
TOKEN = secrets.token_urlsafe(24)

_JOBS: Dict[str, Dict[str, object]] = {}
_LOCK = threading.Lock()


class Job:
    def __init__(self, opts: Options, evidence_root: str):
        self.id = uuid.uuid4().hex[:12]
        self.opts = opts
        self.evidence_root = evidence_root
        self.events = []
        self.percent = 0.0
        self.phase = "queued"
        self.message = "Queued"
        self.done = False
        self.result: Optional[Dict[str, object]] = None
        self.error: Optional[str] = None

    def progress(self, phase: str, message: str, pct: float) -> None:
        with _LOCK:
            self.phase, self.message, self.percent = phase, message, pct
            self.events.append({"phase": phase, "message": message, "percent": pct})

    def run(self) -> None:
        try:
            inv = Investigation(self.opts, self.evidence_root, progress=self.progress)
            self.result = inv.run()
        except Exception as e:
            self.error = "%s: %s" % (type(e).__name__, e)
            self.progress("error", self.error, 100)
            traceback.print_exc()
        finally:
            self.done = True

    def snapshot(self, since: int = 0) -> Dict[str, object]:
        with _LOCK:
            return {
                "id": self.id, "phase": self.phase, "message": self.message,
                "percent": self.percent, "done": self.done, "error": self.error,
                "events": self.events[since:], "event_count": len(self.events),
            }


class Handler(BaseHTTPRequestHandler):
    server_version = "WGF/%s" % __version__
    protocol_version = "HTTP/1.1"

    # -- helpers -----------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype: str = "application/json",
              extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, default=str).encode("utf-8"))

    def _authorised(self, query) -> bool:
        supplied = (query.get("token") or [""])[0] or self.headers.get("X-WGF-Token", "")
        if not secrets.compare_digest(supplied, TOKEN):
            return False
        # Reject cross-origin form posts from other pages.
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).hostname not in ("127.0.0.1", "localhost"):
            return False
        return True

    def log_message(self, fmt, *args):        # keep the console clean
        pass

    # -- routing -----------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        route = parsed.path
        query = parse_qs(parsed.query)

        if route in ("/", "/index.html"):
            return self._serve_file("index.html", inject_token=True)
        if route.startswith("/assets/"):
            return self._serve_file(os.path.basename(route))

        if route.startswith("/api/"):
            if not self._authorised(query):
                return self._json(403, {"error": "invalid or missing token"})
            if route == "/api/scan":
                return self._api_scan()
            if route == "/api/status":
                return self._api_status(query)
            if route == "/api/result":
                return self._api_result(query)
            if route == "/api/reveal":
                return self._api_reveal(query)
            if route == "/api/meta":
                return self._json(200, {
                    "tool": TOOL_NAME, "version": __version__,
                    "windows": scan.IS_WINDOWS, "python": sys.version.split()[0],
                    "evidence_root": self.server.evidence_root,
                })
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if not self._authorised(query):
            return self._json(403, {"error": "invalid or missing token"})
        if parsed.path not in ("/api/run", "/api/ingest"):
            return self._json(404, {"error": "not found"})

        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception as e:
            return self._json(400, {"error": "bad request body: %s" % e})

        if parsed.path == "/api/ingest":
            return self._api_ingest(payload)

        target = (payload.get("target") or "").strip()

        # Addresses pasted by the operator, or recovered from artefacts.
        extra: list = []
        blob = (payload.get("bssids") or "").strip()
        if blob:
            parsed = ingest.ingest(blob)
            extra.extend(o.to_dict() for o in parsed.get("observations", []))
        for row in payload.get("observations") or []:
            if isinstance(row, dict) and row.get("bssid"):
                extra.append(row)

        if not target and not extra and payload.get("mode") != "survey":
            return self._json(400, {
                "error": "supply a target SSID or BSSID, or import at least one "
                         "access point address"})

        # Supplied only in single mode: everything audible alongside the
        # target. Kept separate from `extra`, which becomes the target list.
        context = [row for row in (payload.get("context") or [])
                   if isinstance(row, dict) and row.get("bssid")]

        opts = Options(
            target=target,
            extra_observations=extra,
            context_observations=context,
            known_ssid=(payload.get("known_ssid") or "").strip(),
            mode=payload.get("mode") or "auto",
            neighbours=int(payload.get("neighbours") or apple.MAX_NEIGHBOURS),
            active_scan=bool(payload.get("active_scan", False)),
            replicate_groups=max(0, int(payload.get("replicates", 4) or 0)),
            observed_at=(payload.get("observed_at") or "").strip(),
            msft_api_version=("v21" if payload.get("msft_api_version") == "v21"
                              else "v22"),
            send_device_profile=bool(payload.get("send_device_profile", False)),
            redacted_copy=bool(payload.get("redact", False)),
            use_microsoft=bool(payload.get("use_microsoft", True)),
            use_corroborating=bool(payload.get("use_corroborating", True)),
            use_enrichment=bool(payload.get("use_enrichment", True)),
            fetch_tiles=bool(payload.get("fetch_tiles", True)),
            tile_zoom=int(payload.get("tile_zoom") or 17),
            poi_radius_m=int(payload.get("poi_radius_m") or 200),
            examiner=(payload.get("examiner") or "").strip(),
            organisation=(payload.get("organisation") or "").strip(),
            reference=(payload.get("reference") or "").strip(),
            notes=(payload.get("notes") or "").strip(),
        )
        job = Job(opts, self.server.evidence_root)
        _JOBS[job.id] = job
        threading.Thread(target=job.run, daemon=True).start()
        return self._json(202, {"id": job.id})

    # -- endpoints ---------------------------------------------------------
    #: Largest artefact accepted through the browser. A registry export or an
    #: event-log dump from a busy host runs to a few megabytes; this leaves
    #: generous headroom while keeping an accidental pick of something enormous
    #: out of memory. Larger files can still be given by path.
    MAX_ARTEFACT_BYTES = 64 * 1024 * 1024

    def _api_ingest(self, payload):
        """
        Parse an artefact and preview what was found.

        Three ways in, because a browser cannot hand over a file's location:
        pasted text, the bytes of a file the operator picked, or a path typed by
        hand. The picker sends bytes, which is what lets a single control accept
        every format, including those the parser has to open as a file on
        disk rather than read as text.
        """
        import base64
        import tempfile

        text = payload.get("text") or ""
        path = (payload.get("path") or "").strip()
        blob = payload.get("data_b64") or ""
        filename = payload.get("filename") or ""
        try:
            if blob:
                try:
                    raw = base64.b64decode(blob, validate=True)
                except Exception:
                    return self._json(400, {"error": "the file could not be read"})
                if len(raw) > self.MAX_ARTEFACT_BYTES:
                    return self._json(400, {
                        "error": "that file is %.0f MB; the limit through the "
                                 "browser is %d MB. Give its path instead."
                                 % (len(raw) / 1048576,
                                    self.MAX_ARTEFACT_BYTES // 1048576)})
                # ingest_file dispatches on the extension, so the temporary copy
                # keeps the original suffix.
                suffix = os.path.splitext(filename)[1][:12] or ".bin"
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
                try:
                    tmp.write(raw)
                    tmp.close()
                    parsed = ingest.ingest_file(tmp.name)
                finally:
                    try:
                        os.unlink(tmp.name)
                    except OSError:
                        pass
            elif path:
                if not os.path.isfile(path):
                    return self._json(400, {"error": "no such file: %s" % path})
                parsed = ingest.ingest_file(path)
            else:
                parsed = ingest.ingest(text, filename)
        except Exception as e:
            return self._json(500, {"error": "%s: %s" % (type(e).__name__, e)})
        obs = parsed.get("observations") or []
        return self._json(200, {
            "format": parsed.get("format"),
            "note": parsed.get("note"),
            "count": len(obs),
            "observations": [o.to_dict() if hasattr(o, "to_dict") else o
                             for o in obs],
        })

    def _api_scan(self):
        try:
            survey = scan.scan(active=True)
        except Exception as e:
            return self._json(500, {"error": str(e)})
        beacons = survey.get("beacons") or []
        networks: Dict[str, Dict[str, object]] = {}
        for b in beacons:
            key = b.ssid or "\x00hidden:%s" % b.bssid
            entry = networks.setdefault(key, {
                "ssid": b.ssid, "hidden": not b.ssid, "bssids": [],
                "best_rssi": -999, "bands": set()})
            entry["bssids"].append(b.bssid)
            entry["best_rssi"] = max(entry["best_rssi"], b.rssi_dbm or -999)
            if b.band:
                entry["bands"].add(b.band)
        out = []
        for e in networks.values():
            out.append({**e, "bands": sorted(e["bands"]),
                        "radios": len(e["bssids"])})
        out.sort(key=lambda e: -e["best_rssi"])
        return self._json(200, {
            "method": survey.get("method"),
            "active_scan": survey.get("active_scan"),
            "warnings": survey.get("warnings"),
            "interfaces": survey.get("interfaces"),
            "beacon_count": len(beacons),
            "networks": out,
            "beacons": [b.to_dict() for b in beacons],
        })

    def _api_status(self, query):
        job = _JOBS.get((query.get("id") or [""])[0])
        if not job:
            return self._json(404, {"error": "unknown job"})
        since = int((query.get("since") or ["0"])[0])
        return self._json(200, job.snapshot(since))

    def _api_result(self, query):
        job = _JOBS.get((query.get("id") or [""])[0])
        if not job:
            return self._json(404, {"error": "unknown job"})
        if not job.done:
            return self._json(409, {"error": "still running"})
        if job.error:
            return self._json(500, {"error": job.error})
        return self._json(200, job.result)

    def _api_reveal(self, query):
        """Open a produced file or its folder in the host file manager."""
        path = (query.get("path") or [""])[0]
        root = os.path.abspath(self.server.evidence_root)
        target = os.path.abspath(path)
        if not target.startswith(root) or not os.path.exists(target):
            return self._json(400, {"error": "path is outside the evidence root"})
        try:
            if sys.platform == "win32":
                if os.path.isdir(target):
                    os.startfile(target)                      # noqa: S606
                else:
                    subprocess.Popen(["explorer", "/select,", target])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", target])
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(target)])
        except Exception as e:
            return self._json(500, {"error": str(e)})
        return self._json(200, {"ok": True})

    # -- static ------------------------------------------------------------
    def _serve_file(self, name: str, inject_token: bool = False):
        safe = os.path.basename(name)
        path = os.path.join(WEB_DIR, safe)
        if not os.path.isfile(path):
            return self._json(404, {"error": "not found"})
        with open(path, "rb") as fh:
            data = fh.read()
        if inject_token:
            data = data.replace(b"__WGF_TOKEN__", TOKEN.encode())
        ctype = mimetypes.guess_type(safe)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        return self._send(200, data, ctype)


def _free_port(preferred: int = 8731) -> int:
    for port in (preferred, 0):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
            return s.getsockname()[1]
        except OSError:
            continue
        finally:
            s.close()
    return 0


def serve(evidence_root: str, port: int = 8731, open_browser: bool = True) -> None:
    os.makedirs(evidence_root, exist_ok=True)
    port = _free_port(port)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.evidence_root = os.path.abspath(evidence_root)
    httpd.daemon_threads = True

    url = "http://127.0.0.1:%d/?token=%s" % (port, TOKEN)
    print()
    print("  %s  v%s" % (TOOL_NAME, __version__))
    print("  " + "-" * 62)
    print("  Interface : %s" % url)
    print("  Evidence  : %s" % httpd.evidence_root)
    print("  Bound to loopback only. Press Ctrl+C to stop.")
    print()
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    finally:
        httpd.server_close()
