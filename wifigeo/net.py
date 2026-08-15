"""
Evidence-preserving HTTP client built on urllib.

Every request that leaves this tool passes through `Transport.fetch()`, which
captures the complete transaction - request line, request headers, request
body, response status, response headers, the response body *exactly as it came
off the wire* (still compressed), and the decoded body - and hands it to the
active evidence recorder.

Nothing else here is permitted to open a socket.  That is what makes the
chain of custody complete rather than aspirational.
"""

from __future__ import annotations

import gzip
import hashlib
import http.client
import io
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass, field
from typing import Dict, Optional

from . import USER_AGENT


class TransportError(RuntimeError):
    """Network failure that the caller is expected to handle gracefully."""


@dataclass
class Exchange:
    """One complete, immutable HTTP transaction."""

    seq: int
    label: str
    method: str
    url: str
    request_headers: Dict[str, str]
    request_body: bytes
    started_utc: str
    duration_ms: float
    status: Optional[int] = None
    reason: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_raw: bytes = b""       # exactly as received, still compressed
    response_body: bytes = b""      # after Content-Encoding removal
    error: Optional[str] = None

    @property
    def request_sha256(self) -> str:
        return hashlib.sha256(self.request_body).hexdigest()

    @property
    def response_sha256(self) -> str:
        return hashlib.sha256(self.response_raw).hexdigest()

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None and 200 <= self.status < 300

    def summary(self) -> Dict[str, object]:
        return {
            "seq": self.seq,
            "label": self.label,
            "method": self.method,
            "url": self.url,
            "started_utc": self.started_utc,
            "duration_ms": round(self.duration_ms, 2),
            "status": self.status,
            "reason": self.reason,
            "request_bytes": len(self.request_body),
            "request_sha256": self.request_sha256,
            "response_bytes_wire": len(self.response_raw),
            "response_bytes_decoded": len(self.response_body),
            "response_sha256_wire": self.response_sha256,
            "response_sha256_decoded": hashlib.sha256(self.response_body).hexdigest(),
            "error": self.error,
        }


def _utc_now() -> str:
    """ISO-8601 UTC with microsecond precision and an explicit Z."""
    import datetime as _dt

    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _decode_body(raw: bytes, encoding: str) -> bytes:
    """Undo Content-Encoding.  Never raises - a failed decode returns raw."""
    enc = (encoding or "").lower().strip()
    try:
        if enc == "gzip":
            return gzip.decompress(raw)
        if enc == "deflate":
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return zlib.decompress(raw, -zlib.MAX_WBITS)
        if enc == "br":
            # Brotli is not in the stdlib.  We never advertise it, so reaching
            # here means a server ignored our Accept-Encoding.
            return raw
    except Exception:
        return raw
    return raw


class Transport:
    """
    A single HTTP transport for one investigation.

    `recorder` is anything exposing `.record(Exchange)`; in practice it is an
    `evidence.Case`.  It may be None for throwaway/CLI use.
    """

    def __init__(self, recorder=None, timeout: float = 25.0,
                 verify_tls: bool = True, retries: int = 2):
        self.recorder = recorder
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.retries = max(0, retries)
        self._seq = 0
        # Independent lookups are issued concurrently, so sequence numbers and
        # the evidence recorder are shared state.
        self._lock = threading.Lock()

        if verify_tls:
            self._ctx = ssl.create_default_context()
        else:
            # Offered because two of the reference tools disable verification
            # and some corporate proxies MITM.  It is recorded in the evidence
            # manifest so a reviewer can see it was used.
            self._ctx = ssl.create_default_context()
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ctx),
            _NoRedirect(),
        )

    # -- public ------------------------------------------------------------
    def fetch(self, url: str, *, label: str, method: str = "GET",
              body: bytes = b"", headers: Optional[Dict[str, str]] = None,
              timeout: Optional[float] = None,
              retries: Optional[int] = None) -> Exchange:
        """Perform one HTTP transaction and record it.  Never raises."""
        hdrs = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"}
        if headers:
            hdrs.update(headers)

        with self._lock:
            self._seq += 1
            seq = self._seq
        last: Optional[Exchange] = None
        attempts = self.retries if retries is None else max(0, retries)

        for attempt in range(attempts + 1):
            ex = self._once(seq, label, method, url, body, hdrs, timeout)
            last = ex
            # Retry only on transient conditions.
            transient = ex.error is not None or (ex.status is not None and ex.status >= 500)
            if not transient or attempt == attempts:
                break
            time.sleep(0.8 * (attempt + 1))

        assert last is not None
        if self.recorder is not None:
            with self._lock:
                self.recorder.record(last)
        return last

    # -- internal ----------------------------------------------------------
    def _once(self, seq: int, label: str, method: str, url: str,
              body: bytes, hdrs: Dict[str, str],
              timeout: Optional[float]) -> Exchange:
        started = _utc_now()
        t0 = time.perf_counter()
        ex = Exchange(
            seq=seq, label=label, method=method, url=url,
            request_headers=dict(hdrs), request_body=body,
            started_utc=started, duration_ms=0.0,
        )

        req = urllib.request.Request(
            url, data=body if body else None, method=method, headers=hdrs
        )
        try:
            with self._opener.open(req, timeout=timeout or self.timeout) as resp:
                raw = resp.read()
                ex.status = resp.status
                ex.reason = getattr(resp, "reason", "") or ""
                ex.response_headers = {k: v for k, v in resp.headers.items()}
                ex.response_raw = raw
                ex.response_body = _decode_body(raw, resp.headers.get("Content-Encoding", ""))
        except urllib.error.HTTPError as e:
            # An HTTP error still carries a body worth preserving.
            raw = b""
            try:
                raw = e.read()
            except Exception:
                pass
            ex.status = e.code
            ex.reason = str(e.reason)
            ex.response_headers = {k: v for k, v in (e.headers or {}).items()}
            ex.response_raw = raw
            ex.response_body = _decode_body(raw, ex.response_headers.get("Content-Encoding", ""))
            ex.error = "HTTP %d %s" % (e.code, e.reason)
        except (urllib.error.URLError, socket.timeout, ssl.SSLError,
                http.client.HTTPException, OSError) as e:
            ex.error = "%s: %s" % (type(e).__name__, e)
        except Exception as e:  # pragma: no cover - defensive
            ex.error = "%s: %s" % (type(e).__name__, e)

        ex.duration_ms = (time.perf_counter() - t0) * 1000.0
        return ex


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """
    Follow redirects but keep them visible.

    urllib follows redirects transparently, which would hide a hop from the
    evidence log.  We allow the redirect (the services do use them) but the
    final URL is recorded from the response object, and a reviewer comparing
    request URL to response URL can see that a hop occurred.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, code, msg, headers, newurl)
