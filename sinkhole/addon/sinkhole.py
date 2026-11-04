"""mitmproxy addon for the FirstRun sinkhole: record every request, answer it locally and never
connect upstream (docs/ARCHITECTURE.md 6.4-6.5).

Records are JSON lines in <sinkhole_dir>/events.jsonl; large bodies go to <sinkhole_dir>/bodies/.
"""

import base64
import hashlib
import json
import logging
import os
import time

from mitmproxy import ctx, http, tls

log = logging.getLogger(__name__)

MAX_INLINE_BODY = 256 * 1024
MAX_HEADER_VALUE = 1024
MAX_RECORDS = 5000


def now_ms():
    return int(time.time() * 1000)


def destination_port(context):
    address = context.server.address if context and context.server else None
    return address[1] if address else None


def load_canned(path):
    """Canned responses for curated samples: [{method, host, path, status, headers, body_b64}]."""
    try:
        with open(path, encoding="utf-8") as handle:
            entries = json.load(handle)
    except (OSError, ValueError) as err:
        log.warning("sinkhole: cannot load canned responses from %s: %s", path, err)
        return {}
    canned = {}
    for entry in entries if isinstance(entries, list) else []:
        try:
            key = (entry["method"].upper(), entry["host"].lower(), entry["path"])
            canned[key] = (
                int(entry.get("status", 200)),
                {str(k): str(v) for k, v in entry.get("headers", {}).items()},
                base64.b64decode(entry.get("body_b64", "")),
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            log.warning("sinkhole: skipping malformed canned entry")
    return canned


class Sinkhole:
    def __init__(self):
        self.canned = {}
        self.records = 0
        self.next_id = 0

    def load(self, loader):
        loader.add_option("sinkhole_dir", str, "/sinkhole", "Directory for sinkhole records.")
        loader.add_option("canned", str, "", "JSON file with canned responses for a curated sample.")

    def configure(self, updated):
        if "canned" in updated and ctx.options.canned:
            self.canned = load_canned(ctx.options.canned)

    def running(self):
        os.makedirs(os.path.join(ctx.options.sinkhole_dir, "bodies"), exist_ok=True)
        with open(os.path.join(ctx.options.sinkhole_dir, "ready"), "w", encoding="utf-8") as handle:
            handle.write(str(now_ms()))

    def write(self, record):
        self.records += 1
        if self.records > MAX_RECORDS:
            return
        record.setdefault("ts_ms", now_ms())
        path = os.path.join(ctx.options.sinkhole_dir, "events.jsonl")
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")

    def tls_clienthello(self, data: tls.ClientHelloData):
        hello = data.client_hello
        self.write({
            "kind": "tls.clienthello",
            "sni": hello.sni or "",
            "port": destination_port(data.context),
            "alpn": [p.decode("latin-1") for p in hello.alpn_protocols],
        })

    def tls_failed_client(self, data: tls.TlsData):
        self.write({
            "kind": "tls.failed",
            "sni": data.conn.sni or "",
            "port": destination_port(data.context),
            "error": str(data.conn.error or "")[:300],
        })

    def request(self, flow: http.HTTPFlow):
        req = flow.request
        self.next_id += 1
        record_id = f"r{self.next_id}"
        path, _, query = req.path.partition("?")
        headers = {}
        for name, value in req.headers.items(multi=True):
            value = value[:MAX_HEADER_VALUE]
            headers[name] = f"{headers[name]}, {value}" if name in headers else value

        body = req.raw_content  # None when the body was streamed past body_size_limit
        record = {
            "kind": "http.request",
            "id": record_id,
            "ts_ms": int(req.timestamp_start * 1000),
            "scheme": req.scheme,
            "http_version": req.http_version,
            "method": req.method,
            "host": req.pretty_host,
            "port": req.port,
            "path": path,
            "query": query,
            "headers": headers,
            "body_len": len(body) if body is not None else None,
            "body_sha256": hashlib.sha256(body).hexdigest() if body else None,
        }
        if body and len(body) <= MAX_INLINE_BODY:
            record["body_b64"] = base64.b64encode(body).decode("ascii")
        elif body:
            with open(os.path.join(ctx.options.sinkhole_dir, "bodies", f"{record_id}.bin"), "wb") as handle:
                handle.write(body)
            record["body_ref"] = f"bodies/{record_id}.bin"

        canned = self.canned.get((req.method.upper(), req.pretty_host.lower(), path))
        if canned:
            status, response_headers, content = canned
        else:
            status, response_headers, content = 200, {"Content-Type": "application/octet-stream"}, b""
        if req.http_version.startswith("HTTP/1"):
            response_headers = dict(response_headers, Connection="close")
        flow.response = http.Response.make(status, content, response_headers)
        record["response"] = {"status": status, "canned": bool(canned)}
        self.write(record)


addons = [Sinkhole()]
