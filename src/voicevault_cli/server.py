import hmac
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from zeroconf import ServiceInfo, Zeroconf

from . import __version__
from .config import Config
from .crypto import MAGIC, fingerprint, open_sealed
from .ingest import ingest_package

MAX_BODY = 64 * 1024 * 1024
SERVICE_TYPE = "_obsidianvoice._tcp.local."

LogFn = Callable[[str], None]


def _local_addresses() -> list[bytes]:
    """Best-effort list of this host's LAN IPv4 addresses for the mDNS
    registration."""
    addresses = []
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("192.0.2.1", 80))
        addresses.append(socket.inet_aton(probe.getsockname()[0]))
        probe.close()
    except OSError:
        pass
    return addresses or [socket.inet_aton("127.0.0.1")]


class Receiver:
    """The LAN receiver: an HTTP server speaking the VoiceVault transport
    contract plus a zeroconf advertisement, decrypting and ingesting
    captures as they arrive."""

    def __init__(self, config: Config, log: LogFn):
        self.config = config
        self.log = log
        self.zeroconf: Zeroconf | None = None
        self.httpd: ThreadingHTTPServer | None = None

    def start(self) -> None:
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args) -> None:
                pass

            def _respond(self, status: int, body: dict) -> None:
                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self) -> None:
                if self.path != "/ping":
                    return self._respond(404, {"error": "not found"})
                self._respond(
                    200,
                    {
                        "service": "voicevault",
                        "version": __version__,
                        "fingerprint": fingerprint(receiver.config.public_key),
                    },
                )

            def do_POST(self) -> None:
                if self.path != "/capture":
                    return self._respond(404, {"error": "not found"})
                auth = self.headers.get("Authorization", "").removeprefix("Bearer ")
                if not hmac.compare_digest(auth, receiver.config.auth_token):
                    return self._respond(401, {"error": "unauthorized"})
                length = int(self.headers.get("Content-Length", 0))
                if length <= 0 or length > MAX_BODY:
                    return self._respond(413, {"error": "bad body size"})
                blob = self.rfile.read(length)
                if not blob.startswith(MAGIC):
                    return self._respond(400, {"error": "not a VVSB sealed blob"})
                try:
                    package = open_sealed(blob, receiver.config.private_key)
                    result = ingest_package(package, receiver.config.vault_path)
                except Exception as err:
                    receiver.log(f"ingest failed: {err}")
                    return self._respond(422, {"error": str(err)})
                if result.duplicate:
                    receiver.log(f"duplicate capture {result.capture_id} ignored")
                else:
                    receiver.log(f"captured {result.note_path}")
                self._respond(202, {"stored": result.capture_id})

        self.httpd = ThreadingHTTPServer(("0.0.0.0", self.config.port), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

        hostname = socket.gethostname().removesuffix(".local")
        self.zeroconf = Zeroconf()
        info = ServiceInfo(
            SERVICE_TYPE,
            f"VoiceVault CLI ({hostname}).{SERVICE_TYPE}",
            addresses=_local_addresses(),
            port=self.config.port,
            properties={},
        )
        self.zeroconf.register_service(info)
        self.log(
            f"listening on :{self.config.port}, advertising {SERVICE_TYPE} "
            f"fingerprint {fingerprint(self.config.public_key)}"
        )

    def stop(self) -> None:
        if self.zeroconf is not None:
            self.zeroconf.unregister_all_services()
            self.zeroconf.close()
        if self.httpd is not None:
            self.httpd.shutdown()
