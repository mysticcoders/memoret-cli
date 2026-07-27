import hmac
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from zeroconf import ServiceInfo, Zeroconf

from . import __version__
from .config import Config
from .crypto import MAGIC, fingerprint, open_sealed
from .ingest import PackageRejected, ingest_package
from .manifest import CAPTURE_KINDS

MAX_BODY = 64 * 1024 * 1024
SERVICE_TYPE = "_memoret._tcp.local."

# A connection may idle this long between reads, and a whole upload may take
# this long overall — together they bound slowloris-style connection holding.
SOCKET_TIMEOUT = 15
BODY_TIMEOUT = 120
BODY_CHUNK = 64 * 1024

# Concurrent connections are capped so a flood cannot spawn unbounded
# threads; the listen backlog is bounded for the same reason.
MAX_CONNECTIONS = 16

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


class BoundedHTTPServer(ThreadingHTTPServer):
    """A threading server that refuses connections beyond a fixed in-flight
    bound instead of spawning a thread per arrival, and routes handler
    errors to the receiver log rather than stderr (which would corrupt the
    TUI)."""

    daemon_threads = True
    request_queue_size = MAX_CONNECTIONS

    def __init__(self, address, handler, log: LogFn, max_connections: int = MAX_CONNECTIONS):
        self._slots = threading.BoundedSemaphore(max_connections)
        self._log = log
        super().__init__(address, handler)

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            self._log("connection refused: too many in flight")
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address) -> None:
        self._log("dropped connection after handler error")


class Receiver:
    """The LAN receiver: an HTTP server speaking the Memoret transport
    contract plus a zeroconf advertisement, decrypting and ingesting
    captures as they arrive."""

    def __init__(self, config: Config, log: LogFn):
        self.config = config
        self.log = log
        self.zeroconf: Zeroconf | None = None
        self.httpd: BoundedHTTPServer | None = None

    def start(self) -> None:
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            timeout = SOCKET_TIMEOUT

            def log_message(self, format: str, *args) -> None:
                pass

            def _read_body(self, length: int) -> bytes:
                """Read the declared body under a whole-upload deadline.
                read1 returns as soon as any bytes are available rather than
                blocking for a full chunk, and each read's timeout is capped
                by the time left, so a client trickling bytes below the idle
                timeout is still dropped at the deadline."""
                deadline = time.monotonic() + BODY_TIMEOUT
                chunks: list[bytes] = []
                remaining = length
                while remaining > 0:
                    budget = deadline - time.monotonic()
                    if budget <= 0:
                        raise TimeoutError("body read exceeded deadline")
                    self.connection.settimeout(min(SOCKET_TIMEOUT, budget))
                    chunk = self.rfile.read1(min(remaining, BODY_CHUNK))
                    if not chunk:
                        raise ConnectionError("client closed before body completed")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                return b"".join(chunks)

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
                        "service": "memoret",
                        "version": __version__,
                        "fingerprint": fingerprint(receiver.config.public_key),
                        # Comma-separated rather than a JSON array on
                        # purpose: shipped senders decode /ping as a flat
                        # string map, and an array value makes that decode
                        # throw, which would look like the receiver had
                        # vanished. Senders that do not know the field read
                        # this receiver as voice-only.
                        "capabilities": ",".join(CAPTURE_KINDS),
                    },
                )

            def do_POST(self) -> None:
                if self.path != "/capture":
                    return self._respond(404, {"error": "not found"})
                auth = self.headers.get("Authorization", "").removeprefix("Bearer ")
                if not hmac.compare_digest(auth, receiver.config.auth_token):
                    return self._respond(401, {"error": "unauthorized"})
                try:
                    length = int(self.headers.get("Content-Length", 0))
                except ValueError:
                    return self._respond(413, {"error": "bad body size"})
                if length <= 0 or length > MAX_BODY:
                    return self._respond(413, {"error": "bad body size"})
                try:
                    blob = self._read_body(length)
                except OSError as err:
                    receiver.log(f"dropped incomplete upload: {err}")
                    self.close_connection = True
                    return
                if not blob.startswith(MAGIC):
                    return self._respond(400, {"error": "not a VVSB sealed blob"})
                # The detail stays in the local log. What goes back on the
                # wire is a fixed code: an exception's text is written for
                # whoever is debugging, and can name paths or repeat the
                # contents of a rejected package.
                try:
                    package = open_sealed(blob, receiver.config.private_key)
                    result = ingest_package(package, receiver.config.vault_path)
                except PackageRejected as err:
                    receiver.log(f"ingest rejected ({err.code}): {err}")
                    return self._respond(422, {"error": err.code})
                except Exception as err:
                    receiver.log(f"ingest failed: {err!r}")
                    return self._respond(422, {"error": "unreadable_package"})
                if result.duplicate:
                    receiver.log(f"duplicate capture {result.capture_id} ignored")
                else:
                    receiver.log(f"captured {result.note_path}")
                self._respond(202, {"stored": result.capture_id})

        self.httpd = BoundedHTTPServer(("0.0.0.0", self.config.port), Handler, self.log)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        threading.Thread(target=self._register_mdns, daemon=True).start()
        self.log(
            f"listening on :{self.config.port}, "
            f"fingerprint {fingerprint(self.config.public_key)}"
        )

    def _register_mdns(self) -> None:
        """Register the mDNS advertisement on a plain thread: zeroconf's
        synchronous API deadlocks when created on a thread already running
        an asyncio loop (the Textual UI thread)."""
        try:
            hostname = socket.gethostname().removesuffix(".local")
            self.zeroconf = Zeroconf()
            info = ServiceInfo(
                SERVICE_TYPE,
                f"Memoret CLI ({hostname}).{SERVICE_TYPE}",
                addresses=_local_addresses(),
                port=self.config.port,
                properties={},
            )
            self.zeroconf.register_service(info)
            self.log(f"advertising {SERVICE_TYPE[:-7]} via mDNS")
        except Exception as err:
            self.log(f"mDNS registration failed: {err}")

    def stop(self) -> None:
        if self.zeroconf is not None:
            try:
                self.zeroconf.unregister_all_services()
                self.zeroconf.close()
            except Exception:
                pass
            self.zeroconf = None
        if self.httpd is not None:
            self.httpd.shutdown()
            # shutdown() only stops serve_forever; without this the listening
            # socket stays open, and restarting the receiver in the same
            # process fails to bind.
            self.httpd.server_close()
            self.httpd = None
