import io
import threading

import qrcode
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Footer, Header, RichLog, Static

from .config import Config
from .crypto import fingerprint
from .server import Receiver


def qr_ascii(payload: str) -> str:
    """Render a QR code as terminal text."""
    qr = qrcode.QRCode(border=1)
    qr.add_data(payload)
    out = io.StringIO()
    qr.print_ascii(out=out, invert=True)
    return out.getvalue()


class MemoretTUI(App):
    """Terminal receiver UI: status header, live capture log, and a
    toggleable pairing QR for the iOS app to scan."""

    TITLE = "Memoret"
    CSS = """
    #status { padding: 0 1; color: $text-muted; height: auto; }
    #qr { padding: 0 1; height: auto; }
    RichLog { border: none; }
    """
    BINDINGS = [
        Binding("p", "toggle_qr", "Pairing QR", priority=True),
        Binding("q", "quit", "Quit", priority=True),
    ]

    def __init__(self, config: Config):
        super().__init__()
        self.config = config
        self.receiver = Receiver(config, self.log_line)
        self.qr_visible = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static(self.status_text(), id="status")
            yield Static("", id="qr")
            yield RichLog(id="log", wrap=True)
        yield Footer()

    def status_text(self) -> str:
        return (
            f"vault {self.config.vault_path}  ·  port {self.config.port}  ·  "
            f"fingerprint {fingerprint(self.config.public_key)}  ·  "
            "press p to show the pairing QR"
        )

    def on_mount(self) -> None:
        self._ui_thread = threading.get_ident()
        log = self.query_one("#log", RichLog)
        log.can_focus = False
        log.write("Memoret receiver — press p to show the pairing QR")
        self.receiver.start()

    def on_unmount(self) -> None:
        """Zeroconf's synchronous shutdown cannot run inside Textual's
        event loop, so teardown happens on a worker thread."""
        stopper = threading.Thread(target=self.receiver.stop)
        stopper.start()
        stopper.join(timeout=3)

    def log_line(self, message: str) -> None:
        """Write a log line safely from either the UI thread (startup) or
        the HTTP server threads (captures)."""
        log = self.query_one("#log", RichLog)
        if threading.get_ident() == getattr(self, "_ui_thread", None):
            log.write(message)
        else:
            self.call_from_thread(log.write, message)

    def action_toggle_qr(self) -> None:
        self.qr_visible = not self.qr_visible
        qr = self.query_one("#qr", Static)
        qr.update(qr_ascii(self.config.pairing_json()) if self.qr_visible else "")
