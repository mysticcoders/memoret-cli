import base64
import json
import os
import secrets
import socket
from dataclasses import dataclass
from pathlib import Path

from nacl.public import PrivateKey

CONFIG_DIR = Path.home() / ".memoret"
CONFIG_PATH = CONFIG_DIR / "config.json"
DEFAULT_PORT = 41831


@dataclass
class Config:
    public_key: str
    private_key: str
    auth_token: str
    port: int
    vault_dir: str

    @property
    def vault_path(self) -> Path:
        return Path(self.vault_dir).expanduser()

    def pairing_json(self) -> str:
        """Build the pairing payload the iOS app scans, matching the shape
        the Obsidian plugin emits."""
        hostname = socket.gethostname().removesuffix(".local")
        return json.dumps(
            {
                "pubkey": self.public_key,
                "auth_token": self.auth_token,
                "lan_hostname": hostname,
                "lan_port": self.port,
                "label": f"CLI ({hostname})",
            }
        )


def _write_private(path: Path, text: str) -> None:
    """Write a file holding key material without it ever being observable at
    looser than 0600: the temp file is created with O_EXCL at that mode
    regardless of umask, then atomically renamed over the target."""
    temp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def create(vault_dir: str, port: int) -> Config:
    """Generate a fresh keypair, auth token, and config file with owner-only
    permissions."""
    key = PrivateKey.generate()
    config = Config(
        public_key=base64.b64encode(bytes(key.public_key)).decode(),
        private_key=base64.b64encode(bytes(key)).decode(),
        auth_token=secrets.token_urlsafe(32),
        port=port,
        vault_dir=vault_dir,
    )
    CONFIG_DIR.mkdir(mode=0o700, exist_ok=True)
    _write_private(CONFIG_PATH, json.dumps(config.__dict__, indent=2) + "\n")
    return config


def load() -> Config | None:
    """Load the config if this machine has been initialized."""
    if not CONFIG_PATH.exists():
        return None
    return Config(**json.loads(CONFIG_PATH.read_text()))
