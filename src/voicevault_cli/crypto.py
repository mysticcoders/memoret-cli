import base64
import hashlib

from nacl.public import PrivateKey, SealedBox

MAGIC = b"VVSB\x01"


def open_sealed(blob: bytes, private_key_b64: str) -> bytes:
    """Open a VVSB v1 sealed blob (crypto_box_seal ciphertext behind the
    magic header) with the receiver's private key."""
    if not blob.startswith(MAGIC):
        raise ValueError("not a VVSB v1 sealed blob")
    key = PrivateKey(base64.b64decode(private_key_b64))
    return SealedBox(key).decrypt(blob[len(MAGIC):])


def fingerprint(public_key_b64: str) -> str:
    """First 16 hex chars of SHA-256 over the raw public key, matching the
    fingerprint the iOS app validates during discovery."""
    raw = base64.b64decode(public_key_b64)
    return hashlib.sha256(raw).hexdigest()[:16]
