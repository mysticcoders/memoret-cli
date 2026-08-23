import base64
import hashlib
import os

from pyhpke import AEADId, CipherSuite, KDFId, KEMId

# `VVSB`, the stable part of the header. The version byte that follows it
# moves when the crypto does, so the server's pre-check — which only needs to
# tell our bytes from garbage before handing the blob on — matches this alone
# rather than pinning a scheme it does not decrypt at that layer.
MAGIC = b"VVSB"

VERSION = 0x02

# The full 11-byte v2 header: magic, version, then the RFC 9180 codepoints
# naming the suite — KEM 0x0020 DHKEM(X25519, HKDF-SHA256), KDF 0x0001
# HKDF-SHA256, AEAD 0x0003 ChaCha20-Poly1305. Also passed as associated data,
# so an edited header fails to open rather than opening as something else.
HEADER = b"VVSB\x02\x00\x20\x00\x01\x00\x03"

# X25519 encapsulated key, fixed width for this suite.
ENCAPSULATED_KEY_BYTES = 32

# Domain separation for the HPKE key schedule. Every implementation must pass
# these exact bytes; a mismatch surfaces only as a failed open, a long way
# from the cause.
INFO = b"memoret/vvsb/2"

SUITE = CipherSuite.new(
    KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305
)


def generate_keypair() -> tuple[str, str]:
    """Generate the receiver-owned X25519 keypair, returned as base64
    (public, private).

    The raw encoding is the one libsodium used, so pairings created under v1
    keep working — the blob format broke, the keys did not.
    """
    keypair = SUITE.kem.derive_key_pair(os.urandom(32))
    return (
        base64.b64encode(keypair.public_key.to_public_bytes()).decode(),
        base64.b64encode(keypair.private_key.to_private_bytes()).decode(),
    )


def open_sealed(blob: bytes, private_key_b64: str) -> bytes:
    """Open a VVSB v2 sealed blob with the receiver's private key.

    Raises ValueError on a header that is not ours; the underlying HPKE
    failure propagates for a wrong key or corrupted ciphertext, which the
    server routes to quarantine rather than retrying forever.
    """
    minimum = len(HEADER) + ENCAPSULATED_KEY_BYTES
    if len(blob) < minimum or not blob.startswith(HEADER):
        raise ValueError("not a VVSB v2 sealed blob")
    enc, ciphertext = blob[len(HEADER):minimum], blob[minimum:]
    private_key = SUITE.kem.deserialize_private_key(base64.b64decode(private_key_b64))
    recipient = SUITE.create_recipient_context(enc, private_key, info=INFO)
    return recipient.open(ciphertext, aad=HEADER)


def seal(plaintext: bytes, public_key_b64: str) -> bytes:
    """Seal plaintext to a recipient public key, prepending the v2 header.

    This receiver never seals in normal operation; it exists so the Python
    copy of the contract stays faithful to the others and so tests can
    produce their own inputs rather than depending on a checked-in ciphertext
    that nothing would notice going stale.
    """
    public_key = SUITE.kem.deserialize_public_key(base64.b64decode(public_key_b64))
    enc, sender = SUITE.create_sender_context(public_key, info=INFO)
    return HEADER + enc + sender.seal(plaintext, aad=HEADER)


def fingerprint(public_key_b64: str) -> str:
    """First 16 hex chars of SHA-256 over the raw public key, matching the
    fingerprint the iOS app validates during discovery."""
    raw = base64.b64decode(public_key_b64)
    return hashlib.sha256(raw).hexdigest()[:16]


def receiver_host(public_key_b64: str) -> str:
    """The `.local` name this receiver answers to, without the suffix.

    Deliberately not the machine's own hostname. A sender falls back to
    `<lan_hostname>.local` when discovery fails — the one moment the address
    has to be right — and a machine name can be reassigned underneath a
    pairing that was saved months earlier. mDNS name conflicts do exactly
    that on macOS, renaming the host to `<name>-2` and keeping it.

    A name derived from the fingerprint is stable for the life of the
    keypair, and this receiver publishes it itself.
    """
    return f"memoret-{fingerprint(public_key_b64)}"
