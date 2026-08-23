import base64
import os
import re
import socket

import pytest

from memoret_cli.crypto import (
    HEADER,
    MAGIC,
    fingerprint,
    generate_keypair,
    open_sealed,
    receiver_host,
    seal,
)


def test_round_trip_recovers_the_plaintext():
    public_key, private_key = generate_keypair()
    plaintext = os.urandom(4096)
    assert open_sealed(seal(plaintext, public_key), private_key) == plaintext


def test_overhead_is_header_plus_encapsulated_key_plus_tag():
    public_key, _ = generate_keypair()
    blob = seal(b"x" * 100, public_key)
    assert len(blob) - 100 == len(HEADER) + 32 + 16


def test_magic_is_the_version_free_prefix_of_the_header():
    # The server matches MAGIC alone so a future format revision does not
    # arrive as a rejected capture at a layer that never decrypts anything.
    assert HEADER.startswith(MAGIC)
    assert len(MAGIC) == 4


def test_rejects_a_blob_sealed_to_another_receiver():
    public_key, _ = generate_keypair()
    _, other_private = generate_keypair()
    with pytest.raises(Exception):
        open_sealed(seal(b"secret", public_key), other_private)


def test_rejects_a_tampered_ciphertext():
    public_key, private_key = generate_keypair()
    blob = bytearray(seal(b"secret", public_key))
    blob[-1] ^= 0xFF
    with pytest.raises(Exception):
        open_sealed(bytes(blob), private_key)


def test_rejects_an_edited_suite_header():
    # The header is the AEAD associated data, so editing the suite ids has to
    # fail rather than opening as some other scheme.
    public_key, private_key = generate_keypair()
    blob = bytearray(seal(b"secret", public_key))
    blob[9] ^= 0xFF
    with pytest.raises(Exception):
        open_sealed(bytes(blob), private_key)


def test_rejects_a_v1_blob():
    _, private_key = generate_keypair()
    with pytest.raises(ValueError, match="not a VVSB v2 sealed blob"):
        open_sealed(b"VVSB\x01" + os.urandom(64), private_key)


def test_rejects_a_truncated_blob():
    _, private_key = generate_keypair()
    with pytest.raises(ValueError, match="not a VVSB v2 sealed blob"):
        open_sealed(HEADER + os.urandom(8), private_key)


def test_keys_are_raw_32_bytes():
    # The config validator checks length, and pairings made under v1 have to
    # keep working: HPKE's X25519 encoding is the one libsodium used.
    public_key, private_key = generate_keypair()
    assert len(base64.b64decode(public_key)) == 32
    assert len(base64.b64decode(private_key)) == 32


def test_fingerprint_is_sixteen_hex_chars_of_sha256():
    public_key, _ = generate_keypair()
    value = fingerprint(public_key)
    assert len(value) == 16
    assert all(c in "0123456789abcdef" for c in value)


def test_receiver_host_does_not_borrow_the_machine_name():
    """A sender falls back to <lan_hostname>.local exactly when discovery is
    failing, so that name cannot be one the operating system may reassign."""
    public_key, _ = generate_keypair()
    host = receiver_host(public_key)
    machine = socket.gethostname().removesuffix(".local")
    assert machine not in host
    assert host == f"memoret-{fingerprint(public_key)}"


def test_receiver_host_is_a_legal_dns_label():
    public_key, _ = generate_keypair()
    host = receiver_host(public_key)
    assert len(host) <= 63
    assert re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", host)
