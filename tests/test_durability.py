import base64
import json
import threading
from pathlib import Path

import pytest

from memoret_cli.config import InvalidConfig, validate
from memoret_cli.ingest import (
    INGESTED_INDEX,
    LEGACY_INGESTED_INDEX,
    PackageRejected,
    ingest_package,
)

from test_ingest import manifest_dict, package


def test_index_lives_outside_the_vault_contents(tmp_path: Path) -> None:
    ingest_package(package(manifest_dict()), tmp_path)
    assert (tmp_path / INGESTED_INDEX).exists()
    assert not (tmp_path / LEGACY_INGESTED_INDEX).exists()


def test_adopts_and_retires_an_index_left_at_the_old_path(tmp_path: Path) -> None:
    already = manifest_dict()["capture_id"]
    (tmp_path / LEGACY_INGESTED_INDEX).write_text(json.dumps([already]))

    # The capture in that index must still read as already delivered.
    result = ingest_package(package(manifest_dict()), tmp_path)
    assert result.duplicate is True

    # A later capture moves the index to its new home without losing the id.
    other = manifest_dict(capture_id="99999999-2222-4333-8444-555555555555")
    ingest_package(package(other), tmp_path)
    moved = set(json.loads((tmp_path / INGESTED_INDEX).read_text()))
    assert moved == {already, other["capture_id"]}
    assert not (tmp_path / LEGACY_INGESTED_INDEX).exists()


def test_concurrent_captures_all_survive_the_index(tmp_path: Path) -> None:
    """Two threads reading the old index and writing back their own id is
    exactly how one erased the other."""
    manifests = [
        manifest_dict(
            capture_id=f"{n:08d}-2222-4333-8444-555555555555",
            vault_note_path=f"notes/note-{n}.md",
            attachment_path=f"attachments/audio-{n}.m4a",
        )
        for n in range(12)
    ]
    barrier = threading.Barrier(len(manifests))
    errors: list[BaseException] = []

    def run(manifest: dict) -> None:
        try:
            barrier.wait()
            ingest_package(package(manifest), tmp_path)
        except BaseException as err:  # noqa: BLE001 - surfaced below
            errors.append(err)

    threads = [threading.Thread(target=run, args=(m,)) for m in manifests]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    recorded = set(json.loads((tmp_path / INGESTED_INDEX).read_text()))
    assert recorded == {m["capture_id"] for m in manifests}


def test_the_same_capture_arriving_twice_at_once_is_written_once(tmp_path: Path) -> None:
    manifest = manifest_dict()
    barrier = threading.Barrier(6)
    results = []

    def run() -> None:
        barrier.wait()
        results.append(ingest_package(package(manifest), tmp_path))

    threads = [threading.Thread(target=run) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(1 for r in results if not r.duplicate) == 1
    notes = list((tmp_path / "notes").iterdir())
    assert len(notes) == 1


def test_a_failed_note_write_leaves_no_orphan_audio(tmp_path: Path, monkeypatch) -> None:
    import memoret_cli.ingest as ingest_module

    def explode(self, *args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_text", explode)
    with pytest.raises(OSError):
        ingest_package(package(manifest_dict()), tmp_path)

    monkeypatch.undo()
    attachments = tmp_path / "attachments"
    assert not attachments.exists() or list(attachments.iterdir()) == []
    # The id was never recorded, so a redelivery is free to try again.
    assert ingest_module._load_index(tmp_path) == set()


def test_rejections_carry_a_stable_code(tmp_path: Path) -> None:
    with pytest.raises(PackageRejected) as caught:
        ingest_package(package(manifest_dict(), audio=None), tmp_path)
    assert caught.value.code == "missing_entry"

    with pytest.raises(PackageRejected) as caught:
        ingest_package(package(manifest_dict(), extra=[("manifest.json", b"{}")]), tmp_path)
    assert caught.value.code == "duplicate_entries"

    with pytest.raises(PackageRejected) as caught:
        ingest_package(package(manifest_dict(version=999)), tmp_path)
    assert caught.value.code == "invalid_manifest"


def valid_config() -> dict:
    return {
        "public_key": base64.b64encode(b"\x01" * 32).decode(),
        "private_key": base64.b64encode(b"\x02" * 32).decode(),
        "auth_token": "a-token",
        "port": 41831,
        "vault_dir": "~/Memoret",
    }


def test_accepts_a_well_formed_config() -> None:
    config = validate(valid_config())
    assert config.port == 41831


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("public_key", "not base64!", "not valid base64"),
        ("private_key", base64.b64encode(b"short").decode(), "must be 32 bytes"),
        ("auth_token", "", "auth_token is missing"),
        ("port", 0, "between 1 and 65535"),
        ("port", 70000, "between 1 and 65535"),
        ("port", True, "between 1 and 65535"),
        ("vault_dir", "   ", "vault_dir is missing"),
    ],
)
def test_rejects_a_broken_config(field: str, value: object, expected: str) -> None:
    raw = valid_config()
    raw[field] = value
    with pytest.raises(InvalidConfig, match=expected):
        validate(raw)


def test_rejects_missing_and_unexpected_fields() -> None:
    raw = valid_config()
    del raw["auth_token"]
    with pytest.raises(InvalidConfig, match="missing auth_token"):
        validate(raw)

    raw = valid_config()
    raw["surprise"] = 1
    with pytest.raises(InvalidConfig, match="unexpected surprise"):
        validate(raw)
