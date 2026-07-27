import io
import json
import zipfile
from pathlib import Path

import pytest

from memoret_cli.ingest import ingest_package, rewrite_audio_embed

CAPTURE_ID = "11111111-2222-4333-8444-555555555555"


def manifest_dict(**overrides) -> dict:
    base = {
        "version": 1,
        "capture_id": CAPTURE_ID,
        "created_at": "2026-07-22T14:30:00-07:00",
        "device_id": "test-device",
        "vault_note_path": "notes/2026-07-22-1430.md",
        "attachment_path": "attachments/2026-07-22-1430.m4a",
        "tags": ["voice", "capture"],
        "duration_seconds": 92,
        "transcript_model": "parakeet-v3",
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not None}


def note_for(manifest: dict, body: str = "a transcript") -> str:
    """Render a note the way the sender does, embedding the manifest's own
    attachment path."""
    lines = ["---", f"created: {manifest['created_at'][:16]}", "---"]
    if "attachment_path" in manifest:
        lines.append(f"![[{manifest['attachment_path']}]]")
    lines += ["", body, ""]
    return "\n".join(lines)


def package(manifest: dict, *, audio: bytes | None = b"\x00\x01", note: str | None = None,
            extra: list[tuple[str, bytes]] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("transcript.md", note if note is not None else note_for(manifest))
        if audio is not None:
            archive.writestr("audio.m4a", audio)
        for name, data in extra or []:
            archive.writestr(name, data)
    return buffer.getvalue()


def test_writes_note_and_audio_at_manifest_paths(tmp_path: Path) -> None:
    result = ingest_package(package(manifest_dict()), tmp_path)
    assert result.duplicate is False
    assert result.note_path == "notes/2026-07-22-1430.md"
    assert result.audio_path == "attachments/2026-07-22-1430.m4a"
    assert (tmp_path / result.note_path).exists()
    assert (tmp_path / result.audio_path).read_bytes() == b"\x00\x01"


def test_dedupes_by_capture_id(tmp_path: Path) -> None:
    ingest_package(package(manifest_dict()), tmp_path)
    again = ingest_package(package(manifest_dict()), tmp_path)
    assert again.duplicate is True


def test_link_capture_writes_no_audio(tmp_path: Path) -> None:
    manifest = manifest_dict(
        kind="link", attachment_path=None, duration_seconds=None, transcript_model=None
    )
    result = ingest_package(package(manifest, audio=None), tmp_path)
    assert result.audio_path is None
    assert (tmp_path / result.note_path).exists()


def test_collision_search_does_not_stop_at_the_first_alternate(tmp_path: Path) -> None:
    (tmp_path / "notes").mkdir()
    (tmp_path / "attachments").mkdir()
    (tmp_path / "notes/2026-07-22-1430.md").write_text("taken")
    (tmp_path / f"notes/2026-07-22-1430-{CAPTURE_ID}.md").write_text("also taken")
    (tmp_path / "attachments/2026-07-22-1430.m4a").write_bytes(b"taken")
    (tmp_path / f"attachments/2026-07-22-1430-{CAPTURE_ID}.m4a").write_bytes(b"also taken")

    result = ingest_package(package(manifest_dict()), tmp_path)

    assert result.note_path == f"notes/2026-07-22-1430-{CAPTURE_ID}-2.md"
    assert result.audio_path == f"attachments/2026-07-22-1430-{CAPTURE_ID}-2.m4a"
    # Nothing that was already there may be overwritten.
    assert (tmp_path / "notes/2026-07-22-1430.md").read_text() == "taken"
    assert (
        tmp_path / f"notes/2026-07-22-1430-{CAPTURE_ID}.md"
    ).read_text() == "also taken"
    assert (tmp_path / "attachments/2026-07-22-1430.m4a").read_bytes() == b"taken"


def test_embed_follows_a_renamed_attachment(tmp_path: Path) -> None:
    (tmp_path / "attachments").mkdir()
    (tmp_path / "attachments/2026-07-22-1430.m4a").write_bytes(b"taken")

    result = ingest_package(package(manifest_dict()), tmp_path)

    assert result.audio_path != "attachments/2026-07-22-1430.m4a"
    note = (tmp_path / result.note_path).read_text()
    assert f"![[{result.audio_path}]]" in note
    assert "![[attachments/2026-07-22-1430.m4a]]" not in note


def test_embed_untouched_when_the_attachment_keeps_its_path(tmp_path: Path) -> None:
    result = ingest_package(package(manifest_dict()), tmp_path)
    note = (tmp_path / result.note_path).read_text()
    assert "![[attachments/2026-07-22-1430.m4a]]" in note


def test_rewrite_leaves_an_identical_line_elsewhere_alone() -> None:
    note = "\n".join(
        [
            "---",
            "created: 2026-07-22T14:30",
            "---",
            "![[attachments/a.m4a]]",
            "",
            "I wrote ![[attachments/a.m4a]] in my notes",
            "![[attachments/a.m4a]]",
        ]
    )
    out = rewrite_audio_embed(note, "attachments/a.m4a", "attachments/a-2.m4a").split("\n")
    assert out[3] == "![[attachments/a-2.m4a]]"
    assert out[5] == "I wrote ![[attachments/a.m4a]] in my notes"
    assert out[6] == "![[attachments/a.m4a]]"


def test_rejects_duplicate_entry_names(tmp_path: Path) -> None:
    manifest = manifest_dict()
    blob = package(manifest, extra=[("manifest.json", b"{}")])
    with pytest.raises(ValueError, match="duplicate entries"):
        ingest_package(blob, tmp_path)


def test_rejects_a_voice_capture_with_no_audio(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing audio.m4a"):
        ingest_package(package(manifest_dict(), audio=None), tmp_path)
