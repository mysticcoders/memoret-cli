import io
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path

INGESTED_INDEX = "ingested.json"


@dataclass
class IngestResult:
    capture_id: str
    duplicate: bool
    note_path: str | None = None
    audio_path: str | None = None


def _safe(path: str) -> bool:
    """Reject vault-relative paths that could escape the vault or write
    into hidden directories."""
    if not path or path.startswith("/") or "\\" in path:
        return False
    parts = path.split("/")
    return all(p and p not in (".", "..") and not p.startswith(".") for p in parts)


def _load_index(vault: Path) -> set[str]:
    index = vault / INGESTED_INDEX
    if index.exists():
        return set(json.loads(index.read_text()))
    return set()


def _save_index(vault: Path, ids: set[str]) -> None:
    (vault / INGESTED_INDEX).write_text(json.dumps(sorted(ids)) + "\n")


def ingest_package(package: bytes, vault: Path) -> IngestResult:
    """Unpack a decrypted capture package and write the note plus audio at
    their manifest paths, deduplicating by capture id and suffixing on
    collisions — the same contract the Obsidian plugin implements."""
    archive = zipfile.ZipFile(io.BytesIO(package))
    names = set(archive.namelist())
    for required in ("manifest.json", "transcript.md", "audio.m4a"):
        if required not in names:
            raise ValueError(f"package missing {required}")
    manifest = json.loads(archive.read("manifest.json"))
    capture_id = manifest.get("capture_id", "")
    if not capture_id:
        raise ValueError("manifest missing capture_id")
    note_rel = manifest.get("vault_note_path", "")
    audio_rel = manifest.get("attachment_path", "")
    if not _safe(note_rel) or not _safe(audio_rel):
        raise ValueError("manifest contains unsafe vault paths")

    seen = _load_index(vault)
    if capture_id in seen:
        return IngestResult(capture_id=capture_id, duplicate=True)

    note_path = vault / note_rel
    audio_path = vault / audio_rel
    short = capture_id[:8]
    if note_path.exists():
        note_path = note_path.with_name(f"{note_path.stem}-{short}{note_path.suffix}")
    if audio_path.exists():
        audio_path = audio_path.with_name(f"{audio_path.stem}-{short}{audio_path.suffix}")
    note_path.parent.mkdir(parents=True, exist_ok=True)
    audio_path.parent.mkdir(parents=True, exist_ok=True)
    audio_path.write_bytes(archive.read("audio.m4a"))
    note_path.write_text(archive.read("transcript.md").decode("utf-8"))

    seen.add(capture_id)
    _save_index(vault, seen)
    return IngestResult(
        capture_id=capture_id,
        duplicate=False,
        note_path=str(note_path.relative_to(vault)),
        audio_path=str(audio_path.relative_to(vault)),
    )
