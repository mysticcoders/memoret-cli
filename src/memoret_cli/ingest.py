import io
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .manifest import manifest_kind, validate_manifest

INGESTED_INDEX = "ingested.json"

# Per-entry uncompressed size ceilings. The 64 MB body cap bounds only the
# sealed (compressed) blob; without these, a decrypted entry could inflate
# to gigabytes and exhaust memory or disk (a zip bomb).
MAX_ENTRY_BYTES = {
    "manifest.json": 1 * 1024 * 1024,
    "transcript.md": 10 * 1024 * 1024,
    "audio.m4a": 128 * 1024 * 1024,
}
MAX_ENTRIES = 8


def _read_capped(archive: zipfile.ZipFile, name: str, cap: int) -> bytes:
    """Reads a zip entry, rejecting it if its declared or actual
    uncompressed size exceeds the cap. The declared-size check is cheap;
    the bounded read defends against a header that understates the size."""
    if archive.getinfo(name).file_size > cap:
        raise ValueError(f"package entry {name} exceeds size limit")
    with archive.open(name) as member:
        data = member.read(cap + 1)
    if len(data) > cap:
        raise ValueError(f"package entry {name} exceeds size limit")
    return data


@dataclass
class IngestResult:
    capture_id: str
    duplicate: bool
    note_path: str | None = None
    audio_path: str | None = None


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
    if len(archive.infolist()) > MAX_ENTRIES:
        raise ValueError("package has too many entries")
    names = set(archive.namelist())
    for required in ("manifest.json", "transcript.md"):
        if required not in names:
            raise ValueError(f"package missing {required}")
    manifest = validate_manifest(json.loads(
        _read_capped(archive, "manifest.json", MAX_ENTRY_BYTES["manifest.json"])))
    capture_id = manifest["capture_id"]
    note_rel = manifest["vault_note_path"]

    # Audio belongs to voice captures only, and the manifest validator has
    # already checked that the audio-bearing fields match the kind.
    kind = manifest_kind(manifest)
    has_audio = "audio.m4a" in names
    if kind == "voice" and not has_audio:
        raise ValueError("package missing audio.m4a")
    if kind != "voice" and has_audio:
        raise ValueError(f"package for a {kind} capture must not carry audio.m4a")

    seen = _load_index(vault)
    if capture_id in seen:
        return IngestResult(capture_id=capture_id, duplicate=True)

    short = capture_id[:8]
    note_path = vault / note_rel
    if note_path.exists():
        note_path = note_path.with_name(f"{note_path.stem}-{short}{note_path.suffix}")
    note_path.parent.mkdir(parents=True, exist_ok=True)

    audio_path: Path | None = None
    if has_audio:
        audio_path = vault / manifest["attachment_path"]
        if audio_path.exists():
            audio_path = audio_path.with_name(
                f"{audio_path.stem}-{short}{audio_path.suffix}")
        audio_path.parent.mkdir(parents=True, exist_ok=True)
        audio_path.write_bytes(
            _read_capped(archive, "audio.m4a", MAX_ENTRY_BYTES["audio.m4a"]))

    note_path.write_text(
        _read_capped(archive, "transcript.md", MAX_ENTRY_BYTES["transcript.md"]).decode("utf-8"))

    seen.add(capture_id)
    _save_index(vault, seen)
    return IngestResult(
        capture_id=capture_id,
        duplicate=False,
        note_path=str(note_path.relative_to(vault)),
        audio_path=str(audio_path.relative_to(vault)) if audio_path else None,
    )
