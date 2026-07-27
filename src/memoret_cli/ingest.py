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

# How many suffixed names to try before giving up. Reaching this means
# something is wrong with the vault rather than with the capture, and
# failing loudly beats spinning forever.
MAX_COLLISION_ATTEMPTS = 1000


def _free_path(path: Path, capture_id: str) -> Path:
    """Pick a destination nothing already occupies.

    The first fallback carries the whole capture id, not a prefix of it:
    needing a fallback at all means two captures already want one name, and
    truncating the id is what makes a second clash likelier. The counter
    after it guarantees the search ends. The previous version returned its
    single alternate unchecked, which silently overwrote whatever was
    already there."""
    if not path.exists():
        return path
    candidate = path.with_name(f"{path.stem}-{capture_id}{path.suffix}")
    if not candidate.exists():
        return candidate
    for n in range(2, MAX_COLLISION_ATTEMPTS):
        candidate = path.with_name(f"{path.stem}-{capture_id}-{n}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise ValueError(f"no free destination for {path}")


def rewrite_audio_embed(transcript: str, from_path: str, to_path: str) -> str:
    """Point the note's audio embed at where the attachment actually landed.

    The sender writes the embed from its own manifest path, but a collision
    can rename the file underneath it, leaving the note linking to
    something that is not there.

    The whole line is matched rather than the path alone, so a transcript
    that quotes the same text is left intact, and only the first such line
    is rewritten — the contract emits exactly one, immediately after the
    frontmatter."""
    if from_path == to_path:
        return transcript
    lines = transcript.split("\n")
    target = f"![[{from_path}]]"
    for index, line in enumerate(lines):
        if line == target:
            lines[index] = f"![[{to_path}]]"
            break
    return "\n".join(lines)


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
    listed = archive.namelist()
    # Collapsing straight to a set hid a package carrying the same name
    # twice, where which copy gets read is a property of the zip reader
    # rather than of the contract.
    if len(listed) != len(set(listed)):
        raise ValueError("package has duplicate entries")
    names = set(listed)
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

    note_path = _free_path(vault / note_rel, capture_id)
    note_path.parent.mkdir(parents=True, exist_ok=True)

    audio_path: Path | None = None
    if has_audio:
        audio_path = _free_path(vault / manifest["attachment_path"], capture_id)
        audio_path.parent.mkdir(parents=True, exist_ok=True)
        audio_path.write_bytes(
            _read_capped(archive, "audio.m4a", MAX_ENTRY_BYTES["audio.m4a"]))

    transcript = _read_capped(
        archive, "transcript.md", MAX_ENTRY_BYTES["transcript.md"]).decode("utf-8")
    # The embed the sender wrote names its own manifest path, which is only
    # where the audio ends up when nothing renamed it. Written after the
    # destination is settled, never before.
    if audio_path is not None:
        transcript = rewrite_audio_embed(
            transcript,
            manifest["attachment_path"],
            str(audio_path.relative_to(vault)),
        )
    note_path.write_text(transcript)

    seen.add(capture_id)
    _save_index(vault, seen)
    return IngestResult(
        capture_id=capture_id,
        duplicate=False,
        note_path=str(note_path.relative_to(vault)),
        audio_path=str(audio_path.relative_to(vault)) if audio_path else None,
    )
