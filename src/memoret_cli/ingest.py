import io
import json
import os
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .manifest import manifest_kind, validate_manifest

# Receiver bookkeeping lives beside the vault's contents rather than in it.
# The old location put a machine-readable index in the middle of the user's
# notes, where it shows up in searches and file listings as if it were one.
METADATA_DIR = ".memoret"
INGESTED_INDEX = f"{METADATA_DIR}/ingested.json"
LEGACY_INGESTED_INDEX = "ingested.json"


class PackageRejected(ValueError):
    """A capture that will never ingest, however many times it is sent.

    Carries a stable code for the sender, so the wire response does not
    become a channel for whatever text an exception happened to hold."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


# One lock per vault, so the read-modify-write of the index cannot interleave
# with another request's. The server is threaded, and without this two
# captures arriving together both read the old index and the second write
# erased the first — and two copies of one capture could both pass the
# duplicate check.
#
# This covers threads in this process, which is what the threaded server
# creates. Two `memoret serve` processes pointed at one vault would still
# race; they cannot share a port, so that needs deliberate misconfiguration.
_vault_locks: dict[Path, threading.Lock] = {}
_vault_locks_guard = threading.Lock()


def _vault_lock(vault: Path) -> threading.Lock:
    key = vault.resolve()
    with _vault_locks_guard:
        lock = _vault_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _vault_locks[key] = lock
        return lock

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
    """Read the dedupe index, adopting one left at the old vault-root path.

    Losing this set would not corrupt anything, but it would let every
    capture already delivered arrive a second time on the next redelivery,
    so the old file is read rather than ignored."""
    index = vault / INGESTED_INDEX
    if index.exists():
        return set(json.loads(index.read_text()))
    legacy = vault / LEGACY_INGESTED_INDEX
    if legacy.exists():
        return set(json.loads(legacy.read_text()))
    return set()


def _save_index(vault: Path, ids: set[str]) -> None:
    """Replace the index atomically, so an interruption mid-write leaves the
    previous index intact rather than a truncated file that reads as no
    captures having ever arrived."""
    index = vault / INGESTED_INDEX
    index.parent.mkdir(parents=True, exist_ok=True)
    temp = index.with_name(f"{index.name}.{os.getpid()}.tmp")
    try:
        with open(temp, "w") as handle:
            handle.write(json.dumps(sorted(ids)) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, index)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
    # Only once the new index is in place, so a crash between the two leaves
    # the old file to be adopted rather than nothing at all.
    (vault / LEGACY_INGESTED_INDEX).unlink(missing_ok=True)


def ingest_package(package: bytes, vault: Path) -> IngestResult:
    """Unpack a decrypted capture package and write the note plus audio at
    their manifest paths, deduplicating by capture id and suffixing on
    collisions — the same contract the Obsidian plugin implements."""
    archive = zipfile.ZipFile(io.BytesIO(package))
    if len(archive.infolist()) > MAX_ENTRIES:
        raise PackageRejected("too_many_entries", "package has too many entries")
    listed = archive.namelist()
    # Collapsing straight to a set hid a package carrying the same name
    # twice, where which copy gets read is a property of the zip reader
    # rather than of the contract.
    if len(listed) != len(set(listed)):
        raise PackageRejected("duplicate_entries", "package has duplicate entries")
    names = set(listed)
    for required in ("manifest.json", "transcript.md"):
        if required not in names:
            raise PackageRejected("missing_entry", f"package missing {required}")
    try:
        manifest = validate_manifest(json.loads(
            _read_capped(archive, "manifest.json", MAX_ENTRY_BYTES["manifest.json"])))
    except PackageRejected:
        raise
    except Exception as err:
        raise PackageRejected("invalid_manifest", str(err)) from err
    capture_id = manifest["capture_id"]
    note_rel = manifest["vault_note_path"]

    # Audio belongs to voice captures only, and the manifest validator has
    # already checked that the audio-bearing fields match the kind.
    kind = manifest_kind(manifest)
    has_audio = "audio.m4a" in names
    if kind == "voice" and not has_audio:
        raise PackageRejected("missing_entry", "package missing audio.m4a")
    if kind != "voice" and has_audio:
        raise PackageRejected(
            "kind_mismatch", f"package for a {kind} capture must not carry audio.m4a")

    # Checking for a duplicate, reserving names, writing, and recording the
    # id are one operation. Interleaved, two captures arriving together both
    # read the old index and the second write erased the first, and two
    # copies of one capture could both get past the duplicate check.
    with _vault_lock(vault):
        seen = _load_index(vault)
        if capture_id in seen:
            return IngestResult(capture_id=capture_id, duplicate=True)

        note_path = _free_path(vault / note_rel, capture_id)
        note_path.parent.mkdir(parents=True, exist_ok=True)

        audio_path: Path | None = None
        written: list[Path] = []
        try:
            if has_audio:
                audio_path = _free_path(vault / manifest["attachment_path"], capture_id)
                audio_path.parent.mkdir(parents=True, exist_ok=True)
                audio_path.write_bytes(
                    _read_capped(archive, "audio.m4a", MAX_ENTRY_BYTES["audio.m4a"]))
                written.append(audio_path)

            transcript = _read_capped(
                archive, "transcript.md", MAX_ENTRY_BYTES["transcript.md"]).decode("utf-8")
            # The embed the sender wrote names its own manifest path, which
            # is only where the audio ends up when nothing renamed it.
            # Written after the destination is settled, never before.
            if audio_path is not None:
                transcript = rewrite_audio_embed(
                    transcript,
                    manifest["attachment_path"],
                    str(audio_path.relative_to(vault)),
                )
            note_path.write_text(transcript)
            written.append(note_path)

            seen.add(capture_id)
            _save_index(vault, seen)
        except BaseException:
            # Audio is written before the note, so a failure between them
            # used to leave the recording behind with nothing referring to
            # it — and the redelivery would route around the orphan into a
            # collision name rather than replacing it.
            for path in written:
                path.unlink(missing_ok=True)
            raise

    return IngestResult(
        capture_id=capture_id,
        duplicate=False,
        note_path=str(note_path.relative_to(vault)),
        audio_path=str(audio_path.relative_to(vault)) if audio_path else None,
    )
