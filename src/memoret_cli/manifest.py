import math
import re
from datetime import datetime
from typing import Any

MANIFEST_VERSION = 1

# What a capture carries. "voice" is a recording with audio; "link" is a URL
# shared from elsewhere and has no audio of its own. The field is optional
# and absent means "voice", so captures written before it existed stay
# valid — which is also why the version stays at 1. Receivers advertise the
# kinds they accept on /ping instead.
CAPTURE_KINDS = ("voice", "link")
AUDIO_FIELDS = ("attachment_path", "duration_seconds", "transcript_model")

UUID_V4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def is_safe_vault_path(path: Any) -> bool:
    """Reject vault-relative paths that could escape the vault or write into
    hidden directories, mirroring the contract's isSafeVaultPath."""
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
        return False
    return all(
        p and p not in (".", "..") and not p.startswith(".") for p in path.split("/")
    )


RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)


def _is_rfc3339(value: str) -> bool:
    """A date and a time with an offset, which is what every sender emits.

    This used to be datetime.fromisoformat, which accepts a bare date and a
    space-separated time. The Swift receiver accepted neither, so the two
    disagreed about what a valid capture was — see the shared corpus at
    github.com/mysticcoders/memoret-contract-fixtures. The offset is
    required because a local time is ambiguous and nothing downstream can
    recover which one was meant.

    The shape is checked before the value, since a regex alone would admit
    February 30th."""
    if not RFC3339.match(value):
        return False
    try:
        # Python parses the offset itself, and rejects an impossible day
        # rather than rolling it forward the way some libraries do.
        datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return False
    return True


def manifest_kind(manifest: dict) -> str:
    """The kind a manifest declares, treating absence as "voice"."""
    return manifest.get("kind") or "voice"


def validate_manifest(raw: Any) -> dict:
    """Validate a decoded manifest against the same rules as the Swift and
    TypeScript receivers, raising on the first violation found."""
    if not isinstance(raw, dict):
        raise ValueError("manifest: not an object")
    if raw.get("version") != MANIFEST_VERSION:
        raise ValueError(f"manifest: unsupported version {raw.get('version')!r}")
    capture_id = raw.get("capture_id")
    if not isinstance(capture_id, str) or not UUID_V4.match(capture_id):
        raise ValueError("manifest: capture_id must be a UUID v4")
    created_at = raw.get("created_at")
    if not isinstance(created_at, str) or not _is_rfc3339(created_at):
        raise ValueError("manifest: created_at must be an RFC 3339 timestamp")
    device_id = raw.get("device_id")
    if not isinstance(device_id, str) or not device_id:
        raise ValueError("manifest: device_id must be a non-empty string")
    if not is_safe_vault_path(raw.get("vault_note_path")):
        raise ValueError("manifest: vault_note_path is not a safe vault-relative path")
    tags = raw.get("tags")
    if not isinstance(tags, list) or not all(
        isinstance(t, str) and t for t in tags
    ):
        raise ValueError("manifest: tags must be an array of non-empty strings")
    kind = raw.get("kind")
    if kind is not None and kind not in CAPTURE_KINDS:
        raise ValueError(f"manifest: unsupported kind {kind!r}")
    kind = kind or "voice"

    # The audio-bearing fields travel together: a voice capture carries all of
    # them, a link capture none. A half-populated manifest would leave the
    # receiver guessing whether to expect an audio entry.
    if kind == "voice":
        # Absence and unsafety are reported apart. Telling someone their
        # attachment_path is unsafe when they never sent one points at path
        # validation instead of at the missing field.
        for field in AUDIO_FIELDS:
            if raw.get(field) is None:
                raise ValueError(f"manifest: a voice capture must carry {field}")
        if not is_safe_vault_path(raw.get("attachment_path")):
            raise ValueError(
                "manifest: attachment_path is not a safe vault-relative path")
        duration = raw.get("duration_seconds")
        if (
            not isinstance(duration, (int, float))
            or isinstance(duration, bool)
            or not math.isfinite(duration)
            or duration < 0
        ):
            raise ValueError("manifest: duration_seconds must be a non-negative number")
        transcript_model = raw.get("transcript_model")
        if not isinstance(transcript_model, str) or not transcript_model:
            raise ValueError("manifest: transcript_model must be a non-empty string")
    else:
        for field in AUDIO_FIELDS:
            if raw.get(field) is not None:
                raise ValueError(f"manifest: {field} is not allowed on a {kind} capture")
    return raw
