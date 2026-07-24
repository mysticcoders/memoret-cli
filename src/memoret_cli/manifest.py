import math
import re
from datetime import datetime
from typing import Any

MANIFEST_VERSION = 1

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


def _is_iso8601(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


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
    if not isinstance(created_at, str) or not _is_iso8601(created_at):
        raise ValueError("manifest: created_at must be an ISO-8601 timestamp")
    device_id = raw.get("device_id")
    if not isinstance(device_id, str) or not device_id:
        raise ValueError("manifest: device_id must be a non-empty string")
    for field in ("vault_note_path", "attachment_path"):
        if not is_safe_vault_path(raw.get(field)):
            raise ValueError(f"manifest: {field} is not a safe vault-relative path")
    tags = raw.get("tags")
    if not isinstance(tags, list) or not all(
        isinstance(t, str) and t for t in tags
    ):
        raise ValueError("manifest: tags must be an array of non-empty strings")
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
    return raw
