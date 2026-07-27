"""The shared corpus this receiver is measured against.

The corpus lives in its own public repository so every implementation reads
one copy rather than keeping its own. Fetch it with:

    scripts/fetch-fixtures.sh

CI does that before running the suite. Missing fixtures fail loudly rather
than skipping: a conformance suite that quietly runs nothing is worse than
no conformance suite, because it reads as agreement.
"""

import json
from pathlib import Path

import pytest

from memoret_cli.manifest import validate_manifest

CORPUS = Path(__file__).resolve().parent.parent / "fixtures" / "manifests.json"


def load_corpus() -> dict:
    if not CORPUS.exists():
        raise AssertionError(
            f"conformance corpus missing at {CORPUS}. "
            "Run scripts/fetch-fixtures.sh to download it."
        )
    return json.loads(CORPUS.read_text())


def corpus_cases() -> list:
    return load_corpus()["cases"]


def test_corpus_is_not_empty() -> None:
    """A mis-resolved path must not pass as agreement."""
    assert len(corpus_cases()) > 10


@pytest.mark.parametrize("case", corpus_cases(), ids=lambda c: c["name"])
def test_manifest_matches_the_corpus(case: dict) -> None:
    if case["accept"]:
        validate_manifest(case["manifest"])
        return

    with pytest.raises(ValueError) as caught:
        validate_manifest(case["manifest"])

    reason = case.get("reason")
    if reason is None:
        return
    # Matched on a manifest field name rather than on wording. Field names
    # are JSON keys and identical in every implementation; sentences are
    # not, and four languages will never share them. "audio_fields" is a
    # rule rather than a field, and both halves of it name attachment_path.
    expected = "attachment_path" if reason == "audio_fields" else reason
    assert expected in str(caught.value)
