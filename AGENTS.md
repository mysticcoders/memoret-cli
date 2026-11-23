# Working in memoret-cli

This is the terminal Memoret receiver, published on PyPI as `memoret-cli`: it holds a private key, advertises itself on the local network, accepts sealed captures (`src/memoret_cli/server.py`), opens them (`crypto.py`), validates the manifest (`manifest.py`) and writes notes and audio into a folder (`ingest.py`). The protocol, its vocabulary and the ingest rules are on [developer.memoret.app](https://developer.memoret.app); use the terms in [its glossary](https://developer.memoret.app/#glossary).

## The contract

- This is an independent Python implementation of the Memoret contract, using pyhpke. It agrees with the Swift and TypeScript implementations by specification and by tests, not by shared code.
- Manifest behavior is pinned by [memoret-contract-fixtures](https://github.com/mysticcoders/memoret-contract-fixtures). A disagreement with the corpus is a bug here unless the corpus is wrong, in which case it is fixed there first, tagged, and adopted by changing the tag in `scripts/fetch-fixtures.sh`.
- Don't extend the format or accept input the corpus rejects. A capture one receiver accepts and another rejects is the drift the corpus exists to stop.

## Rules

- The private key never leaves this machine. Never log or persist plaintext captures, transcripts, keys or pairing tokens.
- Follow the ingest rules on the developer site for idempotency, path safety, collisions, embed rewriting, write order, cleanup on failure and quarantine. Never write outside the configured folder.

## Checks

- `scripts/fetch-fixtures.sh`, then `uv run --group dev pytest`. CI runs the suite on every supported Python version.
- Tests do not verify a real phone or Bonjour on a real network; say which evidence you have.

## Delivery

- Work on a branch and open a pull request with the problem, the change, how it was verified, and what remains.
- Pushing a `v*` tag publishes to PyPI (`.github/workflows/publish.yml`). Only tag when asked to release.
