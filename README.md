# memoret-cli

The terminal **receiver** for [Memoret](https://memoret.app). Memoret captures
voice notes on iOS, transcribes them on-device, and delivers them
**end-to-end encrypted** to a receiver you control. This CLI is one such
receiver: it holds the private key, listens on your LAN, and writes decrypted
notes and audio into a plain vault directory.

The private key never leaves the machine running this tool. Captures are sealed
on the phone with HPKE (RFC 9180, `DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
ChaCha20-Poly1305`) and only ever opened here.

## Install

Requires Python 3.11+.

```bash
# Recommended: install as an isolated tool (provides the `memoret` command)
uv tool install memoret-cli
#   or
pipx install memoret-cli
```

Bleeding edge, straight from source:

```bash
uv tool install "git+https://github.com/mysticcoders/memoret-cli.git"
```

## Use

```bash
memoret init                 # create config + keypair in ~/.memoret, pick a vault dir
memoret pair                 # print the pairing QR / JSON to scan from the iOS app
memoret serve                # run the receiver with a TUI (press p for the pairing QR)
memoret serve --headless     # run without the TUI, logging to stdout (good for servers)
```

Config lives in `~/.memoret/config.json` (created `0600`); the LAN receiver
advertises over Bonjour (`_memoret._tcp`) on port `41831` by default.

Inside the vault, notes and audio go where each capture's manifest asks, and
the receiver's own bookkeeping stays out of the way in `.memoret/`. Earlier
versions wrote `ingested.json` into the vault root, where it turned up in
searches and file listings alongside real notes; an index found there is
adopted and retired automatically, so nothing is redelivered.

`memoret serve --headless` stops on SIGTERM as well as Ctrl-C, withdrawing
the Bonjour advertisement on the way out, so it can be run under a service
manager.

## Development

```bash
scripts/fetch-fixtures.sh          # pull the shared conformance corpus
uv run --group dev pytest          # run the suite
```

The manifest rules are pinned by a corpus shared with the other receivers,
at [memoret-contract-fixtures](https://github.com/mysticcoders/memoret-contract-fixtures).
It is fetched rather than vendored, so all four implementations read one
copy instead of drifting apart with their own.

## Security

- Payloads are end-to-end encrypted; the LAN transport is plaintext HTTP by
  design because the content is already sealed to the receiver's public key.
- The receiver authenticates uploads with a bearer token established at pairing.
- See the protocol docs at <https://developer.memoret.app>.

MIT licensed. Issues and pull requests: [mysticcoders/memoret-cli](https://github.com/mysticcoders/memoret-cli).
