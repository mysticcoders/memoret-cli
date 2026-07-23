import time

import click

from . import __version__
from .config import DEFAULT_PORT, CONFIG_PATH, create, load
from .crypto import fingerprint


@click.group()
@click.version_option(__version__)
def cli():
    """Memoret terminal receiver: pair once with the iOS app, then
    captures arrive end-to-end encrypted and land in a local vault
    directory."""


@cli.command()
@click.option(
    "--vault-dir",
    default="~/Memoret",
    show_default=True,
    help="Directory notes and audio are written into.",
)
@click.option("--port", default=DEFAULT_PORT, show_default=True)
@click.option("--force", is_flag=True, help="Overwrite an existing config and keypair.")
def init(vault_dir: str, port: int, force: bool):
    """Generate the receiver keypair, auth token, and config."""
    if load() is not None and not force:
        raise click.ClickException(
            f"already initialized ({CONFIG_PATH}); use --force to regenerate. "
            "Regenerating unpairs every device."
        )
    config = create(vault_dir, port)
    config.vault_path.mkdir(parents=True, exist_ok=True)
    click.echo(f"config written to {CONFIG_PATH}")
    click.echo(f"vault directory: {config.vault_path}")
    click.echo(f"key fingerprint: {fingerprint(config.public_key)}")
    click.echo("run 'memoret serve' and press p to show the pairing QR")


@cli.command()
def pair():
    """Print the pairing QR and JSON without starting the receiver."""
    config = _require_config()
    from .tui import qr_ascii

    click.echo(qr_ascii(config.pairing_json()))
    click.echo(config.pairing_json())


@cli.command()
@click.option("--headless", is_flag=True, help="Run without the TUI, logging to stdout.")
def serve(headless: bool):
    """Start the receiver: HTTP server plus mDNS advertisement."""
    config = _require_config()
    config.vault_path.mkdir(parents=True, exist_ok=True)
    if headless:
        from .server import Receiver

        receiver = Receiver(config, click.echo)
        receiver.start()
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            receiver.stop()
        return
    from .tui import MemoretTUI

    MemoretTUI(config).run()


def _require_config():
    config = load()
    if config is None:
        raise click.ClickException("not initialized — run 'memoret init' first")
    return config
