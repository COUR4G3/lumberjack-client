import datetime as dt
import json
import os
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version

import click
import requests
from dateutil.parser import parse as parse_date
from requests_toolbelt.sessions import BaseUrlSession
from requests_toolbelt.utils.user_agent import user_agent
from watchdog.events import FileCreatedEvent
from watchdog.events import FileModifiedEvent
from watchdog.events import FileSystemEventHandler
from watchdog.events import FileSystemMovedEvent
from watchdog.observers import Observer

try:
    from _version import version as __version__
except ImportError:
    try:
        __version__ = version("lumberjack-client")
    except PackageNotFoundError:
        __version__ = "0.1-dev0"


user_agent_string = user_agent(
    "lumberjack-client",
    __version__,
    extras=(
        ("click", click.__version__),
        ("requests", requests.__version__),
    ),
)


@click.group()
@click.pass_context
def cli(ctx: click.Context):
    """Jack, a simple client for the Lumberjack logging service."""


def _prepare_post_data(line, context=None):
    data = {"body": line}

    try:
        data["date"] = parse_date(line, fuzzy=True).isoformat()
    except ValueError:
        pass

    if context:
        data["context"] = context

    click.echo(data)

    return data


def _ingest_file_to_api(path, context=None, encoding=None, server=None):
    if not context:
        context = {}
    if not server:
        server = "https://lumberjack.sh/"

    with BaseUrlSession(server) as session:
        session.headers.update(
            {
                "User-Agent": user_agent_string,
            }
        )

        with click.open_file(path, "r", encoding=encoding) as f:
            for i, line in enumerate(f, 1):
                context.update({"jack_lineno": i, "jack_path": path})
                data = _prepare_post_data(line, context=context)
                resp = session.post("api/v1/messages", json=data)
                click.echo(resp.json())
                resp.raise_for_status()


class EventHandler(FileSystemEventHandler):
    def __init__(self, context=None, encoding=None, server=None):
        self.context = context
        self.encoding = encoding
        self.server = server

        super().__init__()

    def on_any_event(self, event):
        if isinstance(event, FileSystemMovedEvent):
            path = event.dest_path
        elif isinstance(event, (FileCreatedEvent, FileModifiedEvent)):
            path = event.src_path
        else:
            return

        return _ingest_file_to_api(
            path, self.context, self.encoding, self.server
        )


@cli.command()
@click.argument(
    "src",
    type=click.Path(
        exists=True, file_okay=True, dir_okay=True, allow_dash=True
    ),
)
@click.option(
    "-c",
    "--context",
    envvar="JACK_CONTEXT",
    help="Context to include with logging messages.",
)
@click.option(
    "-e",
    "--encoding",
    default="utf-8-sig",
    envvar="JACK_ENCODING",
    help="Encoding to use when reading files, defaults to UTF-8.",
)
@click.option(
    "-s",
    "--server",
    envvar="JACK_SERVER",
    help="The server to send messages to.",
)
def ingest(context, encoding, src, server):
    """Ingest logging messages."""
    if context:
        context = json.loads(context)

    if src == "-":
        _ingest_file_to_api(src, context, encoding, server)
    else:
        observer = Observer()
        handler = EventHandler(context, encoding, server)
        observer.schedule(handler, src, recursive=True)
        observer.start()

        try:
            while observer.is_alive():
                observer.join(1)
        finally:
            observer.stop()
            observer.join()


if __name__ == "__main__":
    cli.main()
