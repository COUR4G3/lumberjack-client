import datetime as dt
import json
import logging
import os
import selectors
import socket
import ssl
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version

import click
import requests
from dateutil.parser import parse as parse_date
from requests_toolbelt.sessions import BaseUrlSession
from requests_toolbelt.utils.user_agent import user_agent
from syslog_rfc5424_parser import SyslogMessage, ParseError
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


logger = logging.getLogger(__name__)
logging.basicConfig()


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


@cli.command()
@click.option(
    "-h",
    "--host",
    default="",
    envvar="JACK_SYSLOG_HOST",
    help="The host address or UNIX path to bind to.",
)
@click.option(
    "-p",
    "--port",
    type=int,
    envvar="JACK_SYSLOG_PORT",
    help="The port to bind to, defaults to 514 (or 6514 for TLS).",
)
@click.option(
    "-s",
    "--server",
    envvar="JACK_SERVER",
    help="The server to send messages to.",
)
@click.option(
    "--tls",
    is_flag=True,
    envvar="JACK_SYSLOG_TLS",
    help="Use RFC 5425 TLS message transport.",
)
@click.option(
    "--tls-ca",
    is_flag=True,
    envvar="JACK_SYSLOG_TLS_CA",
    help="TLS CA certificate to use for client certificate verification.",
)
@click.option(
    "--tls-certfile",
    is_flag=True,
    envvar="JACK_SYSLOG_TLS_CERTFILE",
    help="TLS server certificate to use.",
)
@click.option(
    "--tls-hostname",
    is_flag=True,
    envvar="JACK_SYSLOG_TLS_HOSTNAME",
    help="Hostname to present for TLS certficate verification.",
)
@click.option(
    "--tls-keyfile",
    is_flag=True,
    envvar="JACK_SYSLOG_TLS_KEYFILE",
    help="TLS server key to use.",
)
@click.option(
    "-u",
    "--udp",
    is_flag=True,
    envvar="JACK_SYSLOG_UDP",
    help="Use RFC 5426 UDP message transport.",
)
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Enable verbose logging output, repeat for more verbose output.",
)
def syslog(
    host,
    port,
    server,
    tls,
    tls_ca,
    tls_certfile,
    tls_hostname,
    tls_keyfile,
    udp,
    verbose,
):
    """Forward syslog messages.

    A simple forwarder that can handle RFC 3165 BSD, RFC 5424 TCP and RFC 5426
    UDP messages, and also supports RFC 5425 TLS security.

    If --tls is specified, you must also specify --certfile and --keyfile.
    Also, --udp (RFC 6012, Syslog over DTLS) is not currently supported.

    """
    if verbose > 1:
        logger.setLevel(logging.DEBUG)
    elif verbose > 0:
        logger.setLevel(logging.INFO)

    if not port and tls:
        port = 6514
    elif not port:
        port = 514

    if udp and tls:
        raise click.ClickException(
            "RFC 6012, Syslog over DTLS is not currently supported. You "
            "cannot combine --tls and --udp flags."
        )
    elif tls and (not tls_certfile or not tls_keyfile):
        raise click.ClickException(
            "--tls-certfile and --tls-keyfile required with --tls flag."
        )

    if udp:
        sock_type = socket.SOCK_DGRAM
    else:
        sock_type = socket.SOCK_STREAM

    sock = socket.socket(socket.AF_INET6, sock_type, 0)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    if tls:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(tls_certfile, tls_keyfile)

        if tls_ca:
            ssl_context.load_verify_locations(tls_ca)
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_context.check_hostname = True

        ssl_context.wrap_socket(
            sock,
            server_side=True,
            do_handshake_on_connect=True,
            server_hostname=tls_hostname,
        )

    selector = selectors.DefaultSelector()

    with BaseUrlSession(server) as session:

        def _syslog_handle(data, context=None):
            if not context:
                context = {}

            message = SyslogMessage.parse(data.decode("utf-8"))

            date = dt.datetime.fromtimestamp(message.timestamp)
            date = date.isoformat()

            data = {
                "body": message.msg,
                "context": {
                    "syslog-appname": message.appname,
                    "syslog-facility": message.facility,
                    "hostname": message.hostname,
                    "syslog-procid": message.procid,
                    "syslog-msgid": message.msgid,
                },
                "date": date,
                "level": message.severity,
            }

            data["context"].update(message.sd)
            data["context"].update(
                {"jack-ingest-from": f"syslog:{host}:{port}"}
            )
            data["context"].update(context)

            while True:
                try:
                    resp = session.post("api/v1/messages", json=data)
                    resp.raise_for_status()
                except requests.exceptions.HTTPError as e:
                    if 400 > e.response.status_code < 500:
                        raise
                except requests.exceptions.RequestException:
                    continue

        def _syslog_tcp_accept(sock):
            conn, addr = sock.accept()
            selector.register(conn, selectors.EVENT_READ, _syslog_tcp_handle)
            logger.info("Accepted connection from %s", addr)

        def _syslog_tcp_handle(sock):
            addr = sock.getpeername()

            try:
                data = sock.recv(4096)
            except socket.error as e:
                logger.exception(
                    "Client %s disconnected [%d]: %s",
                    addr,
                    e.errno,
                    e.strerror,
                )

            if not data:
                selector.unregister(sock)
                logger.info("Client %s disconnected", addr)

            logger.debug("Received %d bytes from from tcp:%s", len(data), addr)
            logger.debug("Data: %s", data.decode("utf-8", "replace"))

            _syslog_handle(data, {"syslog_client": addr[0]})

        def _syslog_udp_handle(sock):
            data, addr = sock.recvfrom(4096)

            logger.debug("Received %d bytes from from udp:%s", len(data), addr)
            logger.debug("Data: %s", data.decode("utf-8", "replace"))

            _syslog_handle(data, {"syslog_client": addr[0]})

        if udp:
            selector.register(sock, selectors.EVENT_READ, _syslog_udp_handle)
        else:
            selector.register(sock, selectors.EVENT_READ, _syslog_tcp_accept)

        session.headers.update(
            {
                "User-Agent": user_agent_string,
            }
        )

        sock.bind((host, port))

        if not udp:
            sock.listen(128)

        logger.info(
            "Listening for connections on %s:%s:%d ...",
            "udp" if udp else "tcp",
            host,
            port,
        )

        try:
            while True:
                events = selector.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj)
        except (KeyboardInterrupt, SystemExit):
            logger.info("Shutting down ...")
        finally:
            sock.close()
            selector.close()


def _format_level(level):
    if level == "emerg":
        return click.style(level.upper(), fg="white", bg="red", bold=True)
    elif level in ("alert", "crit"):
        return click.style(level.upper(), fg="white", bg="red")
    elif level == "error":
        return click.style(level.upper(), fg="red")
    elif level == "warn":
        return click.style(level.upper(), fg="yellow")
    elif level == "debug":
        return click.style(level.upper(), dim=True)
    else:
        return level.upper()


@cli.command()
@click.argument("query", required=False)
@click.option("-f", "--follow", is_flag=True)
@click.option("--pager/--no-pager", default=True)
@click.option("-t", "--tail", type=int)
def tail(follow, query, pager, tail):
    def generator():
        with BaseUrlSession("http://localhost:5000/") as session:
            count = 0
            params = {}
            if query:
                params["q"] = query
            path = {"url": "api/v1/messages"}
            while path:
                resp = session.get(path["url"], params=params)
                resp.raise_for_status()

                data = resp.json()
                if not data:
                    return

                for line in data:
                    date = dt.datetime.fromisoformat(line["date"])
                    level = _format_level("emerg")
                    yield f"{date.strftime('%c')} {level} {line['body'].rstrip()} {line['context']}\n"
                    count += 1

                path = resp.links.get("next")

        yield f"({count} records)"

    if pager:
        click.echo_via_pager(generator())
    else:
        for line in generator():
            click.echo(line, nl=False)


def main():
    cli.main()


if __name__ == "__main__":
    main()
