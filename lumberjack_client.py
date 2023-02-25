import datetime as dt
import json
import logging
import selectors
import socket
import ssl
import time
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version

import click
import requests
import sslpsk
from dtls import do_patch
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

do_patch()

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

    if context:
        data["context"] = context

    click.echo(data)

    return data


def _ingest_file_to_api(path, context=None, encoding=None, server=None):
    if not context:
        context = {}

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
    default="https://lumberjack.sh/",
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
    "-c",
    "--context",
    envvar="JACK_CONTEXT",
    help="Context to include with logging messages.",
)
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
    default="https://lumberjack.sh/",
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
    type=click.Path(
        exists=True, file_okay=True, dir_okay=False, readable=True
    ),
    envvar="JACK_SYSLOG_TLS_CA",
    help="Path to TLS CA certificate to use for client verification.",
)
@click.option(
    "--tls-certfile",
    type=click.Path(
        exists=True, file_okay=True, dir_okay=False, readable=True
    ),
    envvar="JACK_SYSLOG_TLS_CERTFILE",
    help="Path to TLS server certificate to use.",
)
@click.option(
    "--tls-hostname",
    envvar="JACK_SYSLOG_TLS_HOSTNAME",
    help="Hostname to present for TLS certficate verification.",
)
@click.option(
    "--tls-keyfile",
    type=click.Path(
        exists=True, file_okay=True, dir_okay=False, readable=True
    ),
    envvar="JACK_SYSLOG_TLS_KEYFILE",
    help="Path to TLS server key to use.",
)
@click.option(
    "--tls-psk",
    envvar="JACK_SYSLOG_TLS_PSK",
    help="TLS pre-shared key to use.",
)
@click.option(
    "--tls-psk-file",
    type=click.Path(
        exists=True, file_okay=True, dir_okay=False, readable=True
    ),
    envvar="JACK_SYSLOG_TLS_PSK_FILE",
    help="Path to TLS pre-shared keys in 'identity:key' mapping to use.",
)
@click.option(
    "--tls-psk-hint",
    envvar="JACK_SYSLOG_TLS_PSK_HINT",
    help="TLS pre-shared key hint to send client to help select the key.",
)
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Enable verbose logging output, repeat for more verbose output.",
)
def syslog(
    context,
    host,
    port,
    server,
    tls,
    tls_ca,
    tls_certfile,
    tls_hostname,
    tls_keyfile,
    tls_psk,
    tls_psk_file,
    tls_psk_hint,
    verbose,
):
    """Forward syslog messages.

    A simple forwarder that handle RFC 5424 messages, from either TCP, TLS, UDP
    or DTLS (RFCs 5424, 5425, 5426 and 6012 respectively).

    If --tls is specified, you must also specify a path for --tls-certfile and
    --tls-keyfile - and optionally, --tls-ca if you are doing client
    certificate authentication. Alternatively, --tls-psk or --tls-psk-file and
    optionally --tls-psk-hint to use pre-shared keys and identities.

    """
    if verbose > 1:
        logger.setLevel(logging.DEBUG)
    elif verbose > 0:
        logger.setLevel(logging.INFO)

    if not port and tls:
        port = 6514
    elif not port:
        port = 514

    if tls and (not tls_certfile or not tls_keyfile) and not tls_psk:
        raise click.ClickException(
            "--tls-certfile and --tls-keyfile, or --tls-psk required with "
            "--tls flag."
        )

    tcp_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
    tcp_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    udp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
    udp_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    if tls:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        if tls_ca:
            ssl_context.load_verify_locations(tls_ca)
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_context.check_hostname = True

        if tls_certfile and tls_keyfile:
            ssl_context.load_cert_chain(tls_certfile, tls_keyfile)

        if tls_psk_file:
            tls_psk = {}
            with open(tls_psk, "rb") as f:
                for line in f:
                    identity, key = line.split(b":")
                    key = key.strip()
                    tls_psk[identity] = key

        tcp_sock = ssl_context.wrap_socket(
            tcp_sock,
            server_side=not tls_psk,
            server_hostname=tls_hostname,
        )

        udp_sock = ssl_context.wrap_socket(
            udp_sock,
            server_side=not tls_psk,
            server_hostname=tls_hostname,
        )

        if tls_psk:

            def cb(identity):
                if tls_psk_file:
                    return tls_psk.get(identity)
                else:
                    return tls_psk

            sslpsk._ssl_set_psk_server_callback(tcp_sock, cb, tls_psk_hint)
            sslpsk._ssl_set_psk_server_callback(udp_sock, cb, tls_psk_hint)

    selector = selectors.DefaultSelector()

    with BaseUrlSession(server) as session:

        def _syslog_data_handle(data, additional_context=None):
            if not additional_context:
                additional_context = {}

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
            data["context"].update(additional_context)
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

        def _syslog_accept(sock):
            conn, addr = sock.accept()
            selector.register(conn, selectors.EVENT_READ, _syslog_sock_handle)

            if sock.type == socket.SOCK_DGRAM:
                sock_type = "dtls"
            elif tls:
                sock_type = "tls"
            else:
                sock_type = "tcp"

            logger.info(
                "Accepted connection from [%s]:%s:%d", sock_type, *addr
            )

        def _syslog_sock_handle(sock):
            addr = sock.getpeername()

            if sock.type == socket.SOCK_DGRAM:
                sock_type = "dtls"
            elif tls:
                sock_type = "tls"
            else:
                sock_type = "tcp"

            try:
                data = sock.recv(4096)
            except socket.error as e:
                logger.exception(
                    "Client [%s]:%s:%d disconnected [%d]: %s",
                    sock_type,
                    *addr,
                    e.errno,
                    e.strerror,
                )

            if not data:
                selector.unregister(sock)
                logger.info("Client [%s]:%s:%d disconnected", sock_type, *addr)
                sock.close()
                return

            logger.debug(
                "Received %d bytes from from [%s]:%s:%s",
                len(data),
                sock_type,
                *addr,
            )
            logger.debug("Data: %s", data.decode("utf-8", "replace"))

            _syslog_data_handle(
                data, {"syslog-client": f"[{sock_type}]:{addr[0]}:{addr[1]}"}
            )

        def _syslog_udp_handle(sock):
            data, addr = sock.recvfrom(4096)

            logger.debug(
                "Received %d bytes from from [udp]:%s:%d", len(data), *addr
            )
            logger.debug("Data: %s", data.decode("utf-8", "replace"))

            _syslog_data_handle(
                data, {"syslog-client": f"[udp]:{addr[0]}:{addr[1]}"}
            )

        tcp_sock.bind((host, port))
        tcp_sock.listen(4)

        selector.register(tcp_sock, selectors.EVENT_READ, _syslog_accept)

        udp_sock.bind((host, port))
        if tls:
            udp_sock.listen(4)
            selector.register(udp_sock, selectors.EVENT_READ, _syslog_accept)
        else:
            selector.register(
                udp_sock, selectors.EVENT_READ, _syslog_udp_handle
            )

        session.headers.update(
            {
                "User-Agent": user_agent_string,
            }
        )

        if tls:
            logger.info(
                "Listening for connections on [dtls]:%s:%d ...", host, port
            )
            logger.info(
                "Listening for connections on [tls]:%s:%d ...", host, port
            )
        else:
            logger.info(
                "Listening for connections on [tcp]:%s:%d ...", host, port
            )
            logger.info(
                "Listening for connections on [udp]:%s:%d ...", host, port
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
            tcp_sock.close()
            udp_sock.close()
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
@click.option(
    "-s",
    "--server",
    default="https://lumberjack.sh/",
    envvar="JACK_SERVER",
    help="The server to send messages to.",
)
@click.option("-t", "--tail", type=click.IntRange(0, clamp=True))
def tail(follow, query, pager, server, tail):
    def generator():
        nonlocal tail

        with BaseUrlSession(server) as session:
            if tail:
                tail_messages = []

                params = {"limit": min(tail, 1024), "order": "-date"}
                path = "api/v1/messages"
                while tail > 0:
                    resp = session.get(path, params=params)
                    resp.raise_for_status()

                    messages = resp.json()
                    if not messages:
                        break
                    tail -= len(messages)

                    tail_messages += messages

                    path = resp.links["prev"]["url"]

                for message in reversed(tail_messages):
                    _print_message(message)
            else:
                params = {}
                path = "api/v1/messages"
                while True:
                    resp = session.get(path, params=params)
                    resp.raise_for_status()

                    if not messages and follow:
                        time.sleep(1.0)
                        continue
                    elif not messages:
                        break

                    for message in resp.json():
                        _print_message(message)

                    path = resp.links["next"]["url"]

    if pager:
        click.echo_via_pager(generator())
    else:
        for line in generator():
            click.echo(line, nl=False)


def main():
    cli.main()


if __name__ == "__main__":
    main()


def _print_message(message):
    pass
