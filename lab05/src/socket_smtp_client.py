import click
import ssl
import socket
import logging
import base64
from typing import Optional

SMTP_SERVER = 'smtp.gmail.com'
SMTP_SERVER_PORT = 465

SMTP_SERVICE_READY = 220
SMTP_SERVICE_OK = 250
SMTP_SERVICE_START_MAIL_INPUT = 354


class SocketSmtpClient:
    def __init__(self, login, password):
        self._login = login
        self._password = password

    def __enter__(self):
        self._connect()
        self._accept_greeting()
        logging.info(
            f"Established secure connection via {self._ssl_sock.version()}")
        self._ehlo()
        self._auth()
        logging.info("Authentication successful!")
        return self

    def sendmail(self, to: str, datastream, mime: bool, content_type: Optional[str]):
        if mime and "8BITMIME" not in self._ehlo_response:
            raise RuntimeError("8BITMIME is not supported by server")
        body_mail_param = " BODY=8BITMIME" if mime else ""
        self._write(f"MAIL FROM:<{self._login}>{body_mail_param}\r\n")
        if not self._readline().startswith(f"{SMTP_SERVICE_OK}"):
            raise RuntimeError()
        self._write(f"RCPT TO:<{to}>\r\n")
        if not self._readline().startswith(f"{SMTP_SERVICE_OK}"):
            raise RuntimeError()
        self._write("DATA\r\n")
        if not self._readline().startswith(f"{SMTP_SERVICE_START_MAIL_INPUT}"):
            raise RuntimeError()
        if not mime:
            self._writebytes(datastream.read())
        else:
            self._write("MIME-Version: 1.0\r\n")
            self._write(f"Content-Type: {content_type}\r\n")
            self._write("Content-Transfer-Encoding: base64\r\n")
            self._write("\r\n")
            self._writebytes(base64.b64encode(datastream.read()))
        self._write("\r\n.\r\n")
        if not self._readline().startswith(f"{SMTP_SERVICE_OK}"):
            raise RuntimeError()

    def __exit__(self, *_):
        self._ssl_sock.close()
        self._raw_sock.close()

    def _connect(self):
        self._raw_sock = socket.create_connection(
            (SMTP_SERVER, SMTP_SERVER_PORT))
        self._sslcontext = ssl.create_default_context()
        self._ssl_sock = self._sslcontext.wrap_socket(
            self._raw_sock, server_hostname=SMTP_SERVER)
        if self._ssl_sock.version() is None:
            raise RuntimeError("Failed to establish secure connection")
        self._sock_file = self._ssl_sock.makefile('rwb')

    def _accept_greeting(self):
        greeting = self._readline().split()
        if not greeting or greeting[0] != f"{SMTP_SERVICE_READY}":
            raise RuntimeError(
                f"SMTP service {SMTP_SERVER}:{SMTP_SERVER_PORT} is not available: {greeting}")
        if greeting[1] != SMTP_SERVER:
            raise RuntimeError(
                f"SMTP server is {greeting[1]} and not {SMTP_SERVER}. MAN IN THE MIDDLE OMEGALUL")

    def _ehlo(self):
        self._write(f"EHLO {socket.getfqdn()}\r\n")
        greeting = self._readline()
        if greeting[:3] != f"{SMTP_SERVICE_OK}" or len(greeting) < 4:
            raise RuntimeError(greeting)
        self._ehlo_response = {}
        current = greeting
        while not current.startswith(f"{SMTP_SERVICE_OK} "):
            current = self._readline()
            if not current.startswith(f"{SMTP_SERVICE_OK}"):
                raise RuntimeError(current)
            ehlo_line = current[4:].split()
            if not ehlo_line:
                raise RuntimeError("Empty ehlo line")
            ehlo_keyword = ehlo_line[0]
            self._ehlo_response[ehlo_keyword] = ehlo_line[1:]

    def _auth(self):
        auth_methods = self._ehlo_response.get("AUTH")
        if auth_methods is None:
            raise RuntimeError("No auth method is supported by SMTP service")
        if "PLAIN" not in auth_methods:
            raise RuntimeError(
                "PLAIN auth method ain't supported by the SMTP service")
        initial_response = base64.b64encode(
            b'\x00' + self._login.encode('ascii') + b'\x00' + self._password.encode('ascii'))
        self._writebytes("AUTH PLAIN ".encode('ascii') +
                         initial_response + "\r\n".encode('ascii'))
        auth_reply = self._readline()
        if not auth_reply.startswith("235 2.7.0"):
            raise RuntimeError("Authentication failed :(")

    def _readline(self):
        line = self._sock_file.readline().decode('ascii')
        logging.debug(line)
        return line

    def _write(self, text: str):
        logging.debug(text)
        self._sock_file.write(text.encode('ascii'))
        self._sock_file.flush()

    def _writebytes(self, bytes: bytes):
        self._sock_file.write(bytes)
        self._sock_file.flush()


@click.command()
@click.option("--login", required=True, type=str, help='Email address of the sender, must be in gmail.com domain. Same as login to your Google account.')
@click.option("--password", required=True, type=str, help='App password for your Google account. For more information, see https://support.google.com/accounts/answer/185833')
@click.option("--to", required=True, type=str, help='Recipient address')
@click.option("--mime", is_flag=True, default=False)
@click.option("--content-type", type=str)
@click.argument('input', type=click.File('rb'), default='-')
def main(
    login: str,
    password: str,
    to: str,
    input,
    mime: bool,
    content_type: Optional[str],
):
    if mime and content_type is None:
        logging.error("--content-type is required with --mime")
        exit(1)
    if not mime and content_type is not None:
        logging.warn("--mime is not set, so --content-type will be ignored")
    logging.basicConfig(level=logging.DEBUG)
    with SocketSmtpClient(login, password) as client:
        client.sendmail(to, input, mime, content_type)


if __name__ == "__main__":
    main()
