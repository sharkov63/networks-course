import click
from common import DEFAULT_SERVER_PORT, send_bytes, recv_bytes, DEFAULT_TIMEOUT_S
import socket
import logging
import random

class SNWClient:
    def __init__(
        self,
        *,
        server_addr='127.0.0.1',
        server_port=DEFAULT_SERVER_PORT,
        timeout_s=DEFAULT_TIMEOUT_S,
    ):
        self._server_addr = (server_addr, server_port)
        self._socket = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
        )
        self._random = random.Random()
        self._timeout_s = timeout_s

    def send_bytes(self, data: bytes):
        self._socket.settimeout(self._timeout_s)
        send_bytes(self._socket, data, self._server_addr, self._timeout_s)

    def recv_bytes(self):
        self._socket.settimeout(None)
        return recv_bytes(self._socket)[0]


@click.command(name='client', help='Client in the Stop and Wait protocol.')
@click.option("--server-addr", type=str, default='127.0.0.1', help='IP address of the server')
@click.option("--server-port", type=int, default=DEFAULT_SERVER_PORT, help='Port of the server')
@click.option("--timeout-s", type=float, default=DEFAULT_TIMEOUT_S, help='Client timeout in seconds')
@click.option("--file", type=click.File('rb'), required=True, help='File to send to the server')
def client_main(server_addr: str, server_port: int, timeout_s: float, file):
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - client - %(message)s', level=logging.INFO)
    client = SNWClient(
        server_addr=server_addr,
        server_port=server_port,
        timeout_s=timeout_s,
    )
    client.send_bytes(file.read())
    print(client.recv_bytes())


if __name__ == '__main__':
    client_main()
