import click
import socket
import logging
import random
from common import DEFAULT_SERVER_PORT, send_bytes, recv_bytes


class SNWServer:
    def __init__(
        self,
        *,
        server_port=DEFAULT_SERVER_PORT,
    ):
        self._server_port = server_port
        self._socket = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
        )
        self._socket.bind(('127.0.0.1', self._server_port))
        self._random = random.Random()

    def recv_bytes(self):
        return recv_bytes(self._socket)

    def send_bytes(self, data: bytes, client_addr):
        send_bytes(self._socket, data, client_addr)


@click.command(name='server', help='Server in the Stop and Wait protocol')
@click.option("--server-port", type=int, default=DEFAULT_SERVER_PORT, help='Port of the server')
@click.option("--file", type=click.File('rb'), required=True, help='File to send to the client')
def server_main(server_port: int, file):
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - server - %(message)s', level=logging.INFO)
    server = SNWServer(
        server_port=server_port,
    )
    recevied_data, client_addr = server.recv_bytes()
    print(recevied_data)
    if file is not None:
        server.send_bytes(file.read(), client_addr)




if __name__ == '__main__':
    server_main()
