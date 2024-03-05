import socket
import click

HTTP_VERSION = "HTTP/1.1"


def make_query(filename: str) -> bytes:
    return "GET /{} {}\r\n".format(filename, HTTP_VERSION).encode(encoding='ascii')


@click.command()
@click.argument("server_host", required=True)
@click.argument("server_port", type=int, required=True)
@click.argument("filename", required=True)
def client_main(server_host: str, server_port: int, filename: str):
    client_socket = socket.socket()
    client_socket.connect((server_host, server_port))
    with client_socket.makefile('wb') as f:
        f.write(make_query(filename))
    with client_socket.makefile('rb') as f:
        click.echo(f.read())


if __name__ == "__main__":
    client_main()
