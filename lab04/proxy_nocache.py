import click
import logging
import socket
from common import AbstractProxyServer, HTTPError


class NoCacheProxyServer(AbstractProxyServer):
    def __init__(self, port: int):
        super(NoCacheProxyServer, self).__init__(port)

    def serve_client(self, connection: socket.socket):
        with connection.makefile("rb") as request_stream:
            method, url, headers, body = self.read_request(request_stream)
        if method not in ["GET", "POST"]:
            raise HTTPError.make_bad_request(
                "Unsupported method {}, only GET and POST are supported".format(method)
            )
        logging.info("Recieved a {} request for {}".format(method, url))
        response = self.make_external_request(method, url, headers, body)
        response_bytes = AbstractProxyServer.fix_external_response(response)
        logging.info("Sending the response back")
        connection.sendall(response_bytes)
        logging.info("Successfully sent the response back")
        connection.shutdown(1)
        connection.close()


@click.command()
@click.option("--port", default=8888, type=int)
def proxy_main(port):
    logging.basicConfig(level=logging.INFO)
    server = NoCacheProxyServer(port)
    server.launch()


if __name__ == "__main__":
    proxy_main()
