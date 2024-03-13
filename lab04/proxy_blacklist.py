import click
import logging
import socket
import re
from typing import Optional
from common import make_response, AbstractProxyServer, HTTPError


class BlacklistProxyServer(AbstractProxyServer):
    def __init__(self, port: int, blacklist_path: Optional[str]):
        super(BlacklistProxyServer, self).__init__(port)
        self.blacklist_patterns = []
        if blacklist_path is not None:
            try:
                with open(blacklist_path, "r") as blacklist_file:
                    for line in blacklist_file:
                        self.blacklist_patterns.append(line.strip())
            except IOError:
                logging.warn(
                    "Failed to read blacklist at {}; continuing with empty blacklist".format(
                        blacklist_path
                    )
                )

    def serve_client(self, connection: socket.socket):
        with connection.makefile("rb") as request_stream:
            method, url, headers, body = self.read_request(request_stream)
        blacklisted_pattern = self.is_blacklisted(url)
        if blacklisted_pattern is not None:
            message = "URL {} is blacklisted because it matches pattern {}".format(
                url, blacklisted_pattern
            )
            logging.info(message)
            response_bytes = make_response(
                403,
                "Forbidden",
                message.encode(),
            )
        else:
            if method not in ["GET", "POST"]:
                raise HTTPError.make_bad_request(
                    "Unsupported method {}, only GET and POST are supported".format(
                        method
                    )
                )
            logging.info("Recieved a {} request for {}".format(method, url))
            response = self.make_external_request(method, url, headers, body)
            response_bytes = AbstractProxyServer.fix_external_response(response)

        logging.info("Sending the response back")
        connection.sendall(response_bytes)
        logging.info("Successfully sent the response back")
        connection.shutdown(1)
        connection.close()

    def is_blacklisted(self, url: str) -> Optional[str]:
        try:
            domain = BlacklistProxyServer.extract_domain(url)
        except ValueError:
            return None
        for pattern in self.blacklist_patterns:
            if re.fullmatch(pattern, domain) is not None:
                return pattern
        return None

    @staticmethod
    def extract_domain(url: str) -> str:
        if url.startswith("http://"):
            url = url[7:]
        elif url.startswith("https://"):
            url = url[8:]
        else:
            raise ValueError("Invalid URL {}".format(url))
        domain, _, _ = url.partition("/")
        return domain


@click.command()
@click.option("--port", default=8888, type=int)
@click.option("--blacklist", default=None, type=str)
def proxy_main(port, blacklist):
    logging.basicConfig(level=logging.INFO)
    server = BlacklistProxyServer(port, blacklist)
    server.launch()


if __name__ == "__main__":
    proxy_main()
