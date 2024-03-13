import click
import base64
import logging
import socket
import requests
import os
from common import make_response, AbstractProxyServer, HTTPError


class CacheProxyServer(AbstractProxyServer):
    def __init__(self, port: int, cache_dir: str):
        super(CacheProxyServer, self).__init__(port)
        self.cache_dir = cache_dir
        self.cache_metadata = {}

    def serve_client(self, connection: socket.socket):
        with connection.makefile("rb") as request_stream:
            method, url, headers, body = self.read_request(request_stream)
        if method not in ["GET", "POST"]:
            raise HTTPError.make_bad_request(
                "Unsupported method {}, only GET and POST are supported".format(method)
            )
        logging.info("Recieved a {} request for {}".format(method, url))

        if method == "GET" and url in self.cache_metadata:
            response_bytes = self.respond_with_cache_entry(url, headers)
        else:
            response = self.make_external_request(method, url, headers, body)
            response_bytes = AbstractProxyServer.fix_external_response(response)
            if method == "GET":
                self.update_cache(url, response.headers, response.content)

        logging.info("Sending the response back")
        connection.sendall(response_bytes)
        logging.info("Successfully sent the response back")
        connection.shutdown(1)
        connection.close()

    def respond_with_cache_entry(
        self, url: str, headers: dict[str, str]
    ) -> bytes:
        metadata = self.cache_metadata.get(url)
        assert metadata is not None
        new_headers = headers.copy()
        new_headers["If-Modified-Since"] = metadata[0]
        new_headers["If-None-Match"] = metadata[1]
        try:
            response = requests.get(url, headers=new_headers)
        except Exception as e:
            raise HTTPError.make_internal_server_error(str(e))
        if response.status_code == 304:  # Not Modified
            logging.info("Cache hit for URL {}".format(url))
            with open(self.get_cache_file_path(url), "rb") as cache_file:
                content = cache_file.read()
            return make_response(200, "OK", content)
        if not response.ok:
            raise HTTPError(response.status_code, response.reason, response.text)
        self.update_cache(url, response.headers, response.content)
        return self.fix_external_response(response)

    def update_cache(self, url: str, headers, content: bytes):
        if "Last-Modified" not in headers or "Etag" not in headers:
            return  # Don't cache
        self.cache_metadata[url] = [headers["Last-Modified"], headers["Etag"]]
        with open(self.get_cache_file_path(url), "wb") as cache_file:
            cache_file.write(content)

    def get_cache_file_path(self, url: str) -> str:
        cache_file_name = base64.urlsafe_b64encode(url.encode()).decode()
        return os.path.join(self.cache_dir, cache_file_name)


@click.command()
@click.option("--port", default=8888, type=int)
@click.option("--cache-dir", default=".")
def proxy_main(port, cache_dir):
    logging.basicConfig(level=logging.INFO)
    server = CacheProxyServer(port, cache_dir)
    server.launch()


if __name__ == "__main__":
    proxy_main()
