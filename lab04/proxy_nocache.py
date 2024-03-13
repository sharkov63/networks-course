import click
import logging
import socket
import requests
import io
from typing import Optional, Tuple

HTTP_PORT = 80
HTTP_VERSION = "HTTP/1.1"


def make_response(
    status_code: int,
    reason_phrase: str,
    body: Optional[bytes] = None,
    headers={},
) -> bytes:
    http_header = "{} {} {}\r\n".format(HTTP_VERSION, status_code, reason_phrase)
    if headers is not None:
        for key, value in headers.items():
            if key == "Set-Cookie":
                continue
            if key == "Content-Length" and body and len(body) != int(value):
                raise ValueError(
                    "WTF len(body)={} int(value)={}".format(len(body), int(value))
                )
            http_header += "{}: {}\r\n".format(key, value)
    elif body is not None:
        http_header += "Content-Length: {}\r\n".format(len(body))
    http_header += "\r\n"
    response = http_header.encode(encoding="ascii")
    if body is not None:
        response += body
    return response


class HTTPError(Exception):
    def __init__(
        self, status_code: int, reason_phrase: str, body: Optional[str] = None
    ):
        self.status_code = status_code
        self.reason_phrase = reason_phrase
        if body is None:
            self.body = "{}: {}".format(status_code, reason_phrase)
        else:
            self.body = body

    def build_response(self) -> bytes:
        return make_response(
            self.status_code,
            self.reason_phrase,
            self.body.encode(),
        )

    @staticmethod
    def make_bad_request(message: Optional[str] = None):
        return HTTPError(400, "Bad Reqeust", message)

    @staticmethod
    def make_not_found(message: Optional[str] = None):
        return HTTPError(404, "Not Found", message)

    @staticmethod
    def make_internal_server_error(message: Optional[str] = None):
        return HTTPError(500, "Internal Server Error", message)


class NoCacheProxyServer:
    def __init__(self, port: int):
        if port < 1000 or port >= 65536:
            raise ValueError("Invalid port {}".format(port))
        self._port = port
        self._listen_socket = socket.socket()

    def launch(self):
        logging.info("Starting up no-cache proxy server on port {}".format(self._port))
        try:
            self._listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listen_socket.bind(("localhost", self._port))
            self._listen_socket.listen(5)
            while True:
                connection, _ = self._listen_socket.accept()
                try:
                    self._serve_client(connection)
                except HTTPError as http_error:
                    logging.error(http_error.body)
                    self._send_http_error(connection, http_error)
                finally:
                    connection.close()
        finally:
            logging.info("Shutting down the server...")
            self._listen_socket.close()

    def _serve_client(self, connection: socket.socket):
        with connection.makefile("rb") as request_stream:
            method, url, headers, body = self._read_request(request_stream)
        if method not in ["GET", "POST"]:
            raise HTTPError.make_bad_request(
                "Unsupported method {}, only GET and POST are supported".format(method)
            )
        logging.info("Recieved a {} request for {}".format(method, url))
        try:
            response = requests.request(
                method=method, url=url, headers=headers, data=body
            )
        except Exception as e:
            logging.error(e)
            raise HTTPError.make_internal_server_error(str(e))
        logging.info(
            "Got a response {} {}".format(response.status_code, response.reason)
        )
        if not response.ok:
            raise HTTPError(response.status_code, response.reason, response.text)
        response_headers = response.headers
        if "Content-Encoding" in response_headers:
            del response_headers["Content-Encoding"]
        if "Transfer-Encoding" in response_headers:
            del response_headers["Transfer-Encoding"]
        response_headers["Content-Length"] = str(len(response.content))
        response_bytes = make_response(
            response.status_code,
            response.reason,
            response.content,
            response.headers,
        )
        logging.info("Sending the response back")
        connection.sendall(response_bytes)
        logging.info("Successfully sent the response back")
        connection.shutdown(1)
        connection.close()

    def _read_request(
        self, request_stream: io.BufferedReader
    ) -> Tuple[str, str, dict[str, str], Optional[bytes]]:
        """
        :return: method, url, HTTP headers, body (if present)
        """
        request_line = request_stream.readline().decode("ascii").split()
        if len(request_line) != 3:
            raise HTTPError.make_bad_request("Bad Request-Line {}".format(request_line))
        method, url, http_version = request_line
        if http_version != HTTP_VERSION:
            raise HTTPError.make_bad_request(
                "Unsupported HTTP version {}, expected {}".format(
                    http_version, HTTP_VERSION
                )
            )
        if not url:
            raise HTTPError.make_bad_request("Empty URL")
        if url[0] == "/":
            url = url[1:]
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        headers = self._read_headers(request_stream)
        del headers["Host"]
        body = None
        content_length = headers.get("Content-Length")
        if content_length is not None:
            body = request_stream.read(int(content_length))
        return method, url, headers, body

    def _read_headers(self, request_stream: io.BufferedReader) -> dict[str, str]:
        current_line = request_stream.readline().decode("ascii")
        headers = {}
        while current_line != "\r\n":
            field_name, sep, field_value = current_line[:-2].partition(": ")
            if sep != ": ":
                raise HTTPError.make_bad_request(
                    "Invalid HTTP header {}".format(current_line)
                )
            headers[field_name] = field_value
            current_line = request_stream.readline().decode("ascii")
        return headers

    def _send_ascii(self, connection: socket.socket, text: str):
        connection.sendall(text.encode("ascii"))

    def _send_http_error(self, connection: socket.socket, http_error: HTTPError):
        connection.sendall(http_error.build_response())


@click.command()
@click.option("--port", default=8888, type=int)
def proxy_main(port):
    logging.basicConfig(level=logging.INFO)
    server = NoCacheProxyServer(port)
    server.launch()


if __name__ == "__main__":
    proxy_main()
