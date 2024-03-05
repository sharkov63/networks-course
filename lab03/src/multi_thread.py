import socket
import sys
import os
import threading
from typing import Optional

HTTP_VERSION = "HTTP/1.1"

def make_response(status_code: int, reason_phrase: str, body: Optional[bytes]=None) -> bytes:
    http_header = "{} {} {}\r\n".format(HTTP_VERSION, status_code, reason_phrase)
    if body is not None:
        http_header += "Content-Length: {}\r\n".format(len(body))
    http_header += "\r\n"
    response = http_header.encode(encoding='ascii')
    if body is not None:
        response += body
    return response
    
def make_ok_response(body: Optional[bytes]):
    return make_response(200, "OK", body)


class HTTPError(Exception):
    def __init__(self, status_code: int, reason_phrase: str):
        self.status_code = status_code
        self.reason_phrase = reason_phrase

    def build_response(self) -> bytes:
        return make_response(
            self.status_code,
            self.reason_phrase,
            "{} {}".format(self.status_code, self.reason_phrase).encode(encoding='ascii')
        )

    @staticmethod
    def make_bad_request():
        return HTTPError(400, "Bad Reqeust")

    @staticmethod
    def make_not_found():
        return HTTPError(404, "Not Found")

    @staticmethod
    def make_internal_server_error():
        return HTTPError(500, "Internal Server Error")


class MyMultithreadedServer:
    def __init__(self, port: int):
        assert 1000 <= port <= 65535
        self._port = port

    def launch(self):
        listen_socket = socket.socket()
        try:
            listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_socket.bind(('localhost', self._port))
            listen_socket.listen(5)
            print("Began to listen on port {}".format(self._port))
            while True:
                connection, addr = listen_socket.accept()
                print("New connection on addr", addr)
                threading.Thread(target=self._serve_client, args=(connection))
        finally:
            print("Shutting down the server...")
            listen_socket.close()

    def _serve_client(self, connection: socket.socket):
        try:
            file_path = self._parse_request(connection)
            file_contents = self._read_file(file_path)
            self._send_ok_response(connection, file_contents)
        except HTTPError as http_error:
            self._send_http_error(connection, http_error)
        except Exception:
            self._send_http_error(connection, HTTPError.make_internal_server_error())
        finally:
            connection.close()

    def _parse_request(self, connection: socket.socket) -> str:
        """
        :return: path in server directory
        """
        with connection.makefile('r') as f:
            request_line = f.readline().split()
            if len(request_line) != 3 or request_line[0] != 'GET' or request_line[2] != HTTP_VERSION:
                raise HTTPError.make_bad_request()
            path = request_line[1]
            if path[0] == '/':
                path = path[1:]
            return path

    def _read_file(self, file_path: str) -> bytes:
        if not os.path.isfile(file_path):
            raise HTTPError.make_not_found()
        with open(file_path, "rb") as f:
            return f.read()

    def _send_ok_response(self, connection: socket.socket, message_body: bytes):
        self._send_binary_response(
            connection,
            make_ok_response(message_body),
        )

    def _send_http_error(self, connection: socket.socket, http_error: HTTPError):
        self._send_binary_response(connection, http_error.build_response())

    def _send_binary_response(self, connection: socket.socket, response: bytes):
        with connection.makefile('wb') as f:
            f.write(response)


def main():
    if len(sys.argv) != 2:
        print("Invalid number of arguments {}; expected one argument <port>".format(
            len(sys.argv) - 1))
        exit(1)
    raw_port = sys.argv[1]
    try:
        port = int(raw_port)
        if port < 1000 or port >= 65536:
            raise ValueError()
    except ValueError:
        print("Invalid port {}".format(raw_port))
        exit(1)
    server = MyMultithreadedServer(port)
    server.launch()


if __name__ == "__main__":
    main()
