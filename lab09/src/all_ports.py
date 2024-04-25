import socket
import click

@click.command()
@click.option("--addr", type=str, required=True)
@click.option("--port-from", type=int, required=True)
@click.option("--port-to", type=int, required=True)
@click.option("--timeout", type=float, default=0.5, required=False)
def all_ports(addr, port_from, port_to, timeout):
    avaliable_ports = []
    for port in range(port_from, port_to + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((addr, port))
            sock.close()
        except ConnectionError:
            avaliable_ports.append(port)
        except TimeoutError:
            avaliable_ports.append(port)
    print("Available ports:")
    print(*avaliable_ports)

if __name__ == '__main__':
    all_ports()
