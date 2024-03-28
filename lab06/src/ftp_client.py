import ftplib
import click
import logging


class Session:
    def __init__(self, host: str, user: str, password: str):
        self._host = host
        self._user = user
        self._password = password
        self._ftp = ftplib.FTP(self._host)
        self._ftp.login(self._user, self._password)
        logging.info(f"Successfully connected to {user}@{host}")
        logging.info(self._ftp.getwelcome())

    def ls(self, dir) -> str:
        self._ftp.cwd(dir)
        return self._ftp.retrlines("LIST")

    def upload(self, client_file, server_path):
        self._ftp.storbinary(f"STOR {server_path}", client_file)

    def download(self, server_path, client_file):
        self._ftp.retrbinary(f"RETR {server_path}", client_file.write)


@click.group
@click.option("--host", type=str, required=True)
@click.option("--user", type=str, required=True)
@click.option("--password", type=str, required=True)
@click.pass_context
def cli(context, host, user, password):
    logging.basicConfig(level=logging.INFO)
    context.ensure_object(dict)
    context.obj['SESSION'] = Session(host, user, password)


@cli.command
@click.argument("dir", default='.', required=False)
@click.pass_context
def ls(context, dir):
    session = context.obj['SESSION']
    click.echo(session.ls(dir))


@cli.command
@click.argument("client_file", type=click.File('rb'), required=True)
@click.argument("server_path", type=str, required=True)
@click.pass_context
def upload(context, client_file, server_path):
    session = context.obj['SESSION']
    session.upload(client_file, server_path)


@cli.command
@click.argument("server_path", type=str, required=True)
@click.argument("client_file", type=click.File('wb'), required=True)
@click.pass_context
def download(context, server_path, client_file):
    session = context.obj['SESSION']
    session.download(server_path, client_file)


if __name__ == "__main__":
    cli()
