import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import click

SMTP_SERVER = 'smtp.gmail.com'
TLS_PORT = 587


@click.command()
@click.option("--login", required=True, type=str, help='Email address of the sender, must be in gmail.com domain. Same as login to your Google account.')
@click.option("--password", required=True, type=str, help='App password for your Google account. For more information, see https://support.google.com/accounts/answer/185833')
@click.option("--to", required=True, type=str, help='Recipient address')
@click.option("--subject", default='', type=str, help='Subject of the message.')
@click.option("--msg-text-subtype", type=click.Choice(['plain', 'html'], case_sensitive=False), default='plain')
@click.argument('input', type=click.File('r'), default='-')
def smtplib_client_main(login, password, to, input, subject, msg_text_subtype):
    with smtplib.SMTP(SMTP_SERVER, TLS_PORT) as smtp:
        smtp.starttls()
        smtp.login(login, password)
        message = MIMEMultipart()
        message['From'] = login
        message['To'] = to
        message['Subject'] = subject
        body = input.read()
        message.attach(MIMEText(body, msg_text_subtype))
        smtp.send_message(message)
        smtp.quit()


if __name__ == "__main__":
    smtplib_client_main()
