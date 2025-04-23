from email.message import EmailMessage
from email.header import decode_header
from email.mime.text import MIMEText
from email import charset
from imaplib import IMAP4_SSL
import smtplib
from time import sleep


GMAIL_SMTP_ADDRESS = "smtp.gmail.com"
GMAIL_SMTP_PORT = 465
GMAIL_IMAP_ADDRESS = "imap.gmail.com"
GMAIL_IMAP_PORT = 993

class EmailHandler:
    """System for handling sending and recieving emails"""

    def __init__(self, account_email: str, password: str, *,
                 smtp_address: str = GMAIL_SMTP_ADDRESS, smtp_port: int = GMAIL_SMTP_PORT,
                 imap_address: str = GMAIL_IMAP_ADDRESS, imap_port: int = GMAIL_IMAP_PORT):
        """Creates an EmailHandler with the given values"""
        self.account_email = account_email
        self.password      = password
        self.smtp_address  = smtp_address
        self.smtp_port     = smtp_port
        self.imap_address  = imap_address
        self.imap_port     = imap_port

    def send_email(self, recipient: str, subject: str, body: str) -> None:
        """Sends the given email to the following recipient"""
        msg = EmailMessage()

        # create given message
        msg['Subject'] = subject
        msg['From']    = self.account_email
        msg['To']      = recipient
        msg.set_content(body)

        print(msg.as_string())
        # access email server
        with smtplib.SMTP_SSL(self.smtp_address, self.smtp_port) as smtp_server:
            smtp_server.login(self.account_email, self.password)
            smtp_server.sendmail(self.account_email, recipient, msg.as_string())

            print("Message sent!")

    def receive_email(self, search_subject: str) -> tuple[str, str, str] | None:
        """Receives an email with the given subject line, returning SessionID and body"""

        try:
            with IMAP4_SSL(self.imap_address, self.imap_port) as imap_server:
                # log into server
                imap_server.login(self.account_email, self.password)

                # open inbox
                imap_server.select()

                subject_format = f'"{search_subject}"'

                # get server
                success, id_nums = imap_server.search(None, 'UNSEEN', 'SUBJECT', subject_format)

                # get last id number (we only want to handle the most recent match in any case)
                id_num = id_nums[0].split(b' ')[-1]

                subject = imap_server.fetch(id_num, '(RFC822.SIZE BODY[HEADER.FIELDS (SUBJECT)])')[1][0][1]
                sender = imap_server.fetch(id_num, '(RFC822.SIZE BODY[HEADER.FIELDS (FROM)])')[1][0][1]
                body = imap_server.fetch(id_num, '(RFC822.SIZE UID BODY[TEXT])')[1][0][1]

                # Get session id (always after "Info: ", followed by some newlines)
                session_id = subject.rsplit(b'Info: ', 1)[1].rstrip().decode('utf-8')
                sender = sender.rsplit(b'From: ', 1)[1].rstrip().decode('utf-8')
                body = body.rstrip().decode('utf-8')
                
                # Use REGEX for now, remove 

                # Mark retrieved email as read
                imap_server.store(id_num, '+FLAGS', '\\Seen')

                email_data = (session_id, sender, body)

        except IMAP4_SSL.error as e:
            print(f"Error: {e}")
            email_data = None

        return email_data

    def receive_email_continuous(self, subject: str, wait_time: int = 2) -> tuple[str, str, str] | None:
        """Listens for an email until one is found"""
        while True:
            email_data = self.receive_email(subject)
            if email_data:
                break
            sleep(wait_time)

        return email_data
