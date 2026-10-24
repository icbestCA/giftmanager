"""Run with: python -m unittest discover -s tests -v."""

import importlib
import json
import os
import secrets
import smtplib
import socketserver
import ssl
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from email import policy
from email.parser import BytesParser
from pathlib import Path
from unittest.mock import Mock, patch

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]


class SMTPHandler(socketserver.StreamRequestHandler):
    def setup(self):
        if self.server.implicit_tls:
            self.request = self.server.tls_context.wrap_socket(
                self.request, server_side=True
            )
        super().setup()

    def handle(self):
        self.wfile.write(b"220 localhost test SMTP\r\n")
        while True:
            line = self.rfile.readline()
            if not line:
                break
            command = line.decode().strip()
            self.server.commands.append(command)
            verb = command.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                if self.server.tls_context and not isinstance(
                    self.connection, ssl.SSLSocket
                ):
                    self.wfile.write(b"250-localhost\r\n250 STARTTLS\r\n")
                else:
                    self.wfile.write(b"250 localhost\r\n")
            elif verb == "STARTTLS" and self.server.tls_context:
                self.wfile.write(b"220 Start TLS\r\n")
                self.rfile.close()
                self.wfile.close()
                try:
                    self.connection = self.server.tls_context.wrap_socket(
                        self.connection, server_side=True
                    )
                except ssl.SSLError:
                    return
                self.rfile = self.connection.makefile("rb")
                self.wfile = self.connection.makefile("wb", buffering=0)
            elif verb in ("MAIL", "RCPT", "RSET", "NOOP"):
                self.wfile.write(b"250 OK\r\n")
            elif verb == "DATA":
                self.wfile.write(b"354 End with a dot\r\n")
                lines = []
                while True:
                    content = self.rfile.readline()
                    if content in (b".\r\n", b""):
                        break
                    lines.append(content[1:] if content.startswith(b"..") else content)
                self.server.messages.append(
                    BytesParser(policy=policy.default).parsebytes(b"".join(lines))
                )
                self.wfile.write(b"250 Accepted\r\n")
            elif verb == "QUIT":
                self.wfile.write(b"221 Bye\r\n")
                break
            else:
                self.wfile.write(b"502 Not implemented\r\n")


class SMTPServer(socketserver.ThreadingTCPServer):
    def handle_error(self, request, client_address):
        if not isinstance(sys.exception(), ssl.SSLError):
            super().handle_error(request, client_address)


@contextmanager
def smtp_server(tls_context=None, implicit_tls=False):
    with SMTPServer(("127.0.0.1", 0), SMTPHandler) as server:
        server.messages = []
        server.commands = []
        server.tls_context = tls_context
        server.implicit_tls = implicit_tls
        server.daemon_threads = True
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}
        )
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()


class EmailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.previous_cwd = Path.cwd()
        os.chdir(cls.directory.name)
        Path("static").symlink_to(ROOT / "main" / "static", target_is_directory=True)
        sys.path.insert(0, str(ROOT / "main"))
        with patch.dict(
            os.environ,
            {
                "SECRET_KEY": secrets.token_hex(32),
            },
            clear=True,
        ):
            cls.module = importlib.import_module("app")
        cls.module.app.config["TESTING"] = True

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.previous_cwd)
        sys.path.remove(str(ROOT / "main"))
        cls.directory.cleanup()

    def setUp(self):
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.module._settings = dict(self.module._SETTINGS_DEFAULTS)
        self.module.save_users(
            [
                {"username": "owner", "admin": True, "email": "owner@example.test"},
                {"username": "buyer", "email": "buyer@example.test"},
            ]
        )
        self.module.save_gift_ideas(
            [
                {
                    "gift_idea_id": 1,
                    "user_id": "owner",
                    "added_by": "owner",
                    "bought_by": "buyer",
                    "gift_name": "A book",
                }
            ]
        )

    def configure_smtp(self, server):
        os.environ.update(
            {
                "EMAIL_PROVIDER": "smtp",
                "SYSTEM_EMAIL": "sender@example.test",
                "SMTP_HOST": "127.0.0.1",
                "SMTP_PORT": str(server.server_address[1]),
                "SMTP_SECURITY": "none",
            }
        )

    def delete_gift(self):
        client = self.module.app.test_client()
        with client.session_transaction() as session:
            session["username"] = "owner"
        return client.delete("/delete_idea/1")

    def test_deleting_a_bought_gift_sends_one_smtp_notification_to_its_buyer(self):
        with smtp_server() as server:
            self.configure_smtp(server)
            response = self.delete_gift()
            self.assertEqual(response.status_code, 204)
            self.assertEqual(self.module.load_gift_ideas(), [])
            self.assertEqual(len(server.messages), 1)
            message = server.messages[0]
            self.assertEqual(
                message["From"].addresses[0].addr_spec, "sender@example.test"
            )
            self.assertEqual(message["To"].addresses[0].addr_spec, "buyer@example.test")
            self.assertEqual(message["Subject"], "IDEAS DELETED")
            self.assertIn("A book", message.get_content())

    def test_cli_test_email_is_delivered_without_changing_gifts_or_users(self):
        with smtp_server() as server:
            self.configure_smtp(server)
            users_before = self.module.load_users()
            ideas_before = self.module.load_gift_ideas()
            result = self.module.app.test_cli_runner().invoke(
                args=["test-email", "--to", "owner@example.test"]
            )
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(len(server.messages), 1)
            self.assertEqual(
                server.messages[0]["To"].addresses[0].addr_spec, "owner@example.test"
            )
            self.assertIn("test", server.messages[0]["Subject"].lower())
            self.assertEqual(self.module.load_users(), users_before)
            self.assertEqual(self.module.load_gift_ideas(), ideas_before)

    def test_starttls_is_required_by_default_and_checks_certificates(self):
        os.environ.update(
            {
                "EMAIL_PROVIDER": "smtp",
                "SMTP_HOST": "smtp.example.test",
                "SYSTEM_EMAIL": "sender@example.test",
            }
        )
        with patch("smtplib.SMTP") as connection:
            smtp = connection.return_value.__enter__.return_value
            smtp.send_message.return_value = {}
            self.assertEqual(self.delete_gift().status_code, 204)
            connection.assert_called_once_with("smtp.example.test", 587, timeout=10)
            context = smtp.starttls.call_args.kwargs["context"]
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(smtp.send_message.call_count, 1)

    def test_implicit_tls_defaults_to_port_465_and_checks_certificates(self):
        os.environ.update(
            {
                "EMAIL_PROVIDER": "smtp",
                "SMTP_HOST": "smtp.example.test",
                "SMTP_SECURITY": "ssl",
                "SYSTEM_EMAIL": "sender@example.test",
            }
        )
        with patch("smtplib.SMTP_SSL") as connection:
            smtp = connection.return_value.__enter__.return_value
            smtp.send_message.return_value = {}
            self.assertEqual(self.delete_gift().status_code, 204)
            self.assertEqual(connection.call_args.args, ("smtp.example.test", 465))
            context = connection.call_args.kwargs["context"]
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            smtp.starttls.assert_not_called()
            self.assertEqual(smtp.send_message.call_count, 1)

    def test_password_file_is_used_for_authentication_without_trimming_spaces(self):
        password = secrets.token_urlsafe(20) + " "
        with tempfile.NamedTemporaryFile(mode="w") as secret:
            secret.write(password + "\n")
            secret.flush()
            os.environ.update(
                {
                    "EMAIL_PROVIDER": "smtp",
                    "SMTP_HOST": "smtp.example.test",
                    "SMTP_USERNAME": "smtp-user",
                    "SMTP_PASSWORD_FILE": secret.name,
                    "SYSTEM_EMAIL": "sender@example.test",
                }
            )
            with patch("smtplib.SMTP") as connection:
                smtp = connection.return_value.__enter__.return_value
                smtp.send_message.return_value = {}
                self.delete_gift()
                smtp.login.assert_called_once_with("smtp-user", password)
                self.assertEqual(smtp.method_calls[0][0], "starttls")

    def test_environment_password_is_supported(self):
        password = secrets.token_urlsafe(20)
        os.environ.update(
            {
                "EMAIL_PROVIDER": "smtp",
                "SMTP_HOST": "smtp.example.test",
                "SMTP_USERNAME": "smtp-user",
                "SMTP_PASSWORD": password,
                "SYSTEM_EMAIL": "sender@example.test",
            }
        )
        with patch("smtplib.SMTP") as connection:
            smtp = connection.return_value.__enter__.return_value
            smtp.send_message.return_value = {}
            self.delete_gift()
            smtp.login.assert_called_once_with("smtp-user", password)

    def test_authentication_is_never_sent_over_plaintext_smtp(self):
        with smtp_server() as server:
            self.configure_smtp(server)
            os.environ.update(
                {
                    "SMTP_USERNAME": "smtp-user",
                    "SMTP_PASSWORD": secrets.token_urlsafe(20),
                }
            )
            result = self.module.app.test_cli_runner().invoke(
                args=["test-email", "--to", "owner@example.test"]
            )
            self.assertNotEqual(result.exit_code, 0)
            self.assertEqual(server.commands, [])

    def test_missing_starttls_never_falls_back_to_plaintext_delivery(self):
        with smtp_server() as server:
            self.configure_smtp(server)
            os.environ.pop("SMTP_SECURITY")
            result = self.module.app.test_cli_runner().invoke(
                args=["test-email", "--to", "owner@example.test"]
            )
            self.assertNotEqual(result.exit_code, 0)
            self.assertEqual(server.messages, [])
            self.assertFalse(
                any(command.startswith("MAIL") for command in server.commands)
            )

    def test_delivery_failure_does_not_block_gift_deletion_or_log_credentials(self):
        password = secrets.token_urlsafe(20)
        os.environ.update(
            {
                "EMAIL_PROVIDER": "smtp",
                "SMTP_HOST": "smtp.example.test",
                "SMTP_USERNAME": "smtp-user",
                "SMTP_PASSWORD": password,
                "SYSTEM_EMAIL": "sender@example.test",
            }
        )
        with patch("smtplib.SMTP", side_effect=smtplib.SMTPException(password)):
            with self.assertLogs(self.module.app.logger, level="WARNING") as logs:
                response = self.delete_gift()
            self.assertEqual(response.status_code, 204)
            self.assertEqual(self.module.load_gift_ideas(), [])
            self.assertNotIn(password, "".join(logs.output))

    def test_mailjet_remains_the_default_provider(self):
        os.environ.update(
            {
                "MAILJET_API_KEY": secrets.token_hex(16),
                "MAILJET_API_SECRET": secrets.token_hex(16),
                "SYSTEM_EMAIL": "sender@example.test",
            }
        )
        with (
            patch.object(self.module, "Client") as client,
            patch("smtplib.SMTP") as smtp,
        ):
            client.return_value.send.create.return_value = Mock(status_code=200)
            self.assertEqual(self.delete_gift().status_code, 204)
            payload = client.return_value.send.create.call_args.kwargs["data"][
                "Messages"
            ][0]
            self.assertEqual(payload["From"]["Email"], "sender@example.test")
            self.assertEqual(payload["To"][0]["Email"], "buyer@example.test")
            self.assertEqual(payload["Subject"], "IDEAS DELETED")
            smtp.assert_not_called()

    def test_real_mailjet_client_failures_do_not_block_deletion_or_leak_responses(self):
        private_response = secrets.token_urlsafe(20)
        os.environ.update(
            {
                "MAILJET_API_KEY": secrets.token_hex(16),
                "MAILJET_API_SECRET": secrets.token_hex(16),
                "SYSTEM_EMAIL": "sender@example.test",
            }
        )
        rejection = requests.Response()
        rejection.status_code = 401
        rejection._content = json.dumps({"ErrorMessage": private_response}).encode()
        failures = [
            {"return_value": rejection},
            {"side_effect": requests.ConnectionError(private_response)},
        ]
        for failure in failures:
            with self.subTest(failure=list(failure)):
                self.module.save_gift_ideas(
                    [
                        {
                            "gift_idea_id": 1,
                            "user_id": "owner",
                            "added_by": "owner",
                            "bought_by": "buyer",
                            "gift_name": "A book",
                        }
                    ]
                )
                with patch.object(self.module.Client, "_execute_request", **failure):
                    with self.assertLogs(
                        self.module.app.logger, level="WARNING"
                    ) as logs:
                        self.assertEqual(self.delete_gift().status_code, 204)
                    self.assertEqual(self.module.load_gift_ideas(), [])
                    self.assertNotIn(private_response, "".join(logs.output))
                    result = self.module.app.test_cli_runner().invoke(
                        args=["test-email", "--to", "owner@example.test"]
                    )
                    self.assertNotEqual(result.exit_code, 0)
                    self.assertIn("Error:", result.output)
                    self.assertNotIn(private_response, result.output)

    def test_no_mail_configuration_preserves_deletion_and_cli_reports_failure(self):
        self.assertEqual(self.delete_gift().status_code, 204)
        result = self.module.app.test_cli_runner().invoke(
            args=["test-email", "--to", "owner@example.test"]
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not configured", result.output.lower())

    def test_password_is_never_saved_in_settings_json_or_rendered(self):
        password = secrets.token_urlsafe(20)
        self.module.save_setting("SMTP_PASSWORD", password)
        saved = json.loads(self.module._SETTINGS_PATH.read_text())
        self.assertNotIn("SMTP_PASSWORD", saved)
        client = self.module.app.test_client()
        with client.session_transaction() as session:
            session["username"] = "owner"
        os.environ["SMTP_PASSWORD"] = password
        response = client.get("/edit_email_settings")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(password, response.get_data(as_text=True))

    def test_invalid_smtp_settings_do_not_open_a_connection(self):
        invalid = [
            {"SMTP_PORT": "0"},
            {"SMTP_PORT": "65536"},
            {"SMTP_PORT": "abc"},
            {"SMTP_SECURITY": "typo"},
            {"SMTP_HOST": ""},
            {"SMTP_USERNAME": "smtp-user"},
            {"SMTP_PASSWORD": secrets.token_urlsafe(20)},
            {
                "SMTP_PASSWORD": secrets.token_urlsafe(20),
                "SMTP_PASSWORD_FILE": "/missing",
            },
        ]
        for overrides in invalid:
            with (
                self.subTest(overrides=list(overrides)),
                patch.dict(
                    os.environ,
                    {
                        "EMAIL_PROVIDER": "smtp",
                        "SYSTEM_EMAIL": "sender@example.test",
                        "SMTP_HOST": "smtp.example.test",
                        **overrides,
                    },
                    clear=True,
                ),
                patch("smtplib.SMTP") as smtp,
            ):
                result = self.module.app.test_cli_runner().invoke(
                    args=["test-email", "--to", "owner@example.test"]
                )
                self.assertNotEqual(result.exit_code, 0)
                smtp.assert_not_called()

    def test_header_injection_is_rejected_before_connecting(self):
        with smtp_server() as server:
            self.configure_smtp(server)
            for recipient in (
                "owner@example.test\r\nBcc: other@example.test",
                "owner@example.test,other@example.test",
            ):
                with self.subTest(recipient=recipient):
                    result = self.module.app.test_cli_runner().invoke(
                        args=["test-email", "--to", recipient]
                    )
                    self.assertNotEqual(result.exit_code, 0)
            self.assertEqual(server.commands, [])

    def test_invalid_sender_and_recipient_are_reported_without_a_traceback(self):
        with smtp_server() as server:
            self.configure_smtp(server)
            for sender, recipient in (
                ("", "owner@example.test"),
                ("sender@example.test", "bad@@example.test"),
                ("sender@example.test", "local-only"),
            ):
                with self.subTest(sender=sender, recipient=recipient):
                    os.environ["SYSTEM_EMAIL"] = sender
                    result = self.module.app.test_cli_runner().invoke(
                        args=["test-email", "--to", recipient]
                    )
                    self.assertNotEqual(result.exit_code, 0)
                    self.assertIn("Error:", result.output)
                    self.assertNotIn("Traceback", result.output)
            self.assertEqual(server.commands, [])

    def test_real_tls_delivery_and_untrusted_certificate_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory, "cert.pem")
            private_key = Path(directory, "key.pem")
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
            now = datetime.now(UTC)
            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                    critical=False,
                )
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None), critical=True
                )
                .sign(key, hashes.SHA256())
            )
            private_key.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            private_key.chmod(0o600)
            certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, private_key)
            for security in ("starttls", "ssl"):
                for trusted in (True, False):
                    with (
                        self.subTest(security=security, trusted=trusted),
                        smtp_server(context, implicit_tls=security == "ssl") as server,
                    ):
                        self.configure_smtp(server)
                        os.environ.update(
                            {"SMTP_HOST": "localhost", "SMTP_SECURITY": security}
                        )
                        if trusted:
                            os.environ["SSL_CERT_FILE"] = str(certificate)
                        else:
                            os.environ.pop("SSL_CERT_FILE", None)
                        result = self.module.app.test_cli_runner().invoke(
                            args=["test-email", "--to", "owner@example.test"]
                        )
                        self.assertEqual(result.exit_code == 0, trusted, result.output)
                        self.assertEqual(len(server.messages), 1 if trusted else 0)

    def test_legacy_smtp_password_is_promoted_to_environment_not_settings(self):
        password = secrets.token_urlsafe(20)
        with tempfile.TemporaryDirectory() as directory:
            settings_path = Path(directory, "settings.json")
            legacy_path = Path(directory, ".env")
            legacy_path.write_text(
                "SMTP_PASSWORD=" + password + "\nSYSTEM_EMAIL=sender@example.test\n"
            )
            with (
                patch.object(self.module, "_SETTINGS_PATH", settings_path),
                patch.object(self.module, "_LEGACY_ENV_PATH", legacy_path),
            ):
                self.module._load_or_migrate_settings()
            self.assertEqual(os.environ["SMTP_PASSWORD"], password)
            self.assertNotIn(password, settings_path.read_text())


if __name__ == "__main__":
    unittest.main()
