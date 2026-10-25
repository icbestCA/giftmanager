"""Run with: python -m unittest discover -s tests -v."""

import importlib
import io
import json
import logging
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
from bs4 import BeautifulSoup
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

    def finish(self):
        try:
            super().finish()
        finally:
            if isinstance(self.connection, ssl.SSLSocket):
                self.connection.close()

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
        hostname = patch("socket.getfqdn", return_value="localhost")
        hostname.start()
        self.addCleanup(hostname.stop)
        self.module._settings = dict(self.module._SETTINGS_DEFAULTS)
        self.module._SETTINGS_PATH.write_text(json.dumps(self.module._settings))
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

    def admin_client(self):
        client = self.module.app.test_client()
        with client.session_transaction() as session:
            session["username"] = "owner"
        return client

    def email_form(self, client=None):
        client = client or self.admin_client()
        response = client.get("/edit_email_settings")
        self.assertEqual(response.status_code, 200)
        return client, BeautifulSoup(response.get_data(as_text=True), "html.parser")

    def post_email(self, recipient="owner@example.test", client=None, **fields):
        client, page = self.email_form(client)
        token = page.select_one('input[name="csrf_token"]')
        data = {"action": "test", "test_recipient": recipient, **fields}
        if token:
            data["csrf_token"] = token["value"]
        return client.post("/edit_email_settings", data=data, follow_redirects=True)

    def saved_data(self):
        return tuple(
            Path(path).read_bytes()
            for path in (
                self.module.app.config["USERS_FILE"],
                self.module.app.config["IDEAS_FILE"],
                self.module._SETTINGS_PATH,
            )
        )

    def assert_test_failed(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Test email accepted", response.get_data(as_text=True))
        self.assertNotIn("Traceback", response.get_data(as_text=True))

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

    def test_browser_test_email_is_delivered_without_changing_saved_data(self):
        with smtp_server() as server:
            self.configure_smtp(server)
            saved_before = self.saved_data()
            response = self.post_email(SYSTEM_EMAIL="unsaved@example.test")
            self.assertEqual(response.status_code, 200)
            self.assertIn("Test email accepted", response.get_data(as_text=True))
            self.assertEqual(len(server.messages), 1)
            self.assertEqual(
                server.messages[0]["To"].addresses[0].addr_spec, "owner@example.test"
            )
            self.assertIn("test", server.messages[0]["Subject"].lower())
            self.assertEqual(
                server.messages[0]["From"].addresses[0].addr_spec,
                "sender@example.test",
            )
            self.assertEqual(self.saved_data(), saved_before)

    def test_get_renders_both_email_forms_with_hidden_csrf_tokens(self):
        before = self.saved_data()
        _, page = self.email_form()
        forms = page.select('form[method="post"]')
        self.assertEqual(len(forms), 2)
        actions = set()
        tokens = []
        for form in forms:
            self.assertEqual(form.get("action"), "/edit_email_settings")
            actions.add(form.select_one('input[name="action"]')["value"])
            token = form.select_one('input[type="hidden"][name="csrf_token"]')
            self.assertIsNotNone(token, "Both email actions require a CSRF token")
            self.assertTrue(token.get("value"))
            tokens.append(token["value"])
        self.assertEqual(actions, {"save", "test"})
        self.assertEqual(tokens[0], tokens[1])
        self.assertEqual(self.saved_data(), before)

    def test_save_uses_the_token_from_get_and_changes_only_the_sender(self):
        client, page = self.email_form()
        token = page.select_one('input[name="csrf_token"]')
        self.assertIsNotNone(token)
        users_before, ideas_before, _ = self.saved_data()
        with smtp_server() as server:
            self.configure_smtp(server)
            os.environ.pop("SYSTEM_EMAIL")
            response = client.post(
                "/edit_email_settings",
                data={
                    "action": "save",
                    "SYSTEM_EMAIL": "  saved@example.test  ",
                    "csrf_token": token["value"],
                },
                follow_redirects=True,
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn("updated successfully", response.get_data(as_text=True))
            self.assertEqual(server.commands, [])
        self.assertEqual(
            self.module.read_env_variable("SYSTEM_EMAIL"), "saved@example.test"
        )
        settings = json.loads(self.module._SETTINGS_PATH.read_text())
        self.assertEqual(settings["SYSTEM_EMAIL"], "saved@example.test")
        self.assertEqual(self.saved_data()[:2], (users_before, ideas_before))
        self.assertEqual(
            {key: value for key, value in settings.items() if key != "SYSTEM_EMAIL"},
            {
                key: value
                for key, value in self.module._SETTINGS_DEFAULTS.items()
                if key != "SYSTEM_EMAIL"
            },
        )

    def test_csrf_token_remains_valid_after_another_settings_get(self):
        client, first_page = self.email_form()
        first_token = first_page.select_one('input[name="csrf_token"]')
        self.assertIsNotNone(first_token)
        _, second_page = self.email_form(client)
        self.assertEqual(
            second_page.select_one('input[name="csrf_token"]')["value"],
            first_token["value"],
        )
        response = client.post(
            "/edit_email_settings",
            data={
                "SYSTEM_EMAIL": "legacy-save@example.test",
                "csrf_token": first_token["value"],
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            self.module.read_env_variable("SYSTEM_EMAIL"), "legacy-save@example.test"
        )

    def test_missing_invalid_cross_session_and_non_ascii_csrf_tokens_are_rejected(self):
        client, _ = self.email_form()
        other_client, other_page = self.email_form()
        other_token = other_page.select_one('input[name="csrf_token"]')
        tokens = {
            "missing": None,
            "invalid": "invalid-token",
            "cross-session": other_token["value"] if other_token else "other-session",
            "non-ascii": "\u00e9-invalid-token",
        }
        with smtp_server() as server:
            self.configure_smtp(server)
            os.environ.pop("SYSTEM_EMAIL")
            self.module.save_setting("SYSTEM_EMAIL", "sender@example.test")
            before = self.saved_data()
            for action in ("save", "test"):
                for token_name, token in tokens.items():
                    with self.subTest(action=action, token=token_name):
                        data = {
                            "action": action,
                            "SYSTEM_EMAIL": "changed@example.test",
                            "test_recipient": "owner@example.test",
                        }
                        if token is not None:
                            data["csrf_token"] = token
                        response = client.post("/edit_email_settings", data=data)
                        self.assertEqual(response.status_code, 400)
                        self.assertEqual(self.saved_data(), before)
                        self.assertEqual(server.commands, [])
                        self.assertEqual(server.messages, [])
        self.assertIsNot(client, other_client)

    def test_anonymous_and_non_admin_users_cannot_view_or_post_email_settings(self):
        _, page = self.email_form()
        token = page.select_one('input[name="csrf_token"]')
        before = self.saved_data()
        with smtp_server() as server:
            self.configure_smtp(server)
            for username, destination in ((None, "/login"), ("buyer", "/dashboard")):
                client = self.module.app.test_client()
                if username:
                    with client.session_transaction() as session:
                        session["username"] = username
                for method, data in (
                    ("get", None),
                    (
                        "post",
                        {"action": "test", "test_recipient": "owner@example.test"},
                    ),
                    (
                        "post",
                        {"action": "save", "SYSTEM_EMAIL": "changed@example.test"},
                    ),
                ):
                    with self.subTest(username=username, method=method, data=data):
                        if data is not None and token:
                            data["csrf_token"] = token["value"]
                        response = getattr(client, method)(
                            "/edit_email_settings", data=data
                        )
                        self.assertEqual(response.status_code, 302)
                        self.assertEqual(response.headers["Location"], destination)
                        self.assertEqual(self.saved_data(), before)
                        self.assertEqual(server.commands, [])

    def test_non_string_session_csrf_token_is_rejected_without_side_effects(self):
        client, page = self.email_form()
        token = page.select_one('input[name="csrf_token"]')
        self.assertIsNotNone(token)
        with client.session_transaction() as session:
            token_keys = [
                key for key, value in session.items() if value == token["value"]
            ]
            self.assertEqual(len(token_keys), 1)
            session[token_keys[0]] = ["invalid-token-state"]
        before = self.saved_data()
        with smtp_server() as server:
            self.configure_smtp(server)
            response = client.post(
                "/edit_email_settings",
                data={
                    "action": "test",
                    "test_recipient": "owner@example.test",
                    "csrf_token": token["value"],
                },
            )
            self.assertEqual(response.status_code, 400)
            self.assertEqual(server.commands, [])
            self.assertEqual(self.saved_data(), before)

    def test_empty_recipient_is_rejected_without_sending_or_changing_settings(self):
        before = self.saved_data()
        with smtp_server() as server:
            self.configure_smtp(server)
            for recipient in ("", "   "):
                with self.subTest(recipient=recipient):
                    response = self.post_email(recipient)
                    self.assert_test_failed(response)
                    self.assertIn("recipient", response.get_data(as_text=True).lower())
                    self.assertEqual(self.saved_data(), before)
                    self.assertEqual(server.commands, [])

    def test_unknown_action_is_rejected_without_sending_or_changing_settings(self):
        before = self.saved_data()
        with smtp_server() as server:
            self.configure_smtp(server)
            client, page = self.email_form()
            token = page.select_one('input[name="csrf_token"]')
            data = {
                "action": "unknown",
                "SYSTEM_EMAIL": "changed@example.test",
                "test_recipient": "owner@example.test",
            }
            if token:
                data["csrf_token"] = token["value"]
            response = client.post("/edit_email_settings", data=data)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(self.saved_data(), before)
            self.assertEqual(server.commands, [])

    def test_browser_failures_never_expose_exception_details_in_logs_or_html(self):
        private_detail = "private-transport-detail-" + secrets.token_urlsafe(20)
        os.environ.update(
            {
                "EMAIL_PROVIDER": "smtp",
                "SMTP_HOST": "smtp.example.test",
                "SYSTEM_EMAIL": "sender@example.test",
            }
        )
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        self.module.app.logger.addHandler(handler)
        self.addCleanup(self.module.app.logger.removeHandler, handler)
        before = self.saved_data()
        for error in (
            smtplib.SMTPException(private_detail),
            requests.ConnectionError(private_detail),
            ValueError(private_detail),
        ):
            with self.subTest(error=type(error).__name__):
                output.seek(0)
                output.truncate()
                with patch("smtplib.SMTP", side_effect=error):
                    response = self.post_email()
                self.assert_test_failed(response)
                self.assertNotIn(private_detail, response.get_data(as_text=True))
                self.assertNotIn(private_detail, output.getvalue())
                self.assertEqual(self.saved_data(), before)

    def test_save_failures_do_not_expose_exception_details(self):
        private_detail = "private-save-detail-" + secrets.token_urlsafe(20)
        client, page = self.email_form()
        token = page.select_one('input[name="csrf_token"]')
        data = {"action": "save", "SYSTEM_EMAIL": "changed@example.test"}
        if token:
            data["csrf_token"] = token["value"]
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        self.module.app.logger.addHandler(handler)
        self.addCleanup(self.module.app.logger.removeHandler, handler)
        before = self.saved_data()
        with patch.object(
            self.module, "save_setting", side_effect=OSError(private_detail)
        ):
            response = client.post(
                "/edit_email_settings", data=data, follow_redirects=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("updated successfully", response.get_data(as_text=True))
        self.assertNotIn(private_detail, response.get_data(as_text=True))
        self.assertNotIn(private_detail, output.getvalue())
        self.assertEqual(self.saved_data(), before)

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
            self.assert_test_failed(self.post_email())
            self.assertEqual(server.commands, [])

    def test_missing_starttls_never_falls_back_to_plaintext_delivery(self):
        with smtp_server() as server:
            self.configure_smtp(server)
            os.environ.pop("SMTP_SECURITY")
            self.assert_test_failed(self.post_email())
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
            response = self.post_email()
            self.assertEqual(response.status_code, 200)
            self.assertIn("Test email accepted", response.get_data(as_text=True))
            test_payload = client.return_value.send.create.call_args.kwargs["data"][
                "Messages"
            ][0]
            self.assertEqual(test_payload["To"][0]["Email"], "owner@example.test")
            self.assertIn("test", test_payload["Subject"].lower())
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
                    with self.assertLogs(
                        self.module.app.logger, level="WARNING"
                    ) as ui_logs:
                        response = self.post_email()
                    self.assert_test_failed(response)
                    self.assertNotIn(private_response, response.get_data(as_text=True))
                    self.assertNotIn(private_response, "".join(ui_logs.output))

    def test_no_mail_configuration_preserves_deletion_and_browser_reports_failure(self):
        self.assertEqual(self.delete_gift().status_code, 204)
        response = self.post_email()
        self.assert_test_failed(response)
        self.assertIn(
            "provider did not accept", response.get_data(as_text=True).lower()
        )

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
                self.assert_test_failed(self.post_email())
                smtp.assert_not_called()

    def test_header_injection_is_rejected_before_connecting(self):
        before = self.saved_data()
        with smtp_server() as server:
            self.configure_smtp(server)
            for recipient in (
                "owner@example.test\r\nBcc: other@example.test",
                "owner@example.test,other@example.test",
            ):
                with self.subTest(recipient=recipient):
                    self.assert_test_failed(self.post_email(recipient))
                    self.assertEqual(self.saved_data(), before)
            self.assertEqual(server.commands, [])

    def test_invalid_sender_and_recipient_are_reported_without_a_traceback(self):
        before = self.saved_data()
        with smtp_server() as server:
            self.configure_smtp(server)
            for sender, recipient in (
                ("", "owner@example.test"),
                ("sender@example.test", "bad@@example.test"),
                ("sender@example.test", "local-only"),
            ):
                with self.subTest(sender=sender, recipient=recipient):
                    os.environ["SYSTEM_EMAIL"] = sender
                    self.assert_test_failed(self.post_email(recipient))
                    self.assertEqual(self.saved_data(), before)
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
                        response = self.post_email()
                        self.assertEqual(response.status_code, 200)
                        self.assertEqual(
                            "Test email accepted" in response.get_data(as_text=True),
                            trusted,
                        )
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
