# Changelog

## Unreleased

### Added

- Optional standard SMTP delivery for the main English application's existing
  bought-gift deletion notification, with configurable server, port, TLS and login.
- A UI-based email test on the Email Settings page (`/edit_email_settings`)
  that sends a benign test without changing gift/user data.
- Local delivery, TLS, configuration, credential-handling and Mailjet regression
  tests, plus CI on Python 3.11 and 3.12.

### Fixed

- Keep the browser test workflow documented and restore automated coverage for
  administrator actions and SMTP/Mailjet delivery.
- Use theme-aware button colors, visible keyboard focus, ordered headings and
  accessible status/error notices on Email Settings.

- Initialise Mailjet only when sending through that provider, allowing startup
  without Mailjet credentials and reading current credentials at send time.
- Keep gift deletion working when notification delivery/configuration fails.

### Security

- Require a session-bound form token before saving email settings or sending a
  test, and reject unknown actions without changing settings or sending mail.
- Keep provider, configuration and save-error details out of logs and UI notices.
- Require a private Compose signing key rather than an active placeholder, and
  ignore local environment files in version control.

- Require verified TLS by default and prohibit SMTP authentication over plaintext.
- Support a password file; exclude SMTP secrets from saved UI settings and redact
  email-delivery exceptions to error types in logs.
- Validate single sender/recipient addresses and reject header injection.
