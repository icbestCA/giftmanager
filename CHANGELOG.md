# Changelog

## Unreleased

### Added

- Optional standard SMTP delivery for the main English application's existing
  bought-gift deletion notification, with configurable server, port, TLS and login.
- A UI-based email test on the Email Settings page (`/edit_email_settings`) 
  that sends a benign test without changing gift/user data
- Local delivery, TLS, configuration, credential-handling and Mailjet regression
  tests, plus CI on Python 3.11 and 3.12.

### Fixed

- Initialise Mailjet only when sending through that provider, allowing startup
  without Mailjet credentials and reading current credentials at send time.
- Keep gift deletion working when notification delivery/configuration fails.

### Security

- Require verified TLS by default and prohibit SMTP authentication over plaintext.
- Support a password file; exclude SMTP secrets from saved UI settings and redact
  email-delivery exceptions to error types in logs.
- Validate single sender/recipient addresses and reject header injection.
