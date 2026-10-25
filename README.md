# Giftmanager

<p align="center">
  <img src="https://r2.icbest.ca/giftmanagertop.png" alt="project-image">
</p>

## 🚀 Demo

You can check out the live demo here: [Giftmanager Demo](https://giftmanagerdemo.pages.dev/)

## Project Screenshots:

<p align="center">
  <img src="https://r2.icbest.ca/firefox_U5WWHHElTf.png" alt="project-screenshot" width="48%">
  <img src="https://r2.icbest.ca/firefox_JiKT8FWU86.png" alt="project-screenshot" width="48%">
</p>
<p align="center">
  <img src="https://r2.icbest.ca/firefox_QH6LjO2Nvs.png" alt="project-screenshot" width="48%">
  <img src="https://r2.icbest.ca/firefox_H5fG4nF7uL.png" alt="project-screenshot" width="48%">
</p>
<p align="center">
  <img src="https://r2.icbest.ca/firefox_b0H0gE2DrY.png" alt="project-screenshot" width="48%">
  <img src="https://r2.icbest.ca/firefox_ptKiDfrz6J.png" alt="project-screenshot" width="48%">
</p>

## Installation

To set up the project, follow the instructions on the [Getting Started Page](https://gift.icbest.ca/getting-started/installation).

## Email notifications

The main (English) application supports Mailjet and standard SMTP. Translated
copies under `languages/` are separate applications and are unchanged.

Mailjet remains the default: existing `MAILJET_API_KEY`, `MAILJET_API_SECRET`
and `SYSTEM_EMAIL` configurations continue to work. Set `EMAIL_PROVIDER=smtp`
to use an SMTP relay instead. There is no automatic fallback between providers.
The existing notification is sent to the buyer when a bought gift idea is
deleted; SMTP support does not add new notification events.

Configure these variables in Docker/Compose or the process environment:

| Variable | Purpose / default |
| --- | --- |
| `EMAIL_PROVIDER` | `mailjet` (default) or `smtp` |
| `SYSTEM_EMAIL` | Sender email address; use a sender allowed by your provider |
| `SMTP_HOST` | SMTP server hostname; required for SMTP |
| `SMTP_PORT` | Defaults to `587`, or `465` when `SMTP_SECURITY=ssl` |
| `SMTP_SECURITY` | `starttls` (default), `ssl` (TLS from connection start), or `none` |
| `SMTP_USERNAME` | SMTP login; omit for an unauthenticated relay |
| `SMTP_PASSWORD` | SMTP password; environment only, never saved by the UI |
| `SMTP_PASSWORD_FILE` | Alternative password file inside the container; do not set both password options |

STARTTLS is required in `starttls` mode: servers without it are rejected.
Both TLS modes verify the server certificate and hostname. `none` is an
explicit option for a trusted, unauthenticated local relay; authentication
over an unencrypted connection is rejected. Connections use a 10-second
socket timeout. No certificate-verification bypass is provided.

Prefer a read-only password file with restrictive host permissions. A trailing
newline is removed; other password characters, including spaces, are preserved.
Do not commit passwords, secret files or personal application data. Environment
variables override saved settings, including the System Email field in the UI.
Recreate the container after changing its environment or secret mounts.

To try this source before a published image includes it, build locally:

```sh
docker build -t giftmanager:smtp ./main
```

For example, adapt the existing Compose service, retaining its data volume and
ports, and set its image to `giftmanager:smtp`:

```yaml
services:
  giftmanager:
    image: giftmanager:smtp
    environment:
      SECRET_KEY: "${SECRET_KEY:?Set SECRET_KEY to a unique random value}"
      EMAIL_PROVIDER: smtp
      SYSTEM_EMAIL: notifications@example.com
      SMTP_HOST: smtp.example.com
      SMTP_PORT: "587"
      SMTP_SECURITY: starttls
      SMTP_USERNAME: your-smtp-login
      SMTP_PASSWORD_FILE: /run/secrets/smtp_password
    secrets:
      - smtp_password

secrets:
  smtp_password:
    file: ./secrets/smtp_password
```

Create `./secrets/smtp_password` yourself before starting the service. Its
contents are the SMTP password, without quotes. Keep the file readable only by
the service operator/container user; do not put it in `settings.json`.

### Test email from the browser

1. Sign in as an administrator and open **Email Settings** (`/edit_email_settings`).
2. Save any changes to **System Email (Sender)** first. An environment-provided
   `SYSTEM_EMAIL` still takes precedence over the saved value.
3. Enter a recipient under **Test Email Delivery** and select **Send Test Email**.
4. Check the success/error notice, then verify delivery and the From address in
   the recipient's inbox. Server acceptance does not guarantee inbox delivery.

The test uses the currently configured SMTP or Mailjet provider and sends a
benign message without changing gifts, users or saved email settings. Both
Save and Send Test Email require an administrator session and a valid form
security token. If the form expires, reload Email Settings and try again.

For server diagnostics, run `docker compose logs --tail=50 giftmanager`.
Failures record only the error type, without provider responses, credentials,
recipient addresses or message contents. Notification failures do not prevent
gift deletion. There is no delivery queue or retry after a failed notification.
The previous `test-email` command has been replaced by this browser workflow.

### Compose signing key

The supplied Compose file requires `SECRET_KEY` from the shell environment or
an untracked Compose `.env` file. Generate a private random value with:

```sh
python -c 'import secrets; print(secrets.token_hex(32))'
```

For an existing installation, reuse its signing key only if it is already private
and unpredictable. Replace public placeholders such as `<SECRET_KEY>` and the
application's default key with a newly generated private value. Rotation signs
users out; it does not delete their accounts or gifts. Supply the private value
to Compose before starting the container, including when migrating from a legacy
`data/.env`. Keep `.env`, password files and application data out of version
control. The application fallback for non-Compose deployments is unchanged;
those deployments must also supply a private `SECRET_KEY`.

## Running tests

Use Python 3.11 or later with the application's existing dependencies:

```sh
python -m venv venv
. venv/bin/activate
pip install -r main/requirements.txt
python -m unittest discover -s tests -v
```

Tests exercise the administrator browser route, authorization, form security,
error redaction and SMTP/Mailjet compatibility, including real loopback TLS
delivery and certificate rejection. They use temporary data and loopback SMTP
servers, without contacting a real email provider or requiring credentials.

## Features

### Gift Ideas Management
- Add and edit gift ideas for yourself and others.
- Organize with **descriptions, links,** and prices.
- Sort ideas however you like.
- Mark gifts as bought to **avoid duplicates.**
- Keep track of everything you’ve given.
- Built to keep **surprises secret**!

### Nice Features
- Secret Santa made simple.
- Emails notifications.
- Dark mode included.
- Manage multiple families separately.

### Global Management
- Easy-to-use **admin dashboard**.
- Built-in user management.
- Secure login with OIDC.
