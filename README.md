# Northstar Identity — Secure IAM Portal

A small, server-rendered identity and access management starter with a responsive UI. It uses Python's standard library and SQLite; no packages need to be installed.

## Database

The app uses the SQLite database `iam.db` in the project folder by default. It is created and initialized automatically when `server.py` starts, so you do not need to install or start a separate database server. It stores users, password hashes, roles, permissions, and sessions. Accounts and changes persist between app restarts.

Set `IAM_DATABASE_PATH` to store the database somewhere else. Back up this file before moving or replacing it; it contains account data. The local database is excluded from Git so user data is not accidentally committed.

## Run locally

Python 3.10 or later is required.

```powershell
$env:IAM_ADMIN_EMAIL = "admin@example.com"
$env:IAM_ADMIN_PASSWORD = "use-a-unique-password-with-at-least-12-characters"
python server.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). New registrations receive the `member` role. The initial administrator is created only when the configured email is not already registered; set both bootstrap variables before the first launch.

To run without an administrator, omit both bootstrap variables. Registration and member dashboards still work; admin-only role management stays unavailable until an administrator is bootstrapped.

## Features

- Self-service registration, sign-in, sign-out, and authenticated password changes.
- Passwords are salted and hashed with scrypt; login errors do not reveal whether an email is registered, and repeated failures are rate-limited by client address and account.
- Opaque, random session credentials are stored as SHA-256 hashes in SQLite. Session cookies are HTTP-only and `SameSite=Strict`; password changes revoke other sessions and rotate the current one.
- CSRF tokens are required on state-changing requests, cross-origin browser requests are rejected, and responses set a restrictive Content Security Policy and other security headers.
- Role and permission checks protect dashboard and administrator APIs. Members cannot assign roles; administrators cannot demote the last administrator.
- The admin screen lists accounts and roles, and allows authorized administrators to grant or remove admin access.
- The sign-in screen and signed-in dashboard display the total registered-member count; only the aggregate is public, not account details.
- Password policy: 12–128 characters. Public registration never accepts a role from the client.
- Password recovery by email is intentionally not enabled; configure verified email delivery before adding reset links.
- Email verification is not included; verify addresses or use an invitation flow before relying on email as an account identifier in production.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `IAM_HOST` | `127.0.0.1` | Bind address |
| `IAM_PORT` | `8000` | HTTP port |
| `IAM_DATABASE_PATH` | `iam.db` beside `server.py` | SQLite database location |
| `IAM_COOKIE_SECURE` | `0` | Set to `1` when HTTPS is provided by a trusted reverse proxy |
| `IAM_ADMIN_EMAIL` | unset | Email for first-run administrator bootstrap |
| `IAM_ADMIN_PASSWORD` | unset | Strong initial administrator password |

Use a unique administrator password and keep it out of source control and shell history where possible. Do not expose this development server directly to the internet. For deployment, put it behind a TLS-terminating reverse proxy, set `IAM_COOKIE_SECURE=1`, provision and protect the SQLite database, add an email-delivery provider before offering account recovery, and use a production-grade WSGI server and operational monitoring.

## Tests

```powershell
python -m unittest -v
```

The tests cover registration and validation, permission enforcement, password changes, CSRF rejection, role assignment, and protection against demoting the last administrator.
