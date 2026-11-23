import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.environ.get("IAM_DATABASE_PATH", ROOT / "iam.db"))
HOST = os.environ.get("IAM_HOST", "127.0.0.1")
PORT = int(os.environ.get("IAM_PORT", "8000"))
COOKIE_SECURE = os.environ.get("IAM_COOKIE_SECURE", "0").lower() in ("1", "true", "yes")
SESSION_TTL = 60 * 60 * 8
SESSION_COOKIE = "iam_session"
CSRF_COOKIE = "iam_csrf"
MAX_BODY_SIZE = 16 * 1024
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
LOGIN_FAILURES = {}
LOGIN_FAILURES_LOCK = threading.Lock()


class APIError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


@contextmanager
def connect_db():
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_database():
    global DATABASE_PATH
    DATABASE_PATH = Path(DATABASE_PATH)
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS role_permissions (
                role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
                permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
                PRIMARY KEY (role_id, permission_id)
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role_id INTEGER NOT NULL REFERENCES roles(id),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                csrf_token TEXT NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);
            """
        )
        db.executemany(
            "INSERT OR IGNORE INTO roles(name) VALUES (?)",
            (("member",), ("admin",)),
        )
        db.executemany(
            "INSERT OR IGNORE INTO permissions(name, description) VALUES (?, ?)",
            (
                ("dashboard:read", "View the signed-in dashboard"),
                ("users:read", "View user accounts and roles"),
                ("users:manage", "Change user roles"),
            ),
        )
        permissions = {
            row["name"]: row["id"]
            for row in db.execute("SELECT id, name FROM permissions")
        }
        roles = {
            row["name"]: row["id"]
            for row in db.execute("SELECT id, name FROM roles")
        }
        db.execute(
            "INSERT OR IGNORE INTO role_permissions(role_id, permission_id) VALUES (?, ?)",
            (roles["member"], permissions["dashboard:read"]),
        )
        db.executemany(
            "INSERT OR IGNORE INTO role_permissions(role_id, permission_id) VALUES (?, ?)",
            ((roles["admin"], permission_id) for permission_id in permissions.values()),
        )

    bootstrap_email = os.environ.get("IAM_ADMIN_EMAIL", "").strip().lower()
    bootstrap_password = os.environ.get("IAM_ADMIN_PASSWORD", "")
    if bool(bootstrap_email) != bool(bootstrap_password):
        raise ValueError("Set both IAM_ADMIN_EMAIL and IAM_ADMIN_PASSWORD to bootstrap an administrator.")
    if bootstrap_email:
        validate_email(bootstrap_email)
        validate_password(bootstrap_password)
        with connect_db() as db:
            existing = db.execute("SELECT id FROM users WHERE email = ?", (bootstrap_email,)).fetchone()
            if existing is None:
                admin_id = db.execute("SELECT id FROM roles WHERE name = 'admin'").fetchone()["id"]
                db.execute(
                    "INSERT INTO users(email, display_name, password_hash, role_id, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        bootstrap_email,
                        "Administrator",
                        hash_password(bootstrap_password),
                        admin_id,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                logging.info("Created the configured bootstrap administrator.")
            else:
                logging.info("The configured bootstrap email already exists; no account changes were made.")


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    salt_text = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    digest_text = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return "scrypt$16384$8$1${}${}".format(salt_text, digest_text)


def verify_password(password, encoded):
    try:
        algorithm, n, r, p, salt_text, digest_text = encoded.split("$")
        if algorithm != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
        expected = base64.urlsafe_b64decode(digest_text + "=" * (-len(digest_text) % 4))
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, UnicodeError):
        return False


DUMMY_PASSWORD_HASH = hash_password("timing-protection-password")


def validate_email(email):
    normalized = email.strip().lower()
    try:
        normalized.encode("utf-8")
    except UnicodeEncodeError:
        raise APIError(400, "Enter a valid email address.")
    if len(normalized) > 254 or not EMAIL_RE.fullmatch(normalized):
        raise APIError(400, "Enter a valid email address.")
    return normalized


def validate_password(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise APIError(400, "Use a password between 12 and 128 characters.")
    try:
        encoded = password.encode("utf-8")
    except UnicodeEncodeError:
        raise APIError(400, "Password contains unsupported characters.")
    if len(encoded) > 512:
        raise APIError(400, "Password is too long.")


def token_hash(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def user_permissions(db, user_id):
    return [
        row["name"]
        for row in db.execute(
            """
            SELECT p.name
            FROM permissions p
            JOIN role_permissions rp ON rp.permission_id = p.id
            JOIN users u ON u.role_id = rp.role_id
            WHERE u.id = ?
            ORDER BY p.name
            """,
            (user_id,),
        )
    ]


def take_login_attempt(client_ip, email):
    now = time.time()
    window = 10 * 60
    key = (client_ip, email)
    with LOGIN_FAILURES_LOCK:
        attempts = [stamp for stamp in LOGIN_FAILURES.get(key, []) if now - stamp < window]
        if attempts:
            LOGIN_FAILURES[key] = attempts
        else:
            LOGIN_FAILURES.pop(key, None)
        return len(attempts) >= 10


def record_login_failure(client_ip, email):
    now = time.time()
    with LOGIN_FAILURES_LOCK:
        key = (client_ip, email)
        attempts = [
            stamp for stamp in LOGIN_FAILURES.get(key, [])
            if now - stamp < 10 * 60
        ]
        attempts.append(now)
        LOGIN_FAILURES[key] = attempts
        if len(LOGIN_FAILURES) > 10_000:
            for candidate, stamps in list(LOGIN_FAILURES.items()):
                recent = [stamp for stamp in stamps if now - stamp < 10 * 60]
                if recent:
                    LOGIN_FAILURES[candidate] = recent
                else:
                    LOGIN_FAILURES.pop(candidate, None)
            while len(LOGIN_FAILURES) > 10_000:
                LOGIN_FAILURES.pop(next(iter(LOGIN_FAILURES)))


def _cookie_options(max_age=None, http_only=True):
    parts = ["Path=/", "SameSite=Strict"]
    if http_only:
        parts.append("HttpOnly")
    if COOKIE_SECURE:
        parts.append("Secure")
    if max_age is not None:
        parts.append("Max-Age={}".format(max_age))
    return "; ".join(parts)


class IAMHandler(BaseHTTPRequestHandler):
    server_version = "SecureIAM"

    def log_message(self, fmt, *args):
        logging.info("%s - %s", self.address_string(), fmt % args)

    def _send(self, status, body, content_type, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        )
        if self.path.startswith("/api/"):
            self.send_header("Cache-Control", "no-store")
        if headers:
            for name, value in headers:
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, data, headers=None):
        body = json.dumps(data, separators=(",", ":")).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", headers)

    def _error(self, status, message):
        self._json(status, {"error": message})

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise APIError(400, "Invalid request body.")
        if length < 0 or length > MAX_BODY_SIZE:
            raise APIError(413, "Request body is too large.")
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise APIError(400, "Send a valid JSON request.")
        if not isinstance(data, dict):
            raise APIError(400, "Send a valid JSON object.")
        return data

    def _cookies(self):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except CookieError:
            return {}
        return {key: morsel.value for key, morsel in cookies.items()}

    def _check_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return
        parsed = urlsplit(origin)
        host = self.headers.get("Host", "")
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.netloc.lower() != host.lower():
            raise APIError(403, "Cross-origin requests are not allowed.")

    def _csrf(self, user=None):
        supplied = self.headers.get("X-CSRF-Token", "")
        cookies = self._cookies()
        expected = user["csrf_token"] if user else cookies.get(CSRF_COOKIE, "")
        if not expected or not supplied or not hmac.compare_digest(supplied, expected):
            raise APIError(403, "Your session has expired. Refresh the page and try again.")

    def _current_user(self):
        token = self._cookies().get(SESSION_COOKIE)
        if not token or len(token) > 128:
            return None
        now = int(time.time())
        with connect_db() as db:
            row = db.execute(
                """
                SELECT s.csrf_token, u.id, u.email, u.display_name, u.created_at, r.name AS role
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                JOIN roles r ON r.id = u.role_id
                WHERE s.token_hash = ? AND s.expires_at > ?
                """,
                (token_hash(token), now),
            ).fetchone()
            if row is None:
                return None
            user = dict(row)
            user["permissions"] = user_permissions(db, user["id"])
            return user

    def _require_user(self, permission=None):
        user = self._current_user()
        if user is None:
            raise APIError(401, "Please sign in to continue.")
        if permission and permission not in user["permissions"]:
            raise APIError(403, "You do not have permission to do that.")
        return user

    def _create_session(self, user_id):
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = int(time.time())
        with connect_db() as db:
            db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            db.execute(
                "INSERT INTO sessions(token_hash, csrf_token, user_id, expires_at, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (token_hash(token), csrf, user_id, now + SESSION_TTL, now),
            )
        return token, csrf

    def _session_cookie(self, token, max_age=SESSION_TTL):
        return "{}={}; {}".format(SESSION_COOKIE, token, _cookie_options(max_age))

    def _csrf_cookie(self, token, max_age=3600):
        return "{}={}; {}".format(CSRF_COOKIE, token, _cookie_options(max_age))

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            try:
                body = (ROOT / "index.html").read_bytes()
            except OSError:
                self._error(500, "The application UI could not be loaded.")
                return
            self._send(200, body, "text/html; charset=utf-8")
            return
        static_files = {
            "/styles.css": ("styles.css", "text/css; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
        }
        if path in static_files:
            filename, content_type = static_files[path]
            try:
                body = (ROOT / filename).read_bytes()
            except OSError:
                self._error(500, "An application asset could not be loaded.")
                return
            self._send(200, body, content_type)
            return
        if not path.startswith("/api/"):
            self._error(404, "Not found.")
            return
        try:
            if path == "/api/session":
                user = self._current_user()
                if user:
                    self._json(
                        200,
                        {
                            "authenticated": True,
                            "user": self._public_user(user),
                            "csrf_token": user["csrf_token"],
                        },
                    )
                else:
                    csrf = self._cookies().get(CSRF_COOKIE) or secrets.token_urlsafe(32)
                    self._json(
                        200,
                        {"authenticated": False, "csrf_token": csrf},
                        [("Set-Cookie", self._csrf_cookie(csrf))],
                    )
                return
            if path == "/api/public/stats":
                with connect_db() as db:
                    total_users = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
                self._json(200, {"total_users": total_users})
                return
            if path == "/api/dashboard":
                user = self._require_user("dashboard:read")
                with connect_db() as db:
                    active_sessions = db.execute(
                        "SELECT COUNT(*) AS count FROM sessions WHERE user_id = ? AND expires_at > ?",
                        (user["id"], int(time.time())),
                    ).fetchone()["count"]
                    total_users = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
                self._json(
                    200,
                    {
                        "role": user["role"],
                        "permissions": user["permissions"],
                        "account_created": user["created_at"],
                        "active_sessions": active_sessions,
                        "total_users": total_users,
                    },
                )
                return
            if path == "/api/admin/users":
                self._require_user("users:read")
                with connect_db() as db:
                    users = db.execute(
                        """
                        SELECT u.id, u.email, u.display_name, u.created_at, r.name AS role
                        FROM users u JOIN roles r ON r.id = u.role_id
                        ORDER BY u.created_at DESC, u.id DESC
                        """
                    ).fetchall()
                self._json(200, {"users": [dict(row) for row in users]})
                return
            if path == "/api/admin/roles":
                self._require_user("users:read")
                with connect_db() as db:
                    roles = db.execute(
                        """
                        SELECT r.name, p.name AS permission
                        FROM roles r
                        LEFT JOIN role_permissions rp ON rp.role_id = r.id
                        LEFT JOIN permissions p ON p.id = rp.permission_id
                        ORDER BY r.name, p.name
                        """
                    ).fetchall()
                grouped = {}
                for row in roles:
                    grouped.setdefault(row["name"], [])
                    if row["permission"]:
                        grouped[row["name"]].append(row["permission"])
                self._json(
                    200,
                    {"roles": [{"name": name, "permissions": items} for name, items in grouped.items()]},
                )
                return
            self._error(404, "Not found.")
        except APIError as error:
            self._error(error.status, error.message)
        except Exception:
            logging.exception("Request failed.")
            self._error(500, "An unexpected server error occurred.")

    def do_POST(self):
        self._mutate()

    def do_PATCH(self):
        self._mutate()

    def _mutate(self):
        path = urlsplit(self.path).path
        if not path.startswith("/api/"):
            self._error(404, "Not found.")
            return
        try:
            self._check_origin()
            user = self._current_user()
            self._csrf(user)
            data = self._body()
            if self.command == "POST" and path == "/api/auth/register":
                self._register(data)
                return
            if self.command == "POST" and path == "/api/auth/login":
                self._login(data)
                return
            if self.command == "POST" and path == "/api/auth/logout":
                user = self._require_user()
                with connect_db() as db:
                    db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(self._cookies()[SESSION_COOKIE]),))
                self._json(
                    200,
                    {"ok": True},
                    [("Set-Cookie", self._session_cookie("", 0))],
                )
                return
            if self.command == "POST" and path == "/api/auth/change-password":
                self._change_password(data)
                return
            match = re.fullmatch(r"/api/admin/users/(\d+)/role", path)
            if self.command == "PATCH" and match:
                self._change_role(int(match.group(1)), data)
                return
            self._error(404, "Not found.")
        except APIError as error:
            self._error(error.status, error.message)
        except Exception:
            logging.exception("Request failed.")
            self._error(500, "An unexpected server error occurred.")

    def _register(self, data):
        email = validate_email(data.get("email", "") if isinstance(data.get("email", ""), str) else "")
        name = data.get("display_name", "")
        password = data.get("password", "")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
            raise APIError(400, "Your name must be between 1 and 80 characters.")
        try:
            name.strip().encode("utf-8")
        except UnicodeEncodeError:
            raise APIError(400, "Enter a valid name.")
        validate_password(password)
        with connect_db() as db:
            role_id = db.execute("SELECT id FROM roles WHERE name = 'member'").fetchone()["id"]
            try:
                cursor = db.execute(
                    "INSERT INTO users(email, display_name, password_hash, role_id, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        email,
                        name.strip(),
                        hash_password(password),
                        role_id,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                user_id = cursor.lastrowid
            except sqlite3.IntegrityError:
                raise APIError(409, "An account with that email already exists.")
        token, csrf = self._create_session(user_id)
        self._json(
            201,
            {"authenticated": True, "user": self._load_public_user(user_id), "csrf_token": csrf},
            [("Set-Cookie", self._session_cookie(token))],
        )

    def _login(self, data):
        email = validate_email(data.get("email", "") if isinstance(data.get("email", ""), str) else "")
        password = data.get("password", "")
        if not isinstance(password, str) or len(password) > 512:
            raise APIError(400, "Check your email and password.")
        client_ip = self.client_address[0]
        if take_login_attempt(client_ip, email):
            raise APIError(429, "Too many unsuccessful attempts. Try again in a few minutes.")
        with connect_db() as db:
            row = db.execute(
                "SELECT id, password_hash FROM users WHERE email = ?",
                (email,),
            ).fetchone()
        stored_hash = row["password_hash"] if row else DUMMY_PASSWORD_HASH
        password_matches = verify_password(password, stored_hash)
        if row is None or not password_matches:
            record_login_failure(client_ip, email)
            raise APIError(401, "Check your email and password.")
        with LOGIN_FAILURES_LOCK:
            LOGIN_FAILURES.pop((client_ip, email), None)
        token, csrf = self._create_session(row["id"])
        self._json(
            200,
            {"authenticated": True, "user": self._load_public_user(row["id"]), "csrf_token": csrf},
            [("Set-Cookie", self._session_cookie(token))],
        )

    def _change_password(self, data):
        user = self._require_user()
        current = data.get("current_password", "")
        new_password = data.get("new_password", "")
        if not isinstance(current, str) or not isinstance(new_password, str):
            raise APIError(400, "Enter your current and new passwords.")
        validate_password(new_password)
        with connect_db() as db:
            row = db.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
        if not row or not verify_password(current, row["password_hash"]):
            raise APIError(400, "Your current password is incorrect.")
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = int(time.time())
        with connect_db() as db:
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_password), user["id"]))
            db.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
            db.execute(
                "INSERT INTO sessions(token_hash, csrf_token, user_id, expires_at, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (token_hash(token), csrf, user["id"], now + SESSION_TTL, now),
            )
        self._json(
            200,
            {"ok": True, "csrf_token": csrf, "message": "Password updated. Other sessions were signed out."},
            [("Set-Cookie", self._session_cookie(token))],
        )

    def _change_role(self, user_id, data):
        self._require_user("users:manage")
        role_name = data.get("role")
        if role_name not in ("admin", "member"):
            raise APIError(400, "Choose a valid role.")
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            target = db.execute(
                """
                SELECT u.id, r.name AS role
                FROM users u JOIN roles r ON r.id = u.role_id
                WHERE u.id = ?
                """,
                (user_id,),
            ).fetchone()
            if target is None:
                raise APIError(404, "User not found.")
            if target["role"] == "admin" and role_name != "admin":
                admins = db.execute(
                    """
                    SELECT COUNT(*) AS count
                    FROM users u JOIN roles r ON r.id = u.role_id
                    WHERE r.name = 'admin'
                    """
                ).fetchone()["count"]
                if admins <= 1:
                    raise APIError(409, "The last administrator cannot be demoted.")
            role_id = db.execute("SELECT id FROM roles WHERE name = ?", (role_name,)).fetchone()["id"]
            db.execute("UPDATE users SET role_id = ? WHERE id = ?", (role_id, user_id))
        self._json(200, {"ok": True})

    def _load_public_user(self, user_id):
        with connect_db() as db:
            row = db.execute(
                """
                SELECT u.id, u.email, u.display_name, u.created_at, r.name AS role
                FROM users u JOIN roles r ON r.id = u.role_id
                WHERE u.id = ?
                """,
                (user_id,),
            ).fetchone()
            user = dict(row)
            user["permissions"] = user_permissions(db, user_id)
            return user

    def _public_user(self, user):
        return {
            key: user[key]
            for key in ("id", "email", "display_name", "created_at", "role", "permissions")
        }

    def do_PUT(self):
        self._error(405, "Method not allowed.")

    def do_DELETE(self):
        self._error(405, "Method not allowed.")

    def do_OPTIONS(self):
        self._error(405, "Method not allowed.")


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    init_database()
    server = ThreadingHTTPServer((HOST, PORT), IAMHandler)
    logging.info("Secure IAM Portal listening at http://%s:%s", HOST, PORT)
    if not os.environ.get("IAM_ADMIN_EMAIL"):
        logging.warning("No bootstrap admin configured. Set IAM_ADMIN_EMAIL and IAM_ADMIN_PASSWORD before first launch.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
