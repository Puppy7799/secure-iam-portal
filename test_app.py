import http.cookiejar
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import server


class IAMApplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        server.DATABASE_PATH = os.path.join(cls.temp_dir.name, "test.db")
        server.init_database()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.IAMHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = "http://127.0.0.1:{}".format(cls.httpd.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.thread.join()
        cls.httpd.server_close()
        cls.temp_dir.cleanup()

    def setUp(self):
        server.LOGIN_FAILURES.clear()
        self.cookies = http.cookiejar.CookieJar()
        self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies))
        self.csrf = self.request("/api/session")[1]["csrf_token"]

    def request(self, path, method="GET", data=None, expected_status=200):
        headers = {}
        payload = None
        if data is not None:
            payload = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if method != "GET":
            headers["X-CSRF-Token"] = self.csrf
            headers["Origin"] = self.base_url
        request = urllib.request.Request(
            self.base_url + path,
            data=payload,
            headers=headers,
            method=method,
        )
        try:
            response = self.client.open(request)
        except urllib.error.HTTPError as error:
            response = error
        result = json.loads(response.read().decode("utf-8"))
        self.assertEqual(response.status, expected_status, result)
        if response.status < 400 and result.get("csrf_token"):
            self.csrf = result["csrf_token"]
        return response, result

    def register(self, email="member@example.test", password="correct horse battery"):
        _, result = self.request(
            "/api/auth/register",
            "POST",
            {"email": email, "display_name": "Test Member", "password": password},
            201,
        )
        self.csrf = result["csrf_token"]
        return result

    def test_public_and_dashboard_user_totals(self):
        _, before = self.request("/api/public/stats")
        self.assertGreaterEqual(before["total_users"], 0)
        self.register("total-{}@example.test".format(threading.get_ident()))
        _, after = self.request("/api/public/stats")
        self.assertEqual(after["total_users"], before["total_users"] + 1)
        _, dashboard = self.request("/api/dashboard")
        self.assertEqual(dashboard["total_users"], after["total_users"])

    def test_registration_login_and_password_change(self):
        registered = self.register()
        self.assertEqual(registered["user"]["role"], "member")
        self.assertIn("dashboard:read", registered["user"]["permissions"])
        self.request("/api/admin/users", expected_status=403)
        other_client = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        csrf_request = urllib.request.Request(self.base_url + "/api/session")
        csrf_data = json.loads(other_client.open(csrf_request).read().decode("utf-8"))
        other_login = urllib.request.Request(
            self.base_url + "/api/auth/login",
            data=json.dumps({
                "email": "member@example.test",
                "password": "correct horse battery",
            }).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": csrf_data["csrf_token"],
                "Origin": self.base_url,
            },
            method="POST",
        )
        other_client.open(other_login).read()
        self.request("/api/auth/change-password", "POST", {
            "current_password": "correct horse battery",
            "new_password": "another secure password",
        })
        self.request("/api/dashboard")
        expired_session = urllib.request.Request(self.base_url + "/api/dashboard")
        with self.assertRaises(urllib.error.HTTPError) as error:
            other_client.open(expired_session)
        self.assertEqual(error.exception.code, 401)
        self.request("/api/auth/logout", "POST", {})
        self.request("/api/dashboard", expected_status=401)

    def test_registration_rejects_weak_password_and_duplicate_email(self):
        self.request(
            "/api/auth/register",
            "POST",
            {"email": "weak@example.test", "display_name": "Weak", "password": "short"},
            400,
        )
        self.request(
            "/api/auth/register",
            "POST",
            {"email": "invalid@example.test", "display_name": "Invalid", "password": "valid passphrase\ud800"},
            400,
        )
        self.register("duplicate@example.test")
        self.request(
            "/api/auth/register",
            "POST",
            {"email": "duplicate@example.test", "display_name": "Again", "password": "correct horse battery"},
            409,
        )

    def test_admin_can_assign_role_but_last_admin_cannot_be_demoted(self):
        with server.connect_db() as db:
            admin_role = db.execute("SELECT id FROM roles WHERE name = 'admin'").fetchone()["id"]
            db.execute(
                "INSERT INTO users(email, display_name, password_hash, role_id, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    "admin@example.test",
                    "Admin",
                    server.hash_password("admin password long"),
                    admin_role,
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            member_role = db.execute("SELECT id FROM roles WHERE name = 'member'").fetchone()["id"]
            db.execute(
                "INSERT INTO users(email, display_name, password_hash, role_id, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    "role-target@example.test",
                    "Role Target",
                    server.hash_password("target password long"),
                    member_role,
                    "2026-02-01T00:00:00+00:00",
                ),
            )
        self.request("/api/auth/login", "POST", {
            "email": "admin@example.test",
            "password": "admin password long",
        })
        self.request("/api/admin/users", expected_status=200)
        with server.connect_db() as db:
            admin_id = db.execute("SELECT id FROM users WHERE email = 'admin@example.test'").fetchone()["id"]
            target_id = db.execute(
                "SELECT id FROM users WHERE email = 'role-target@example.test'"
            ).fetchone()["id"]
        self.request("/api/admin/users/{}/role".format(admin_id), "PATCH", {"role": "member"}, 409)
        self.request("/api/admin/users/{}/role".format(target_id), "PATCH", {"role": "admin"})
        with server.connect_db() as db:
            target_role = db.execute(
                "SELECT r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = ?",
                (target_id,),
            ).fetchone()["name"]
        self.assertEqual(target_role, "admin")

    def test_state_changing_route_requires_csrf_token(self):
        request = urllib.request.Request(
            self.base_url + "/api/auth/register",
            data=json.dumps({
                "email": "csrf@example.test",
                "display_name": "CSRF Test",
                "password": "correct horse battery",
            }).encode("utf-8"),
            headers={"Content-Type": "application/json", "Origin": self.base_url, "X-CSRF-Token": "invalid"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.client.open(request)
        self.assertEqual(error.exception.code, 403)


if __name__ == "__main__":
    unittest.main()
