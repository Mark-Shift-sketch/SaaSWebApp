import pytest
from itsdangerous import BadSignature


# --- Fake DB layer (mock get_connection -> FakeConn -> FakeCursor) ---

class FakeCursor:
    def __init__(self):
        self._last_result = None
        self._fetch_queue = []

    def execute(self, query, params=None):
        q = " ".join(str(query).split()).lower()

        # 1) request_types (udashboard)
        if "from request_types" in q:
            self._last_result = [
                {
                    "request_type_id": 1,
                    "type_name": "Leave Form",
                    "template_filename": "leave.pdf",
                    "template_mode": "upload",
                },
                {
                    "request_type_id": 2,
                    "type_name": "Purchase Request",
                    "template_filename": "pr.pdf",
                    "template_mode": "annotate",
                },
            ]
            return

        # 2) recent_requests (udashboard)
        if "from requests r" in q and "join users u" in q and "limit 200" in q:
            self._last_result = [
                {
                    "request_id": 101,
                    "created_at": "2026-02-24 10:00:00",
                    "filename": "file1.pdf",
                    "email": "user1@phinmaed.com",
                    "dept_name": "GSD",
                    "type_name": "Leave Form",
                    "status_name": "PENDING",
                    "stage_position_id": 1,
                },
                {
                    "request_id": 102,
                    "created_at": "2026-02-24 11:00:00",
                    "filename": None,
                    "email": "user2@phinmaed.com",
                    "dept_name": "GSD",
                    "type_name": "Purchase Request",
                    "status_name": "APPROVED",
                    "stage_position_id": 1,
                },
            ]
            return

        # 3) counts (udashboard) -> returns {"c": number}
        if "select count(*) as c" in q:
            if "status_name='pending'" in q:
                self._fetch_queue = [{"c": 1}]
            elif "status_name='approved'" in q:
                self._fetch_queue = [{"c": 1}]
            elif "status_name='rejected'" in q:
                self._fetch_queue = [{"c": 0}]
            else:
                self._fetch_queue = [{"c": 0}]
            return

        # 4) approvals_today (udashboard)
        if "from request_actions" in q and "action='approved'" in q and "as c" in q:
            self._fetch_queue = [{"c": 1}]
            return

        # 5) history_rows (udashboard)
        if "from request_actions" in q and "order by" in q:
            self._last_result = [
                {
                    "request_id": 101,
                    "action": "APPROVED",
                    "actor_email": "approver@phinmaed.com",
                    "message": "ok",
                    "created_at": "2026-02-24 12:00:00",
                }
            ]
            return

        self._last_result = []
        self._fetch_queue = []

    def fetchall(self):
        return self._last_result or []

    def fetchone(self):
        if self._fetch_queue:
            return self._fetch_queue.pop(0)
        return {"c": 0, "count": 0}

    def close(self):
        pass


class FakeConn:
    def cursor(self, dictionary=True):
        return FakeCursor()

    def close(self):
        pass


def fake_get_connection():
    return FakeConn()


# ----------------- TESTS -----------------

def test_login_page_loads(client):
    r = client.get("/login")
    assert r.status_code == 200


def test_redirect_when_not_logged_in(client):
    r = client.get("/udashboard", follow_redirects=False)
    assert r.status_code in (301, 302)
    assert "/login" in (r.headers.get("Location", "") or "")


def test_udashboard_loads_when_logged_in_with_mocked_db(client, monkeypatch):
    import main
    monkeypatch.setattr(main, "get_connection", fake_get_connection)
    monkeypatch.setattr(main, "ensure_session_company_context", lambda cursor: 1)
    monkeypatch.setattr(main, "get_user_id_for_company", lambda email, company_id: 1)

    with client.session_transaction() as sess:
        sess["email"] = "dev@example.com"
        sess["role"] = "dev"
        sess["company_id"] = 1
        sess["dept"] = "GSD"
        sess["position_id"] = 1
        sess["position"] = "Developer"

    r = client.get("/udashboard")
    assert r.status_code == 200

    body = r.get_data(as_text=True).lower()
    assert "dashboard" in body


def test_activity_logs_requires_login(client):
    r = client.get("/api/activity_logs")
    assert r.status_code == 200
    data = r.get_json()
    assert data["success"] is False


def test_allowed_file_only_accepts_pdf_extension():
    import main

    assert main.allowed_file("request.pdf") is True
    assert main.allowed_file("request.PDF") is True
    assert main.allowed_file("request.txt") is False
    assert main.allowed_file("request") is False


def test_token_create_and_verify_round_trip():
    import main

    token = main.create_token("user@example.com")
    assert main.verify_token(token) == "user@example.com"


def test_verify_token_rejects_invalid_signature():
    import main

    with pytest.raises(BadSignature):
        main.verify_token("not-a-valid-token")


def test_password_policy_requires_symbol_by_default():
    import main

    ok, _ = main.validate_password_strength("Validpass1")
    assert ok is False


def test_password_policy_accepts_strong_password():
    import main

    ok, _ = main.validate_password_strength("Validpass1!")
    assert ok is True


def test_api_user_dashboard_requires_bearer_token(client):
    r = client.get("/api/user_dashboard")
    assert r.status_code == 401
    assert r.get_json() == {"error": "Missing token"}


@pytest.mark.parametrize(
    "session_data, expected_path",
    [
        ({}, "/login"),
        (
            {
                "email": "dean@example.com",
                "role": "Dean",
                "dept": "CEA",
                "position": "Dean",
            },
            "/dean",
        ),
        (
            {
                "email": "admin@example.com",
                "role": "Admin",
                "dept": "GSD",
                "position": "Admin",
            },
            "/gsd_dashboard",
        ),
        (
            {
                "email": "admin2@example.com",
                "role": "Admin",
                "dept": "CEA",
                "position": "Admin",
            },
            "/admin",
        ),
        (
            {
                "email": "it@example.com",
                "role": "IT",
                "dept": "IT",
                "position": "IT",
            },
            "/IT",
        ),
        (
            {
                "email": "user@example.com",
                "role": "User",
                "dept": "CEA",
                "position": "None",
            },
            "/udashboard",
        ),
    ],
)
def test_home_redirects_to_role_dashboard(client, session_data, expected_path):
    with client.session_transaction() as sess:
        sess.clear()
        for key, value in session_data.items():
            sess[key] = value

    r = client.get("/", follow_redirects=False)
    assert r.status_code in (301, 302)
    assert expected_path in (r.headers.get("Location", "") or "")


def test_logout_clears_session(client):
    with client.session_transaction() as sess:
        sess["email"] = "user@example.com"
        sess["role"] = "User"

    r = client.get("/logout", follow_redirects=False)
    assert r.status_code in (301, 302)
    assert "/login" in (r.headers.get("Location", "") or "")

    with client.session_transaction() as sess:
        assert "email" not in sess
        assert "role" not in sess


def test_security_headers_are_set(client):
    r = client.get("/login")

    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert r.headers.get("Cross-Origin-Resource-Policy") == "same-site"
    assert "default-src 'self'" in (r.headers.get("Content-Security-Policy") or "")


def test_inventory_api_requires_login(client):
    r = client.post("/api/inventory", json={"product_name": "Paper", "quantity": 1})
    assert r.status_code == 401


def test_inventory_api_forbidden_for_non_gsd_user(client):
    with client.session_transaction() as sess:
        sess["email"] = "user@example.com"
        sess["role"] = "User"
        sess["dept"] = "CEA"

    r = client.post("/api/inventory", json={"product_name": "Paper", "quantity": 1})
    assert r.status_code == 403


def test_forgot_password_page_loads(client):
    r = client.get("/forgot-password")
    assert r.status_code == 200


def test_login_page_contains_forgot_password_link(client):
    r = client.get("/login")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "/forgot-password" in body


def test_password_reset_token_round_trip():
    import main

    token = main.create_password_reset_token("user@example.com")
    assert main.verify_password_reset_token(token) == "user@example.com"


def test_reset_password_invalid_token_message(client):
    r = client.get("/reset-password/not-a-valid-token")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Invalid reset link" in body


def test_check_company_user_seat_capacity_blocks_when_limit_reached():
    import main

    class _Cursor:
        def __init__(self):
            self._last_query = ""

        def execute(self, query, params=None):
            self._last_query = " ".join(str(query).split()).lower()

        def fetchone(self):
            if "from tenant_subscriptions" in self._last_query:
                return {
                    "plan_name": "FREE",
                    "subscription_status": "ACTIVE",
                    "seats_limit": 1,
                    "requests_limit": 200,
                }
            if "count(*) as count from users" in self._last_query:
                return {"count": 1}
            return {}

    ok, msg = main.check_company_user_seat_capacity(_Cursor(), 10)
    assert ok is False
    assert "Seat limit reached" in msg


def test_check_company_request_capacity_blocks_when_monthly_limit_reached():
    import main

    class _Cursor:
        def __init__(self):
            self._last_query = ""

        def execute(self, query, params=None):
            self._last_query = " ".join(str(query).split()).lower()

        def fetchone(self):
            if "from tenant_subscriptions" in self._last_query:
                return {
                    "plan_name": "FREE",
                    "subscription_status": "ACTIVE",
                    "seats_limit": 10,
                    "requests_limit": 2,
                }
            if "from requests" in self._last_query and "count(*) as count" in self._last_query:
                return {"count": 2}
            return {}

    ok, msg = main.check_company_request_capacity(_Cursor(), 10)
    assert ok is False
    assert "Monthly request limit reached" in msg


def test_check_company_capacity_rejects_inactive_subscription():
    import main

    class _Cursor:
        def __init__(self):
            self._last_query = ""

        def execute(self, query, params=None):
            self._last_query = " ".join(str(query).split()).lower()

        def fetchone(self):
            if "from tenant_subscriptions" in self._last_query:
                return {
                    "plan_name": "PRO",
                    "subscription_status": "SUSPENDED",
                    "seats_limit": 100,
                    "requests_limit": 5000,
                }
            return {}

    user_ok, user_msg = main.check_company_user_seat_capacity(_Cursor(), 10)
    req_ok, req_msg = main.check_company_request_capacity(_Cursor(), 10)
    assert user_ok is False
    assert req_ok is False
    assert "Subscription is not active" in user_msg
    assert "Subscription is not active" in req_msg