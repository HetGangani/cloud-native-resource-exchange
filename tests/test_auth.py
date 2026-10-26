from datetime import datetime, timedelta, timezone
import jwt
from werkzeug.security import check_password_hash

from app.models import ActivityLog, User, db


def test_login_missing_payload(client):
    """Test login with missing username or password."""
    response = client.post("/auth/login", json={})
    assert response.status_code == 400


def test_login_failed_records_activity_log(client, app):
    """Test login failure records login_failed action in ActivityLog and returns 401."""
    with app.app_context():
        initial_failed_logs = ActivityLog.query.filter_by(action="login_failed").count()

        response = client.post("/auth/login", json={
            "username": "nonexistent_user",
            "password": "wrong_password"
        })
        assert response.status_code == 401
        assert "Invalid username or password" in response.get_json()["error"]

        new_failed_logs = ActivityLog.query.filter_by(action="login_failed").count()
        assert new_failed_logs == initial_failed_logs + 1


def test_login_success_and_protected_route(client, app):
    """Test login succeeds, returns JWT, records login_success, and allows accessing /auth/me."""
    with app.app_context():
        response = client.post("/auth/login", json={
            "username": "testadmin",
            "password": "testpassword123"
        })
        assert response.status_code == 200
        data = response.get_json()
        assert "token" in data
        assert data["user"]["is_admin"] is True

        token = data["token"]

        # Call /auth/me without token -> 401
        res_no_auth = client.get("/auth/me")
        assert res_no_auth.status_code == 401

        # Call /auth/me with token -> 200
        res_auth = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res_auth.status_code == 200
        me_data = res_auth.get_json()
        assert me_data["username"] == "testadmin"
        assert me_data["is_admin"] is True


def test_registration_success(client, app):
    """Test successful user registration with valid inputs."""
    with app.app_context():
        payload = {
            "username": "devops_user_01",
            "email": "devops01@sentinel.io",
            "password": "SecurePassword123"
        }
        res = client.post("/auth/register", json=payload)
        assert res.status_code == 201
        data = res.get_json()
        assert data["message"] == "User registered successfully"
        user_info = data["user"]
        assert user_info["username"] == "devops_user_01"
        assert user_info["email"] == "devops01@sentinel.io"
        assert user_info["is_admin"] is False
        assert "password" not in user_info
        assert "password_hash" not in user_info
        assert "password_hash" not in data

        # Verify password is secure hash in database, not plaintext
        user = User.query.filter_by(username="devops_user_01").first()
        assert user is not None
        assert user.password_hash != "SecurePassword123"
        assert check_password_hash(user.password_hash, "SecurePassword123")

        # Verify activity log entry
        reg_log = ActivityLog.query.filter_by(
            action="user_registered",
            user_id=user.id
        ).first()
        assert reg_log is not None
        assert "devops_user_01" in reg_log.detail


def test_registration_duplicate_username(client, app):
    """Test registration rejects duplicate username with 409 Conflict."""
    with app.app_context():
        # First registration
        client.post("/auth/register", json={
            "username": "duplicate_check_user",
            "email": "dup1@sentinel.io",
            "password": "Password123"
        })

        # Second registration with same username but different email
        res = client.post("/auth/register", json={
            "username": "duplicate_check_user",
            "email": "dup2@sentinel.io",
            "password": "Password123"
        })
        assert res.status_code == 409
        data = res.get_json()
        assert "already registered" in data["error"].lower()


def test_registration_duplicate_email(client, app):
    """Test registration rejects duplicate email with 409 Conflict."""
    with app.app_context():
        # First registration
        client.post("/auth/register", json={
            "username": "unique_user_a",
            "email": "shared_email@sentinel.io",
            "password": "Password123"
        })

        # Second registration with different username but same email
        res = client.post("/auth/register", json={
            "username": "unique_user_b",
            "email": "shared_email@sentinel.io",
            "password": "Password123"
        })
        assert res.status_code == 409
        data = res.get_json()
        assert "already registered" in data["error"].lower()


def test_registration_missing_and_empty_fields(client):
    """Test registration validates missing or empty fields."""
    # Non-dict / empty body
    res = client.post("/auth/register", data="not json", content_type="text/plain")
    assert res.status_code == 400

    # Missing username
    res = client.post("/auth/register", json={
        "email": "test@example.com",
        "password": "Password123"
    })
    assert res.status_code == 400
    assert "Username is required" in res.get_json()["error"]

    # Missing email
    res = client.post("/auth/register", json={
        "username": "testuser_valid",
        "password": "Password123"
    })
    assert res.status_code == 400
    assert "Email address is required" in res.get_json()["error"]

    # Missing password
    res = client.post("/auth/register", json={
        "username": "testuser_valid",
        "email": "test@example.com"
    })
    assert res.status_code == 400
    assert "Password is required" in res.get_json()["error"]


def test_registration_invalid_username_format(client):
    """Test registration rejects usernames failing length or character rules."""
    # Too short (<3 chars)
    res = client.post("/auth/register", json={
        "username": "ab",
        "email": "short@example.com",
        "password": "Password123"
    })
    assert res.status_code == 400

    # Disallowed characters (spaces or special characters)
    res = client.post("/auth/register", json={
        "username": "invalid user!",
        "email": "invalid@example.com",
        "password": "Password123"
    })
    assert res.status_code == 400


def test_registration_invalid_email_format(client):
    """Test registration rejects malformed email addresses."""
    invalid_emails = ["not-an-email", "user@", "@domain.com", "user@domain", "user space@domain.com"]
    for email in invalid_emails:
        res = client.post("/auth/register", json={
            "username": "email_test_usr",
            "email": email,
            "password": "Password123"
        })
        assert res.status_code == 400, f"Expected 400 for email: {email}"
        assert "email" in res.get_json()["error"].lower()


def test_registration_password_policy(client):
    """Test registration enforces minimum length and alphanumeric policy."""
    # Too short (<8 chars)
    res = client.post("/auth/register", json={
        "username": "pass_policy_usr",
        "email": "pass1@example.com",
        "password": "Pass1"
    })
    assert res.status_code == 400
    assert "8 characters" in res.get_json()["error"]

    # Letters only (no digits)
    res = client.post("/auth/register", json={
        "username": "pass_policy_usr2",
        "email": "pass2@example.com",
        "password": "PasswordOnlyLetters"
    })
    assert res.status_code == 400
    assert "both letters and numbers" in res.get_json()["error"]

    # Digits only (no letters)
    res = client.post("/auth/register", json={
        "username": "pass_policy_usr3",
        "email": "pass3@example.com",
        "password": "1234567890"
    })
    assert res.status_code == 400
    assert "both letters and numbers" in res.get_json()["error"]


def test_public_registration_cannot_grant_admin_privileges(client, app):
    """Prove public registration cannot create an administrator even if requested."""
    with app.app_context():
        # Attacker tries to pass is_admin=True and role='admin'
        payload = {
            "username": "sneaky_admin_candidate",
            "email": "sneaky@example.com",
            "password": "Password123",
            "is_admin": True,
            "role": "admin",
            "admin": True
        }
        res = client.post("/auth/register", json=payload)
        assert res.status_code == 201
        data = res.get_json()
        assert data["user"]["is_admin"] is False

        # Verify in database directly
        user = User.query.filter_by(username="sneaky_admin_candidate").first()
        assert user is not None
        assert user.is_admin is False


def test_registered_user_login_and_auth_me(client, app):
    """Test a newly registered user can log in and view their /auth/me profile."""
    with app.app_context():
        client.post("/auth/register", json={
            "username": "login_flow_user",
            "email": "flow@sentinel.io",
            "password": "FlowPassword99"
        })

        # Login with username
        res = client.post("/auth/login", json={
            "username": "login_flow_user",
            "password": "FlowPassword99"
        })
        assert res.status_code == 200
        data = res.get_json()
        assert "token" in data
        assert data["user"]["username"] == "login_flow_user"
        assert data["user"]["email"] == "flow@sentinel.io"
        assert data["user"]["is_admin"] is False

        # Access /auth/me
        token = data["token"]
        me_res = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_res.status_code == 200
        me = me_res.get_json()
        assert me["username"] == "login_flow_user"
        assert me["email"] == "flow@sentinel.io"
        assert me["is_admin"] is False


def test_login_with_email_identifier(client, app):
    """Test user can log in using email address instead of username."""
    with app.app_context():
        client.post("/auth/register", json={
            "username": "email_login_user",
            "email": "email_login@sentinel.io",
            "password": "Password123"
        })

        # Login passing email in username field
        res = client.post("/auth/login", json={
            "username": "email_login@sentinel.io",
            "password": "Password123"
        })
        assert res.status_code == 200
        assert res.get_json()["user"]["username"] == "email_login_user"

        # Login passing email in email field
        res2 = client.post("/auth/login", json={
            "email": "email_login@sentinel.io",
            "password": "Password123"
        })
        assert res2.status_code == 200
        assert res2.get_json()["user"]["username"] == "email_login_user"


def test_login_generic_error_on_invalid_credentials(client, app):
    """Test login failure gives identical error message whether user exists or not."""
    with app.app_context():
        client.post("/auth/register", json={
            "username": "existing_auth_user",
            "email": "existing_auth@sentinel.io",
            "password": "CorrectPassword123"
        })

        # Existing user with wrong password
        res1 = client.post("/auth/login", json={
            "username": "existing_auth_user",
            "password": "WrongPassword999"
        })
        assert res1.status_code == 401
        err1 = res1.get_json()["error"]

        # Non-existing user
        res2 = client.post("/auth/login", json={
            "username": "completely_fictional_user",
            "password": "WrongPassword999"
        })
        assert res2.status_code == 401
        err2 = res2.get_json()["error"]

        # Messages must be identical to prevent username enumeration
        assert err1 == err2
        assert "Invalid username or password" in err1


def test_protected_endpoints_invalid_or_expired_tokens(client, app):
    """Test protected endpoint rejects missing, malformed, and expired JWT tokens."""
    # Missing token
    res_no_tok = client.get("/auth/me")
    assert res_no_tok.status_code == 401
    assert "token is required" in res_no_tok.get_json()["error"].lower()

    # Malformed token
    res_bad_tok = client.get("/auth/me", headers={"Authorization": "Bearer not-a-valid-jwt"})
    assert res_bad_tok.status_code == 401

    # Expired token
    with app.app_context():
        expired_payload = {
            "sub": "1",
            "username": "testadmin",
            "is_admin": True,
            "iat": datetime.now(timezone.utc) - timedelta(hours=48),
            "exp": datetime.now(timezone.utc) - timedelta(hours=24),
        }
        expired_token = jwt.encode(
            expired_payload,
            app.config["SECRET_KEY"],
            algorithm="HS256"
        )
        res_expired = client.get("/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
        assert res_expired.status_code == 401
        assert "expired" in res_expired.get_json()["error"].lower()


def test_regular_user_cannot_access_admin_action(client, app):
    """Test a regular user cannot perform admin-only actions (PATCH /resources/<id>/approve)."""
    with app.app_context():
        # Register regular user
        client.post("/auth/register", json={
            "username": "unprivileged_user",
            "email": "unprivileged@sentinel.io",
            "password": "Password123"
        })
        login_res = client.post("/auth/login", json={
            "username": "unprivileged_user",
            "password": "Password123"
        })
        regular_token = login_res.get_json()["token"]

        # Attempt to approve a resource
        res = client.patch(
            "/resources/1/approve",
            headers={"Authorization": f"Bearer {regular_token}"}
        )
        assert res.status_code == 403
        assert "Administrator privileges required" in res.get_json()["error"]


def test_logout_endpoint(client, app):
    """Test logout endpoint returns success and instructs client to clear token."""
    res = client.post("/auth/logout")
    assert res.status_code == 200
    data = res.get_json()
    assert "Logged out successfully" in data["message"]
    assert data["stateless"] is True


def test_login_with_identifier_request_field(client, app):
    """Test login succeeds using the 'identifier' field with both username and email."""
    with app.app_context():
        client.post("/auth/register", json={
            "username": "identifier_user",
            "email": "identifier@sentinel.io",
            "password": "Password123"
        })

        # Login using identifier as username
        res1 = client.post("/auth/login", json={
            "identifier": "identifier_user",
            "password": "Password123"
        })
        assert res1.status_code == 200
        assert "token" in res1.get_json()
        assert res1.get_json()["user"]["username"] == "identifier_user"

        # Login using identifier as email
        res2 = client.post("/auth/login", json={
            "identifier": "identifier@sentinel.io",
            "password": "Password123"
        })
        assert res2.status_code == 200
        assert "token" in res2.get_json()
        assert res2.get_json()["user"]["username"] == "identifier_user"


def test_token_signed_with_wrong_secret_returns_401(client, app):
    """Test token signed with an unauthorized secret key is rejected with HTTP 401."""
    with app.app_context():
        untrusted_payload = {
            "sub": "1",
            "username": "testadmin",
            "is_admin": True,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        untrusted_token = jwt.encode(
            untrusted_payload,
            "unauthorized-attacker-secret-key-99999",
            algorithm="HS256"
        )
        res = client.get("/auth/me", headers={"Authorization": f"Bearer {untrusted_token}"})
        assert res.status_code == 401
        assert "Invalid token" in res.get_json()["error"]


def test_tampered_token_payload_returns_401(client, app):
    """Test modifying token payload claims without recalculating signature is rejected with HTTP 401."""
    with app.app_context():
        valid_payload = {
            "sub": "1",
            "username": "testadmin",
            "is_admin": False,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        valid_token = jwt.encode(valid_payload, app.config["SECRET_KEY"], algorithm="HS256")
        
        # Tamper token by altering the payload part
        parts = valid_token.split(".")
        assert len(parts) == 3
        tampered_token = f"{parts[0]}.eyJhZG1pbiI6dHJ1ZX0.{parts[2]}"

        res = client.get("/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
        assert res.status_code == 401
        assert "Invalid token" in res.get_json()["error"]


def test_token_with_non_numeric_subject_returns_401_gracefully(client, app):
    """Test token with a non-numeric subject claim returns HTTP 401 instead of raising HTTP 500."""
    with app.app_context():
        bad_sub_payload = {
            "sub": "non-numeric-uuid-string",
            "username": "attacker",
            "is_admin": False,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        token = jwt.encode(bad_sub_payload, app.config["SECRET_KEY"], algorithm="HS256")
        res = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 401
        assert "Invalid token" in res.get_json()["error"]


def test_token_with_nonexistent_user_returns_401(client, app):
    """Test validly signed token referencing a deleted or nonexistent user ID returns HTTP 401."""
    with app.app_context():
        nonexistent_payload = {
            "sub": "99999999",
            "username": "deleted_user",
            "is_admin": False,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        token = jwt.encode(nonexistent_payload, app.config["SECRET_KEY"], algorithm="HS256")
        res = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 401
        assert "User not found" in res.get_json()["error"]


def test_unauthenticated_versus_unauthorized_status_codes(client, app):
    """Verify unauthenticated requests return 401 while authenticated non-admins receive 403 on admin routes."""
    with app.app_context():
        # Unauthenticated request to admin endpoint -> 401
        res_unauth = client.patch("/resources/1/approve")
        assert res_unauth.status_code == 401
        assert "token" in res_unauth.get_json()["error"].lower()

        # Authenticated non-admin request to admin endpoint -> 403
        client.post("/auth/register", json={
            "username": "regular_user",
            "email": "regular@sentinel.io",
            "password": "Password123"
        })
        login_res = client.post("/auth/login", json={
            "username": "regular_user",
            "password": "Password123"
        })
        reg_token = login_res.get_json()["token"]

        res_reg = client.patch(
            "/resources/1/approve",
            headers={"Authorization": f"Bearer {reg_token}"}
        )
        assert res_reg.status_code == 403
        assert "Administrator privileges required" in res_reg.get_json()["error"]


def test_existing_admin_authentication_preserves_privileges(client, app):
    """Verify administrator account authenticates and preserves is_admin privileges."""
    with app.app_context():
        res = client.post("/auth/login", json={
            "username": app.config.get("ADMIN_USERNAME", "testadmin"),
            "password": app.config.get("ADMIN_PASSWORD", "testpassword123")
        })
        assert res.status_code == 200
        data = res.get_json()
        assert "token" in data
        assert data["user"]["is_admin"] is True

        token = data["token"]
        me_res = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_res.status_code == 200
        assert me_res.get_json()["is_admin"] is True

