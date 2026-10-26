import os
import pytest
from app import create_app
from app.models import db, User, Resource, ActivityLog
from app.config import Config


class TestConfig(Config):
    TESTING = True
    # If running with real Postgres DB or testing SQLite fallback:
    # Use existing DATABASE_URL or SQLite in-memory for testing isolation
    SQLALCHEMY_DATABASE_URI = os.getenv("TEST_DATABASE_URL", os.getenv("DATABASE_URL"))
    SECRET_KEY = "test-secret-key-32-bytes-minimum-security-required-12345"
    S3_BUCKET_NAME = "test-sentinel-bucket"
    AWS_REGION = "us-east-1"
    ADMIN_USERNAME = "testadmin"
    ADMIN_PASSWORD = "testpassword123"
    ADMIN_EMAIL = "testadmin@sentinel.local"


@pytest.fixture(scope="session")
def app():
    """Create Flask application instance for testing."""
    test_app = create_app(TestConfig)
    with test_app.app_context():
        if "sqlite" in (test_app.config.get("SQLALCHEMY_DATABASE_URI") or ""):
            db.create_all()
        yield test_app


@pytest.fixture
def client(app):
    """Test client fixture."""
    return app.test_client()


@pytest.fixture(autouse=True)
def clean_test_state(app):
    """Clean up test-created users and resources before and after each test for isolation."""
    def _do_cleanup():
        with app.app_context():
            try:
                test_usernames = [
                    "devops_user_01", "sneaky_admin_candidate", "duplicate_check_user",
                    "unique_user_a", "unique_user_b", "login_flow_user", "email_login_user",
                    "pw_user", "regular_user", "user_alice", "user_bob",
                    "resource_owner_user", "other_normal_user", "deleter_user",
                    "user_editor", "user_intruder", "user_fail_test", "transition_test_user",
                    "identifier_user", "user_owner_p4", "user_stranger_p4"
                ]
                users = User.query.filter(User.username.in_(test_usernames)).all()
                if users:
                    u_ids = [u.id for u in users]
                    ActivityLog.query.filter(ActivityLog.user_id.in_(u_ids)).delete(synchronize_session=False)
                    Resource.query.filter(Resource.uploaded_by.in_(u_ids)).delete(synchronize_session=False)
                    User.query.filter(User.id.in_(u_ids)).delete(synchronize_session=False)
                    db.session.commit()
            except Exception:
                db.session.rollback()

    _do_cleanup()
    yield
    _do_cleanup()


@pytest.fixture
def auth_headers(client, app):
    """Returns headers containing valid admin JWT token."""
    with app.app_context():
        response = client.post("/auth/login", json={
            "username": "testadmin",
            "password": "testpassword123"
        })
        assert response.status_code == 200
        token = response.get_json()["token"]
        return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def regular_user_headers(client, app):
    """Returns headers containing valid regular user JWT token."""
    with app.app_context():
        username = "fixture_reg_user"
        email = "fixture_reg_user@example.com"
        password = "Password123"
        user = User.query.filter_by(username=username).first()
        if not user:
            client.post("/auth/register", json={
                "username": username,
                "email": email,
                "password": password
            })
        response = client.post("/auth/login", json={
            "username": username,
            "password": password
        })
        assert response.status_code == 200
        token = response.get_json()["token"]
        return {"Authorization": f"Bearer {token}"}
