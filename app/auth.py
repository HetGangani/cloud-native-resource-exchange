import logging
import re
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from app.models import ActivityLog, User, db

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
logger = logging.getLogger(__name__)

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,80}$")


def validate_registration_input(username, email, password):
    """Validate registration payload fields, lengths, format, and password policy.
    
    Returns (is_valid: bool, error_message: str | None).
    """
    if not isinstance(username, str) or not username.strip():
        return False, "Username is required"
    if not isinstance(email, str) or not email.strip():
        return False, "Email address is required"
    if not isinstance(password, str) or not password:
        return False, "Password is required"

    username = username.strip()
    email = email.strip()

    if not USERNAME_REGEX.match(username):
        return (
            False,
            "Username must be 3-80 characters and contain only letters, numbers, underscores, or hyphens",
        )

    if len(email) > 120 or not EMAIL_REGEX.match(email):
        return False, "A valid email address format is required"

    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if len(password) > 128:
        return False, "Password must not exceed 128 characters"
    if not (any(c.isalpha() for c in password) and any(c.isdigit() for c in password)):
        return False, "Password must contain both letters and numbers"

    return True, None


def get_client_ip():
    """Retrieve client IP address considering proxy headers."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "unknown"


def generate_jwt_token(user):
    """Generate JWT access token for an authenticated user."""
    expiration_hours = current_app.config.get("JWT_EXPIRATION_HOURS", 24)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "email": getattr(user, "email", None),
        "is_admin": user.is_admin,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=expiration_hours),
    }
    token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")
    return token


def ensure_admin_user():
    """Ensure the default administrator account exists in the database."""
    admin_username = current_app.config.get("ADMIN_USERNAME", "admin")
    admin_password = current_app.config.get("ADMIN_PASSWORD", "admin123")
    admin_email = current_app.config.get("ADMIN_EMAIL", "admin@sentinel.local")

    admin = User.query.filter_by(username=admin_username).first()
    if not admin:
        admin = User(
            username=admin_username,
            email=admin_email,
            password_hash=generate_password_hash(admin_password),
            is_admin=True,
        )
        db.session.add(admin)
        db.session.commit()
        logger.info(f"Initialized default admin account: '{admin_username}'")
    elif getattr(admin, "email", None) is None:
        try:
            admin.email = admin_email
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.warning(f"Could not backfill admin email: {e}")
    return admin


def get_authenticated_user_from_request():
    """Extract and authenticate user from Authorization header if present, else None."""
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    elif "x-access-token" in request.headers:
        token = request.headers.get("x-access-token")

    if not token:
        return None

    try:
        payload = jwt.decode(
            token,
            current_app.config["SECRET_KEY"],
            algorithms=["HS256"],
        )
        sub = payload.get("sub")
        user_id = int(sub) if sub is not None else None
        return db.session.get(User, user_id) if user_id else None
    except Exception:
        return None


def token_required(f):
    """Decorator to require a valid JWT token in Authorization header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = None

        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        elif "x-access-token" in request.headers:
            token = request.headers.get("x-access-token")

        if not token:
            return jsonify({"error": "Authentication token is required"}), 401

        try:
            payload = jwt.decode(
                token,
                current_app.config["SECRET_KEY"],
                algorithms=["HS256"],
            )
            sub = payload.get("sub")
            try:
                user_id = int(sub) if sub is not None else None
            except (ValueError, TypeError):
                return jsonify({"error": "Invalid token"}), 401

            user = db.session.get(User, user_id) if user_id else None
            if not user:
                return jsonify({"error": "User not found"}), 401
            g.current_user = user
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        except Exception as e:
            logger.error(f"Token decoding error: {e}")
            return jsonify({"error": "Authentication failed"}), 401

        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    """Decorator to require administrator privileges."""
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if not getattr(g.current_user, "is_admin", False):
            try:
                activity = ActivityLog(
                    user_id=g.current_user.id,
                    action="access_denied",
                    detail=f"Administrator privileges required for '{request.method} {request.path}' by '{g.current_user.username}'",
                )
                db.session.add(activity)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Failed to record access_denied log: {e}")

            return jsonify({"error": "Administrator privileges required"}), 403
        return f(*args, **kwargs)

    return decorated


@auth_bp.route("/register", methods=["POST"])
def register():
    """Public user registration endpoint.
    
    Contract:
      Input: JSON {"username", "email", "password"}
      Output: 201 Created with user details (excluding password_hash), or 400/409
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be valid JSON"}), 400

    raw_username = data.get("username")
    raw_email = data.get("email")
    raw_password = data.get("password")

    is_valid, error_msg = validate_registration_input(raw_username, raw_email, raw_password)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    username = raw_username.strip()
    email = raw_email.strip().lower()
    password = raw_password
    client_ip = get_client_ip()

    # Pre-checks for duplicate username and email
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username is already registered"}), 409

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email address is already registered"}), 409

    # Public registration strictly assigns regular-user role (is_admin=False).
    # Any client-supplied admin or role flags are ignored.
    new_user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        is_admin=False,
    )

    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username or email is already registered"}), 409
    except Exception as e:
        db.session.rollback()
        logger.error(f"User registration error: {e}")
        return jsonify({"error": "An error occurred during registration"}), 500

    # Structured log and activity record
    logger.info(f"USER_REGISTERED username='{username}' email='{email}' ip='{client_ip}'")
    try:
        log_entry = ActivityLog(
            user_id=new_user.id,
            action="user_registered",
            detail=f"User '{username}' registered with email '{email}' from ip='{client_ip}'",
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as log_err:
        db.session.rollback()
        logger.error(f"Failed to record ActivityLog for user_registered: {log_err}")

    return jsonify({
        "message": "User registered successfully",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "is_admin": new_user.is_admin,
        }
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """Unified login endpoint supporting admin and registered users.
    
    Accepts either username or email in the 'username' (or 'email') field.
    Contract:
      Input: JSON {"username", "password"} or {"email", "password"} or {"identifier", "password"}
      Output: {"token": ..., "user": {...}} 200, or 400/401
    """
    ensure_admin_user()

    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or data.get("username") or data.get("email") or "").strip()
    password = data.get("password", "")
    client_ip = get_client_ip()

    if not identifier or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # Support login with username or email
    user = User.query.filter(
        or_(
            User.username == identifier,
            User.email == identifier.lower()
        )
    ).first()

    if not user or not check_password_hash(user.password_hash, password):
        # Structured log for CloudWatch metric filter and detection
        logger.warning(
            f"LOGIN_FAILED username='{identifier}' ip='{client_ip}'"
        )
        try:
            log_entry = ActivityLog(
                user_id=user.id if user else None,
                action="login_failed",
                detail=f"Failed login attempt for identifier='{identifier}' from ip='{client_ip}'",
            )
            db.session.add(log_entry)
            db.session.commit()
        except Exception as log_err:
            db.session.rollback()
            logger.error(f"Failed to record ActivityLog for login_failed: {log_err}")

        return jsonify({"error": "Invalid username or password"}), 401

    # Login successful
    token = generate_jwt_token(user)
    logger.info(f"LOGIN_SUCCESS username='{user.username}' ip='{client_ip}'")

    try:
        log_entry = ActivityLog(
            user_id=user.id,
            action="login_success",
            detail=f"User '{user.username}' logged in successfully from ip='{client_ip}'",
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as log_err:
        db.session.rollback()
        logger.error(f"Failed to record ActivityLog for login_success: {log_err}")

    return jsonify({
        "token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": getattr(user, "email", None),
            "is_admin": user.is_admin,
        }
    }), 200


@auth_bp.route("/me", methods=["GET"])
@token_required
def me():
    """Returns current authenticated user details."""
    user = g.current_user
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": getattr(user, "email", None),
        "is_admin": user.is_admin,
    }), 200


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Logout endpoint.
    
    JWT tokens are stateless and verified via signature. The platform does not
    maintain a server-side session table or token blacklist. Clients must
    discard tokens from client-side storage upon logout.
    """
    user = get_authenticated_user_from_request()
    client_ip = get_client_ip()
    if user:
        try:
            log_entry = ActivityLog(
                user_id=user.id,
                action="logout",
                detail=f"User '{user.username}' initiated logout from ip='{client_ip}'",
            )
            db.session.add(log_entry)
            db.session.commit()
        except Exception as log_err:
            db.session.rollback()
            logger.error(f"Failed to record ActivityLog for logout: {log_err}")

    return jsonify({
        "message": "Logged out successfully. Please discard the authentication token on the client.",
        "stateless": True,
    }), 200
