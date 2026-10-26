import logging
import os
from flask import Flask, send_from_directory
from sqlalchemy import text
from flask_migrate import Migrate

from app.config import Config
from app.models import db, User
from app.health import health_bp
from app.auth import auth_bp
from app.resources import resources_bp
from app.metrics import init_observability


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Configure structured logging for stdout / CloudWatch
    log_level = getattr(logging, app.config.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    )

    db.init_app(app)
    Migrate(app, db)

    # Initialize observability: metrics, request timers, structured logging
    init_observability(app)

    # Register API blueprints
    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(resources_bp)

    @app.route("/")
    def home():
        return {
            "application": "Cloud-Native Digital Resource Exchange Platform",
            "status": "running"
        }

    @app.route("/db-test")
    def db_test():
        try:
            result = db.session.execute(text("SELECT 1"))
            value = result.scalar()

            return {
                "database": "connected",
                "result": value
            }

        except Exception as e:
            return {
                "database": "connection_failed",
                "error": str(e)
            }, 500

    @app.route("/model-test")
    def model_test():
        try:
            existing = User.query.filter_by(username="model_test_user").first()
            if existing:
                db.session.delete(existing)
                db.session.commit()

            test_user = User(
                username="model_test_user",
                password_hash="temporary-test-value",
                is_admin=False
            )

            db.session.add(test_user)
            db.session.commit()

            user_count = User.query.count()

            return {
                "model": "User",
                "status": "working",
                "user_count": user_count
            }

        except Exception as e:
            db.session.rollback()

            return {
                "model": "User",
                "status": "failed",
                "error": str(e)
            }, 500

    @app.route("/ui")
    @app.route("/ui/<path:filename>")
    def frontend_ui(filename="index.html"):
        frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
        return send_from_directory(frontend_dir, filename)

    return app