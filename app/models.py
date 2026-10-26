from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates


db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    resources = db.relationship(
        "Resource",
        backref="uploader",
        lazy=True
    )

    activity_logs = db.relationship(
        "ActivityLog",
        backref="user",
        lazy=True
    )

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "is_admin": self.is_admin,
        }


class Resource(db.Model):
    __tablename__ = "resources"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    s3_key = db.Column(db.String(300), nullable=False)
    uploaded_by = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )
    # Explicit lifecycle status: pending, approved, rejected
    status = db.Column(db.String(20), default="pending", nullable=False, index=True)
    approved = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )

    __table_args__ = (
        db.CheckConstraint("status IN ('pending', 'approved', 'rejected')", name="ck_resources_status"),
    )

    def __init__(self, **kwargs):
        # Synchronize status and approved if only one is explicitly specified
        if "status" in kwargs and "approved" not in kwargs:
            kwargs["approved"] = (kwargs["status"] == "approved")
        elif "approved" in kwargs and "status" not in kwargs:
            kwargs["status"] = "approved" if kwargs["approved"] else "pending"
        elif "status" in kwargs and "approved" in kwargs:
            # status is authoritative
            kwargs["approved"] = (kwargs["status"] == "approved")
        else:
            kwargs.setdefault("status", "pending")
            kwargs.setdefault("approved", False)
        super().__init__(**kwargs)

    @validates("status")
    def _validate_status(self, key, value):
        if value not in ("pending", "approved", "rejected"):
            raise ValueError(f"Invalid status '{value}'. Allowed values: pending, approved, rejected")
        if not getattr(self, "_in_sync", False):
            try:
                self._in_sync = True
                self.approved = (value == "approved")
            finally:
                self._in_sync = False
        return value

    @validates("approved")
    def _validate_approved(self, key, value):
        if not getattr(self, "_in_sync", False):
            try:
                self._in_sync = True
                if value is True:
                    self.status = "approved"
                elif value is False and getattr(self, "status", None) == "approved":
                    self.status = "pending"
            finally:
                self._in_sync = False
        return value


class ActivityLog(db.Model):
    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )
    action = db.Column(db.String(100), nullable=False)
    detail = db.Column(db.Text)
    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )