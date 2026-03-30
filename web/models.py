"""
web/models.py — Database models for RepoShield.
"""

from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64),  unique=True, nullable=False, index=True)
    email         = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(20),  nullable=False, default="user")
    status        = db.Column(db.String(20),  nullable=False, default="pending")
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login    = db.Column(db.DateTime, nullable=True)

    scans = db.relationship(
        "Scan", backref="owner",
        lazy="dynamic", cascade="all, delete-orphan"
    )

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_active(self) -> bool:
        return self.status == "active"

    @is_active.setter
    def is_active(self, value: bool):
        self.status = "active" if value else "disabled"

    def get_id(self) -> str:
        return str(self.id)

    def __repr__(self):
        return f"<User {self.username} [{self.status}|{self.role}]>"


class Scan(db.Model):
    __tablename__ = "scans"

    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    repo_url      = db.Column(db.String(512), nullable=False)

    # queued → cloning → static_scan → dep_scan → ai_analysis → scoring → complete | failed
    status        = db.Column(db.String(30), nullable=False, default="queued")
    error_message = db.Column(db.Text, nullable=True)

    # Result summary columns
    risk_score       = db.Column(db.Integer, nullable=True)
    classification   = db.Column(db.String(20), nullable=True)
    confidence_pct   = db.Column(db.Integer, nullable=True)
    static_findings  = db.Column(db.Integer, nullable=True)
    files_scanned    = db.Column(db.Integer, nullable=True)
    total_cves       = db.Column(db.Integer, nullable=True)
    mitre_count      = db.Column(db.Integer, nullable=True)
    ai_files         = db.Column(db.Integer, nullable=True)  # files sent to AI

    report_json   = db.Column(db.Text, nullable=True)
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at  = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<Scan #{self.id} [{self.status}] {self.repo_url[:40]}>"
