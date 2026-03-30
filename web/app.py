"""
web/app.py — Flask application factory for RepoShield Phase 1.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask
from flask_login import LoginManager
from web.models import db, User
from config import DATABASE_URL, SECRET_KEY


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    app.config["SECRET_KEY"]                     = SECRET_KEY
    app.config["SQLALCHEMY_DATABASE_URI"]        = DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ── Extensions ────────────────────────────────────────────
    db.init_app(app)

    lm = LoginManager()
    lm.login_view          = "auth.login"
    lm.login_message       = "Please sign in to access RepoShield."
    lm.login_message_category = "warning"
    lm.init_app(app)

    @lm.user_loader
    def load_user(uid: str):
        return User.query.get(int(uid))

    # ── Blueprints ────────────────────────────────────────────
    from web.routes.auth      import auth_bp
    from web.routes.dashboard import dashboard_bp
    from web.routes.scans     import scans_bp
    from web.routes.admin     import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(admin_bp)

    return app
