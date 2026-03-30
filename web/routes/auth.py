"""
web/routes/auth.py — Register, login, logout.
"""

from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from web.models import db, User

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")

        # ── Validation ────────────────────────────────────────
        errors = []
        if len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if "@" not in email or "." not in email:
            errors.append("Enter a valid email address.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if User.query.filter_by(username=username).first():
            errors.append("That username is already taken.")
        if User.query.filter_by(email=email).first():
            errors.append("That email is already registered.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template(
                "auth/register.html", username=username, email=email
            )

        # ── Create user ───────────────────────────────────────
        is_first_user = User.query.count() == 0
        user = User(
            username=username,
            email=email,
            role="admin"  if is_first_user else "user",
            status="active" if is_first_user else "pending",
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        if is_first_user:
            flash(
                "Admin account created. Welcome to RepoShield!", "success"
            )
            login_user(user)
            return redirect(url_for("dashboard.home"))
        else:
            flash(
                "Account created. Please wait for an admin to approve you.",
                "info"
            )
            return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password   = request.form.get("password", "")
        remember   = bool(request.form.get("remember"))

        user = User.query.filter(
            (User.username == identifier) |
            (User.email    == identifier.lower())
        ).first()

        if not user or not user.check_password(password):
            flash("Incorrect username/email or password.", "danger")
            return render_template("auth/login.html", identifier=identifier)

        if user.status == "pending":
            flash("Your account is pending admin approval.", "warning")
            return render_template("auth/login.html")

        if user.status == "disabled":
            flash("Your account has been disabled. Contact the admin.", "danger")
            return render_template("auth/login.html")

        user.last_login = datetime.now(timezone.utc)
        db.session.commit()
        login_user(user, remember=remember)

        next_page = request.args.get("next")
        return redirect(next_page or url_for("dashboard.home"))

    return render_template("auth/login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
