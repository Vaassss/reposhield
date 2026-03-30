"""
web/routes/admin.py — Admin panel.
"""

from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from web.models import db, User, Scan

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


@admin_bp.route("/")
@login_required
@admin_required
def index():
    pending      = (
        User.query.filter_by(status="pending")
        .order_by(User.created_at.asc()).all()
    )
    stats = {
        "total_users":    User.query.count(),
        "pending":        User.query.filter_by(status="pending").count(),
        "active":         User.query.filter_by(status="active").count(),
        "total_scans":    Scan.query.count(),
        "critical_scans": Scan.query.filter_by(classification="Critical").count(),
        "running":        Scan.query.filter(
            Scan.status.notin_(["complete", "failed"])
        ).count(),
    }
    recent_scans = (
        Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    )
    return render_template(
        "admin/index.html",
        pending=pending, stats=stats, recent_scans=recent_scans
    )


@admin_bp.route("/users")
@login_required
@admin_required
def users():
    page  = request.args.get("page", 1, type=int)
    users = (
        User.query.order_by(User.created_at.desc())
        .paginate(page=page, per_page=20, error_out=False)
    )
    return render_template("admin/users.html", users=users)


@admin_bp.route("/users/<int:uid>/approve", methods=["POST"])
@login_required
@admin_required
def approve(uid: int):
    user = User.query.get_or_404(uid)
    user.status = "active"
    db.session.commit()
    flash(f"'{user.username}' approved — they can now log in and submit scans.", "success")
    return redirect(request.referrer or url_for("admin.index"))


@admin_bp.route("/users/<int:uid>/toggle_status", methods=["POST"])
@login_required
@admin_required
def toggle_status(uid: int):
    user = User.query.get_or_404(uid)
    if user.id == current_user.id:
        flash("You cannot change your own status.", "danger")
        return redirect(url_for("admin.users"))
    user.status = "disabled" if user.status == "active" else "active"
    db.session.commit()
    flash(f"'{user.username}' is now {user.status}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:uid>/toggle_role", methods=["POST"])
@login_required
@admin_required
def toggle_role(uid: int):
    user = User.query.get_or_404(uid)
    if user.id == current_user.id:
        flash("You cannot change your own role.", "danger")
        return redirect(url_for("admin.users"))
    user.role = "admin" if user.role == "user" else "user"
    db.session.commit()
    flash(f"'{user.username}' is now a {user.role}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:uid>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(uid: int):
    user = User.query.get_or_404(uid)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin.users"))
    db.session.delete(user)
    db.session.commit()
    flash(f"User '{user.username}' and all their scans deleted.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/scans")
@login_required
@admin_required
def all_scans():
    page       = request.args.get("page", 1, type=int)
    uid_filter = request.args.get("user_id", type=int)
    q          = Scan.query
    if uid_filter:
        q = q.filter_by(user_id=uid_filter)
    scans     = q.order_by(Scan.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    all_users = User.query.order_by(User.username).all()
    return render_template(
        "admin/scans.html",
        scans=scans, all_users=all_users, uid_filter=uid_filter
    )
