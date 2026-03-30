"""
web/routes/dashboard.py — User dashboard.
"""

from flask import Blueprint, render_template
from flask_login import login_required, current_user
from web.models import Scan

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
@login_required
def home():
    recent = (
        Scan.query
        .filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(8)
        .all()
    )
    stats = {
        "total":    Scan.query.filter_by(user_id=current_user.id).count(),
        "complete": Scan.query.filter_by(user_id=current_user.id, status="complete").count(),
        "critical": Scan.query.filter_by(user_id=current_user.id, classification="Critical").count(),
        "failed":   Scan.query.filter_by(user_id=current_user.id, status="failed").count(),
    }
    return render_template("dashboard/home.html", scans=recent, stats=stats)
