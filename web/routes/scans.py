import os, sys, json, threading
from datetime import datetime, timezone

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_login import login_required, current_user

from web.models import db, Scan
from config import CLONE_BASE_DIR

import zipfile, uuid, shutil

scans_bp = Blueprint("scans", __name__, url_prefix="/scans")

RUNNING = {
    "queued",
    "cloning",
    "static_scan",
    "dep_scan",
    "ai_analysis",
    "dynamic_analysis",
    "scoring",
}


# -----------------------------
# Pipeline
# -----------------------------
def _run_pipeline(app, scan_id: int):
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    sys.path.insert(0, root)

    from intake.repo_cloner import clone_repo
    from static_analysis.static_scanner import scan_repository
    from dependency_analysis.dep_scanner import scan_dependencies
    from ttp_engine.mapper import map_static_findings
    from ai_analysis.ai_analyzer import analyze_top_files
    from scoring_engine.scorer import calculate_score
    from report_generator.report import generate_report
    from dynamic_analysis.dynamic_engine import run_dynamic_analysis

    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        def _status(s):
            # reload to ensure we have latest
            nonlocal scan
            scan = Scan.query.get(scan_id)
            if not scan:
                return False
            scan.status = s
            db.session.commit()
            return True

        try:
            if not _status("cloning"):
                return

            # Handle local uploads (repo_url='local://<path>')
            if scan.repo_url and str(scan.repo_url).startswith("local://"):
                repo_path = scan.repo_url[len("local://") :]
                if not os.path.isdir(repo_path):
                    raise RuntimeError("Uploaded project path not found on disk")
            else:
                repo_path = clone_repo(scan.repo_url)

            if not _status("static_scan"):
                return
            static_findings = scan_repository(repo_path)

            if not _status("dep_scan"):
                return
            dep_findings = scan_dependencies(repo_path)

            static_ttps = map_static_findings(static_findings.get("findings", []))

            if not _status("ai_analysis"):
                return
            ranked_files = static_findings.get("ranked_files", [])
            ai_analysis = {"file_results": [], "correlation": {"coordinated": False}, "ai_score": 0.0}
            ai_ran = False
            if ranked_files:
                ai_analysis = analyze_top_files(ranked_files)
                ai_ran = True

            if not _status("dynamic_analysis"):
                return
            dynamic_output = run_dynamic_analysis(repo_path)
            dynamic_results = dynamic_output.get("results", [])
            dynamic_correlation = dynamic_output.get("correlation")
            dynamic_ai_correlation = dynamic_output.get("ai_correlation")

            dynamic_score = max([r.get("dynamic_score", 0) for r in dynamic_results], default=0)

            if not _status("scoring"):
                return
            risk_score, classification, confidence = calculate_score(
                static_ttps=static_ttps,
                dep_risk_score=dep_findings.get("dep_risk_score", 0),
                ai_score=ai_analysis.get("ai_score", 0.0),
                ai_ran=ai_ran,
                scanned_files=static_findings.get("scanned_files", 0),
                total_findings=static_findings.get("total_findings", 0),
                packages_analysed=dep_findings.get("packages_analysed", 0),
                dynamic_score=dynamic_score,
            )

            report = generate_report(
                repo_url=scan.repo_url,
                static_findings=static_findings,
                static_ttps=static_ttps,
                dep_findings=dep_findings,
                ai_analysis=ai_analysis,
                dynamic_results=dynamic_results,
                dynamic_score=dynamic_score,
                dynamic_correlation=dynamic_correlation,
                dynamic_ai_correlation=dynamic_ai_correlation,
                risk_score=risk_score,
                classification=classification,
                confidence=confidence,
            )

            scan = Scan.query.get(scan_id)
            scan.report_json = json.dumps(report, indent=2)
            scan.status = "complete"
            scan.completed_at = datetime.now(timezone.utc)
        except Exception as e:
            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)
        finally:
            db.session.commit()


# -----------------------------
# Routes
# -----------------------------
@scans_bp.route("/submit", methods=["GET", "POST"]) 
@login_required
def submit():
    if request.method == "POST":
        repo_url = (request.form.get("repo_url") or "").strip()
        repo_file = request.files.get("repo_file")

        # Either a URL or an uploaded ZIP is required
        if not repo_url and (not repo_file or repo_file.filename == ""):
            flash("Provide a repository URL or upload a zipped project.", "danger")
            return redirect(url_for("scans.submit"))

        scan = Scan(user_id=current_user.id, repo_url=repo_url or "", status="queued")
        db.session.add(scan)
        db.session.commit()

        # If an uploaded zip was provided, extract it into a unique folder
        if repo_file and repo_file.filename:
            filename = f"scan_{scan.id}_{uuid.uuid4().hex}.zip"
            os.makedirs(CLONE_BASE_DIR, exist_ok=True)
            zip_path = os.path.join(CLONE_BASE_DIR, filename)
            repo_file.save(zip_path)

            extract_dir = os.path.join(CLONE_BASE_DIR, f"scan_{scan.id}")
            try:
                with zipfile.ZipFile(zip_path, 'r') as z:
                    z.extractall(extract_dir)
                # mark repo_url to point to local path for pipeline
                scan.repo_url = f"local://{extract_dir}"
                db.session.commit()
            except Exception as e:
                scan.status = "failed"
                scan.error_message = f"Failed to extract uploaded archive: {e}"
                db.session.commit()
                flash("Uploaded archive could not be processed.", "danger")
                return redirect(url_for("scans.detail", scan_id=scan.id))

        from web.app import create_app
        try:
            threading.Thread(target=_run_pipeline, args=(create_app(), scan.id), daemon=True).start()
        except Exception as e:
            scan.status = "failed"
            scan.error_message = f"Pipeline start failed: {e}"
            db.session.commit()
            flash("Failed to start scan pipeline.", "danger")
            return redirect(url_for("scans.detail", scan_id=scan.id))

        return redirect(url_for("scans.detail", scan_id=scan.id))

    return render_template("scans/submit.html")


@scans_bp.route("/<int:scan_id>")
@login_required
def detail(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    report = json.loads(scan.report_json) if scan.report_json else None
    return render_template("scans/detail.html", scan=scan, report=report, RUNNING=RUNNING)


@scans_bp.route("/<int:scan_id>/status")
@login_required
def status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify({"status": scan.status})


@scans_bp.route("/history")
@login_required
def history():
    page = request.args.get("page", 1, type=int)
    per_page = 10
    query = Scan.query.order_by(Scan.created_at.desc())
    if not current_user.is_admin:
        query = query.filter_by(user_id=current_user.id)
    scans = query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template("scans/history.html", scans=scans)


@scans_bp.route("/<int:scan_id>/download")
@login_required
def download(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if not scan.report_json:
        flash("No report available for this scan.", "warning")
        return redirect(url_for("scans.detail", scan_id=scan.id))
    return Response(scan.report_json, mimetype="application/json", headers={"Content-Disposition": f"attachment; filename=scan_{scan.id}.json"})


@scans_bp.route("/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id and not current_user.is_admin:
        flash("Not authorised to delete this scan.", "danger")
        return redirect(url_for("scans.detail", scan_id=scan.id))

    # mark as deleted so pipeline can stop
    try:
        scan.status = "deleted"
        db.session.commit()
    except Exception:
        db.session.rollback()

    # try to remove any extracted or cloned dir
    try:
        # if repo_url points to local path, remove it
        if scan.repo_url and str(scan.repo_url).startswith("local://"):
            path = scan.repo_url[len("local://") :]
            if os.path.exists(path):
                shutil.rmtree(path, ignore_errors=True)
        else:
            # try remove any matching folder by scan id
            candidate = os.path.join(CLONE_BASE_DIR, f"scan_{scan.id}")
            if os.path.exists(candidate):
                shutil.rmtree(candidate, ignore_errors=True)
    except Exception:
        pass

    try:
        db.session.delete(scan)
        db.session.commit()
        flash("Scan deleted.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Could not delete scan: {e}", "danger")

    return redirect(url_for("scans.history"))
