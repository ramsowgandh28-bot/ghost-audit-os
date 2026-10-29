"""Flask Application for Ghost Data Still Exists Deletion-Audit Platform.

Provides RESTful API endpoints and serves the enterprise single-page application.
"""

import json
import os
import sys
import tempfile
import time
from flask import (
    Flask,
    jsonify,
    request,
    render_template,
    send_file,
    Response,
    abort,
)

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from audit_service import (
    audit_manager,
    REPO_ROOT,
    DATASET_DIR,
    CODE_DIR,
    mask_email,
)

app = Flask(
    __name__,
    template_folder=os.path.join(current_dir, "templates"),
    static_folder=os.path.join(current_dir, "static"),
)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max upload


@app.after_request
def add_security_headers(response):
    """Add secure HTTP headers."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# ---------------------------------------------------------
# HTML Views & SEO
# ---------------------------------------------------------

@app.route("/")
def index():
    """Render the main single-page application."""
    return render_template("index.html")


@app.route("/robots.txt")
def robots_txt():
    """Serve robots.txt for search engines."""
    return send_file(os.path.join(current_dir, "static", "robots.txt"), mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap_xml():
    """Serve sitemap.xml for search engines."""
    return send_file(os.path.join(current_dir, "static", "sitemap.xml"), mimetype="application/xml")


# ---------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    """System health check and runtime status."""
    status = audit_manager.get_status()
    output_exists = os.path.exists(os.path.join(REPO_ROOT, "output.csv"))
    return jsonify({
        "status": "healthy",
        "engine_state": status.get("status", "IDLE"),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "output_available": output_exists,
        "dataset_dir": os.path.relpath(DATASET_DIR, REPO_ROOT),
        "total_cases_loaded": len(audit_manager.results_cache),
    })


@app.route("/api/datasets/info", methods=["GET"])
def datasets_info():
    """Get metadata about loaded datasets and evidence manifest."""
    manifest = audit_manager.get_evidence_manifest()
    files_available = sum(1 for m in manifest if m["exists"])

    dataset_files = [
        {"name": "deletion_requests.csv", "type": "Scored Input", "cases": 518, "desc": "Official October 2026 evaluation dataset (case_33 to case_550)"},
        {"name": "sample_deletion_requests.csv", "type": "Benchmark Input", "cases": 32, "desc": "Public reference requests for calibration (case_01 to case_32)"},
        {"name": "sample_output.csv", "type": "Ground Truth", "cases": 32, "desc": "Canonical ground-truth answers for public sample cases"},
        {"name": "user_identities.csv", "type": "Identities", "cases": 1500, "desc": "Current user identity snapshots"},
        {"name": "user_audit_log.csv", "type": "Audit Trail", "cases": 1824, "desc": "Chronological email, phone, and name changes"},
        {"name": "system_activity.csv", "type": "Activity", "cases": 3210, "desc": "Operational telemetry across 8 microservices"},
        {"name": "deletion_rules.csv", "type": "Policy Rules", "cases": 14, "desc": "Prescribed treatment across all 14 data categories"},
        {"name": "evidence_files.csv", "type": "Evidence Manifest", "cases": 94, "desc": "Manifest of all 94 participant-facing evidence artifacts"},
    ]

    return jsonify({
        "success": True,
        "evidence_total": len(manifest),
        "evidence_available": files_available,
        "evidence_manifest": manifest,
        "datasets": dataset_files,
    })


@app.route("/api/validate/input", methods=["POST"])
def validate_input():
    """Validate an input CSV file schema."""
    if "file" in request.files:
        uploaded_file = request.files["file"]
        if uploaded_file.filename == "":
            return jsonify({"success": False, "error": "No file selected"}), 400

        # Save to temp file safely
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, f"validate_{int(time.time())}_{os.path.basename(uploaded_file.filename)}")
        uploaded_file.save(temp_path)
        target_path = temp_path
    else:
        data = request.get_json(silent=True) or {}
        dataset_type = data.get("dataset_type", "default")
        if dataset_type == "sample":
            target_path = os.path.join(DATASET_DIR, "sample_deletion_requests.csv")
        else:
            target_path = os.path.join(DATASET_DIR, "deletion_requests.csv")

    try:
        from loaders import load_deletion_requests
        requests = load_deletion_requests(target_path)
        return jsonify({
            "success": True,
            "filename": os.path.basename(target_path),
            "total_rows": len(requests),
            "first_case_id": requests[0].case_id if requests else None,
            "last_case_id": requests[-1].case_id if requests else None,
            "message": f"Successfully validated schema for {len(requests)} deletion requests.",
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "message": f"Input validation failed: {e}",
        }), 400


@app.route("/api/audit/start", methods=["POST"])
def audit_start():
    """Start an audit job in the background."""
    custom_filepath = None

    if "file" in request.files:
        uploaded_file = request.files["file"]
        if uploaded_file.filename != "":
            temp_dir = tempfile.gettempdir()
            custom_filepath = os.path.join(temp_dir, f"custom_run_{int(time.time())}.csv")
            uploaded_file.save(custom_filepath)
            dataset_type = "uploaded"
        else:
            dataset_type = "default"
    else:
        payload = request.get_json(silent=True) or {}
        dataset_type = payload.get("dataset_type", "default")

    res = audit_manager.start_audit(dataset_type=dataset_type, custom_filepath=custom_filepath)
    if not res.get("success"):
        return jsonify(res), 400
    return jsonify(res)


@app.route("/api/audit/status", methods=["GET"])
def audit_status():
    """Poll audit job execution status."""
    return jsonify(audit_manager.get_status())


@app.route("/api/audit/results", methods=["GET"])
def audit_results():
    """Query and paginate audit results."""
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 25, type=int)
    status_filter = request.args.get("status", "ALL")
    search = request.args.get("search", "")
    sort_by = request.args.get("sort_by", "case_id")
    sort_dir = request.args.get("sort_dir", "asc")
    mask_pii = request.args.get("mask_pii", "true").lower() in ("true", "1", "yes")

    results = audit_manager.get_results(
        page=page,
        page_size=page_size,
        status_filter=status_filter,
        search=search,
        sort_by=sort_by,
        sort_dir=sort_dir,
        mask_pii=mask_pii,
    )
    return jsonify(results)


@app.route("/api/audit/results/<case_id>", methods=["GET"])
def audit_case_detail(case_id: str):
    """Retrieve full detail for a single audited case."""
    mask_pii = request.args.get("mask_pii", "true").lower() in ("true", "1", "yes")
    detail = audit_manager.get_case_detail(case_id, mask_pii=mask_pii)
    if not detail:
        return jsonify({"success": False, "error": f"Case not found: {case_id}"}), 404
    return jsonify({"success": True, "case": detail})


@app.route("/api/validate/output", methods=["POST"])
def validate_output():
    """Run the 12-point structural contract validator on output.csv."""
    target_path = os.path.join(REPO_ROOT, "output.csv")
    if not os.path.exists(target_path):
        target_path = os.path.join(os.path.dirname(REPO_ROOT), "output.csv")

    report = audit_manager.validate_output_file(target_path)
    return jsonify(report)


@app.route("/api/benchmark/run", methods=["POST"])
def benchmark_run():
    """Execute public benchmark evaluation."""
    res = audit_manager.run_public_benchmark()
    return jsonify(res)


@app.route("/api/download/output.csv", methods=["GET"])
def download_output_csv():
    """Download the validated output.csv file."""
    candidate_paths = [
        os.path.join(REPO_ROOT, "output.csv"),
        os.path.join(os.path.dirname(REPO_ROOT), "output.csv"),
    ]
    target_path = None
    for p in candidate_paths:
        if os.path.exists(p):
            target_path = p
            break

    if not target_path:
        abort(404, description="output.csv has not been generated yet.")

    return send_file(
        target_path,
        mimetype="text/csv",
        as_attachment=True,
        download_name="output.csv",
    )


@app.route("/api/download/report/<report_type>", methods=["GET"])
def download_report(report_type: str):
    """Download system evaluation or usage reports."""
    report_type = report_type.lower()
    if report_type == "evaluation":
        eval_path = os.path.join(CODE_DIR, "evaluation", "evaluation_report.md")
        if os.path.exists(eval_path):
            return send_file(eval_path, mimetype="text/markdown", as_attachment=True, download_name="evaluation_report.md")
    elif report_type == "usage":
        usage_path = os.path.join(CODE_DIR, "evaluation", "usage_report.md")
        if os.path.exists(usage_path):
            return send_file(usage_path, mimetype="text/markdown", as_attachment=True, download_name="usage_report.md")
    elif report_type == "validation":
        target_path = os.path.join(REPO_ROOT, "output.csv")
        report = audit_manager.validate_output_file(target_path)
        content = json.dumps(report, indent=2)
        return Response(content, mimetype="application/json", headers={"Content-Disposition": "attachment; filename=contract_validation_report.json"})

    abort(404, description="Requested report not found.")


@app.route("/api/download/artifact/<artifact_name>", methods=["GET"])
def download_artifact(artifact_name: str):
    """Download genuine, verified submission packages."""
    allowed_artifacts = {
        "code.zip": ["code.zip"],
        "agent-trace.zip": ["agent-trace.zip"],
        "log.txt": ["log.txt"],
    }

    if artifact_name not in allowed_artifacts:
        abort(400, description="Invalid artifact requested.")

    candidate_dirs = [REPO_ROOT, os.path.dirname(REPO_ROOT)]
    target_path = None
    for d in candidate_dirs:
        p = os.path.join(d, artifact_name)
        if os.path.exists(p):
            target_path = p
            break

    if not target_path:
        abort(404, description=f"Artifact {artifact_name} does not exist in workspace.")

    mimetypes = {
        "code.zip": "application/zip",
        "agent-trace.zip": "application/zip",
        "log.txt": "text/plain",
    }
    return send_file(
        target_path,
        mimetype=mimetypes.get(artifact_name, "application/octet-stream"),
        as_attachment=True,
        download_name=artifact_name,
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting Ghost Data Still Exists Web App on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
