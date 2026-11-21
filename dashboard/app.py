"""Flask dashboard — visualizes scan results from results dir."""

import json
from pathlib import Path
from flask import Flask, render_template, jsonify, request
from werkzeug.utils import secure_filename


def run_dashboard(host="127.0.0.1", port=5000, results_dir=Path("./results")):
    app = Flask(__name__, template_folder="templates")
    results_dir = Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    def list_results():
        out = []
        for f in sorted(results_dir.glob("*.json"), reverse=True):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                continue
            out.append({
                "file": f.name,
                "target": data.get("target", "?"),
                "candidates": len(data.get("idor_candidates", data.get("attempts", []))),
                "successes": sum(
                    1 for c in data.get("idor_candidates", [])
                    if c.get("bypass_successes")
                ) + len(data.get("successes", [])),
            })
        return out

    @app.route("/")
    def index():
        return render_template("index.html", results=list_results())

    @app.route("/api/result/<filename>")
    def get_result(filename):
        safe_name = secure_filename(filename)
        path = results_dir / safe_name
        if not safe_name.endswith(".json") or not path.is_file():
            return jsonify({"error": "not found"}), 404
        try:
            return jsonify(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            return jsonify({"error": "invalid result file"}), 400

    @app.route("/api/results")
    def api_results():
        return jsonify(list_results())

    @app.route("/api/upload", methods=["POST"])
    def upload():
        if "file" not in request.files:
            return jsonify({"error": "no file"}), 400
        f = request.files["file"]
        filename = secure_filename(f.filename)
        if not filename or not filename.lower().endswith(".json"):
            return jsonify({"error": "must be json"}), 400
        try:
            payload = f.read()
            json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return jsonify({"error": "invalid json"}), 400
        (results_dir / filename).write_bytes(payload)
        return jsonify({"ok": True, "file": filename})

    print(f"[+] dashboard on http://{host}:{port}  (results: {results_dir})")
    app.run(host=host, port=port, debug=False)