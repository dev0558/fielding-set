import os
import hashlib
from flask import Flask, render_template, send_from_directory

app = Flask(__name__)
app.secret_key = "ir_p0rt4l_s3cr3t_k3y_2024"

ARTIFACTS_DIR = "/app/artifacts"


def get_file_info(filename):
    filepath = os.path.join(ARTIFACTS_DIR, filename)
    if not os.path.exists(filepath):
        return {"name": filename, "size": "N/A", "sha256": "N/A"}
    size = os.path.getsize(filepath)
    with open(filepath, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()
    if size > 1024 * 1024:
        size_str = f"{size / (1024*1024):.2f} MB"
    elif size > 1024:
        size_str = f"{size / 1024:.1f} KB"
    else:
        size_str = f"{size} bytes"
    return {"name": filename, "size": size_str, "sha256": sha256}


@app.route("/")
def index():
    artifacts = [
        get_file_info("incident_dump.bin"),
        get_file_info("vss_snapshot.dd"),
    ]
    return render_template("index.html", artifacts=artifacts)


@app.route("/download/<filename>")
def download(filename):
    allowed = {"incident_dump.bin", "vss_snapshot.dd"}
    if filename not in allowed:
        return "File not found", 404
    return send_from_directory(ARTIFACTS_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
