from flask import Flask, request, jsonify
from flask_cors import CORS
from analyzer.analyzer import analyze_apk
import os

app = Flask(__name__)
CORS(app)  # allow frontend to connect

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

MAX_SIZE_MB = 8  # 🔴 IMPORTANT: demo size limit (prevents SIGKILL)

@app.route("/scan", methods=["POST"])
def scan_apk():
    try:
        # 1️⃣ Check file exists
        if "apk" not in request.files:
            return jsonify({"error": "APK not found"}), 400

        # 2️⃣ Check file size (VERY IMPORTANT)
        if request.content_length is None:
            return jsonify({"error": "Invalid upload"}), 400

        if request.content_length > MAX_SIZE_MB * 1024 * 1024:
            return jsonify({
                "error": f"APK too large. Max allowed size is {MAX_SIZE_MB} MB for demo."
            }), 413

        file = request.files["apk"]

        # 3️⃣ Validate filename
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        if not file.filename.endswith(".apk"):
            return jsonify({"error": "Invalid file type"}), 400

        # 4️⃣ Save APK temporarily
        path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(path)

        # 5️⃣ Analyze APK (lightweight)
        result = analyze_apk(path)

        # 6️⃣ Delete APK after scan (security)
        os.remove(path)

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/", methods=["GET"])
def home():
    return "SBI Backend Running"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
