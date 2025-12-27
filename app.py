from flask import Flask, request, jsonify
from flask_cors import CORS
from analyzer.analyzer import analyze_apk
import os

app = Flask(__name__)
CORS(app)

# ===============================
# CONFIG
# ===============================
UPLOAD_FOLDER = "uploads"
MAX_SIZE_MB = 8  # 🔴 SAFE LIMIT (avoids SIGKILL on Render)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ===============================
# ROUTES
# ===============================
@app.route("/", methods=["GET"])
def home():
    return "✅ SBI APK Scanner Backend Running"

@app.route("/scan", methods=["POST"])
def scan_apk():
    try:
        # 1️⃣ File existence
        if "apk" not in request.files:
            return jsonify({"error": "APK file not found"}), 400

        # 2️⃣ File size protection
        if request.content_length is None:
            return jsonify({"error": "Invalid upload"}), 400

        if request.content_length > MAX_SIZE_MB * 1024 * 1024:
            return jsonify({
                "error": f"APK too large. Max allowed {MAX_SIZE_MB} MB (demo limit)"
            }), 413

        file = request.files["apk"]

        # 3️⃣ Validate filename
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        if not file.filename.lower().endswith(".apk"):
            return jsonify({"error": "Only APK files allowed"}), 400

        # 4️⃣ Save temporarily
        apk_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(apk_path)

        # 5️⃣ Static APK analysis (FAST)
        result = analyze_apk(apk_path)

        # 6️⃣ Cleanup
        os.remove(apk_path)

        return jsonify(result)

    except Exception as e:
    print("🔥 APK ANALYSIS ERROR:", e)
    return jsonify({
        "error": "APK analysis failed",
        "details": str(e)
    }), 500



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
