from flask import Flask, request, jsonify
from flask_cors import CORS
from analyzer.analyzer import analyze_apk
import os

app = Flask(__name__)
CORS(app)  # 🔴 VERY IMPORTANT (frontend connect)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/scan", methods=["POST"])
def scan_apk():
    try:
        if "apk" not in request.files:
            return jsonify({"error": "APK not found"}), 400

        file = request.files["apk"]

        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        if not file.filename.endswith(".apk"):
            return jsonify({"error": "Invalid file type"}), 400

        path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(path)

        result = analyze_apk(path)

        os.remove(path)  # security cleanup

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/", methods=["GET"])
def home():
    return "SBI Backend Running"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
