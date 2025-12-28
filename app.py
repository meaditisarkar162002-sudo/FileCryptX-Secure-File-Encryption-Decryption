from flask import Flask, render_template, request, send_file, abort
from werkzeug.utils import secure_filename
from pathlib import Path
from crypto_utils import encrypt_file, decrypt_file
from cryptography.exceptions import InvalidTag

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
OUTPUT_FOLDER = BASE_DIR / "output"

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    file = request.files["file"]
    password = request.form["password"]

    filename = secure_filename(file.filename)
    input_path = UPLOAD_FOLDER / filename
    output_path = OUTPUT_FOLDER / (filename + ".enc")

    file.save(input_path)
    encrypt_file(input_path, output_path, password)

    return send_file(output_path, as_attachment=True)

@app.route("/decrypt", methods=["POST"])
def decrypt():
    file = request.files["file"]
    password = request.form["password"]

    filename = secure_filename(file.filename)
    input_path = UPLOAD_FOLDER / filename
    output_path = OUTPUT_FOLDER / ("decrypted_" + filename.replace(".enc", ""))

    file.save(input_path)

    try:
        decrypt_file(input_path, output_path, password)
    except InvalidTag:
        return (
            "❌ Decryption failed: Wrong password or file was modified.",
            400,
        )

    return send_file(output_path, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
