from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import hashlib
import hmac
import os
import struct
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = os.path.dirname(os.path.abspath(__file__))
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

MAGIC = b"RC4S"
VERSION = 0x01


def rc4_ksa(key: bytes):
    S = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_prga(S, data: bytes):
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(byte ^ K)
    return bytes(out)


def rc4(key: bytes, data: bytes):
    return rc4_prga(rc4_ksa(key), data)


def derive_key(password: str, salt: bytes):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, dklen=32)


def mac(key: bytes, data: bytes):
    return hmac.new(key, data, hashlib.sha256).digest()


def encrypt_data(data: bytes, password: str):
    salt = os.urandom(16)
    master = derive_key(password, salt)
    rc4_key = hashlib.sha256(master + b"RC4").digest()
    mac_key = hashlib.sha256(master + b"MAC").digest()
    cipher = rc4(rc4_key, data)
    tag = mac(mac_key, cipher)
    return MAGIC + struct.pack("B", VERSION) + salt + tag + cipher


def decrypt_data(data: bytes, password: str):
    if len(data) < 49:
        raise ValueError("Invalid file")

    magic = data[:4]
    version = data[4]
    salt = data[5:21]
    tag = data[21:53]
    cipher = data[53:]

    if magic != MAGIC:
        raise ValueError("Not RC4 file")
    if version != VERSION:
        raise ValueError("Version error")

    master = derive_key(password, salt)
    rc4_key = hashlib.sha256(master + b"RC4").digest()
    mac_key = hashlib.sha256(master + b"MAC").digest()

    check = mac(mac_key, cipher)

    if not hmac.compare_digest(tag, check):
        raise ValueError("Wrong password or file corrupted")

    return rc4(rc4_key, cipher)


@app.route('/')
def home():
    return jsonify({
        "status": "running",
        "message": "RC4 Encryption API is active",
        "endpoints": ["/api/process", "/api/download/<filename>", "/api/health"]
    })


@app.route('/api/process', methods=['POST'])
def process():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400

    file = request.files['file']
    password = request.form.get('password', '')
    op = request.form.get('type', '').lower()
    out_name = request.form.get('output_filename', '').strip()

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    data = file.read()
    name = secure_filename(file.filename)

    filename = secure_filename(out_name) if out_name else (
        name + ".enc" if op == "encrypt" else name.replace(".enc", "")
    )

    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if op == "encrypt":
        result = encrypt_data(data, password)
        with open(path, "wb") as f:
            f.write(result)

        return jsonify({
            "success": True,
            "filename": filename,
            "size": len(result),
            "operation": "encrypt"
        })

    elif op == "decrypt":
        try:
            result = decrypt_data(data, password)
        except Exception as e:
            return jsonify({"error": str(e)}), 400

        with open(path, "wb") as f:
            f.write(result)

        return jsonify({
            "success": True,
            "filename": filename,
            "size": len(result),
            "operation": "decrypt"
        })

    return jsonify({"error": "Invalid operation"}), 400


@app.route('/api/download/<filename>')
def download(filename):
    filename = secure_filename(filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not os.path.exists(path):
        return jsonify({"error": "Not found"}), 404

    return send_file(path, as_attachment=True)


@app.route('/api/health')
def health():
    return jsonify({"status": "ok", "algo": "RC4"})


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)