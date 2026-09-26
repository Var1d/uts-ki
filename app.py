from io import BytesIO
from pathlib import Path
from flask import Flask, render_template, request, send_file
from crypto_utils import (
    encrypt_bytes,
    decrypt_bytes,
    encrypt_text,
    decrypt_text,
)

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    error = None
    result_text = None
    result_action = None
    text_input = ""

    if request.method == "POST":
        action = request.form.get("action")

        # Fitur enkripsi dan dekripsi teks
        if action in ("encrypt_text", "decrypt_text"):
            password = request.form.get("password", "")
            text_input = request.form.get("text_input", "")

            if not password:
                error = "Password tidak boleh kosong."
            elif text_input == "":
                error = "Masukkan teks terlebih dahulu."
            else:
                try:
                    if action == "encrypt_text":
                        result_text = encrypt_text(text_input, password)
                    else:
                        result_text = decrypt_text(text_input, password)

                    result_action = action

                except (ValueError, UnicodeDecodeError):
                    error = (
                        "Gagal memproses teks. "
                        "Periksa password dan ciphertext."
                    )

        # Fitur enkripsi dan dekripsi file
        elif action in ("encrypt_file", "decrypt_file"):
            password = request.form.get("file_password", "")
            uploaded_file = request.files.get("file")

            if not password:
                error = "Password tidak boleh kosong."
            elif not uploaded_file or uploaded_file.filename == "":
                error = "Pilih file terlebih dahulu."
            else:
                try:
                    file_data = uploaded_file.read()
                    original_name = Path(uploaded_file.filename).name

                    if action == "encrypt_file":
                        encrypted_text = encrypt_bytes(
                            file_data,
                            password,
                        )
                        output_data = encrypted_text.encode("utf-8")
                        output_name = original_name + ".utsk"

                    else:
                        encrypted_text = file_data.decode("utf-8")
                        output_data = decrypt_bytes(
                            encrypted_text,
                            password,
                        )

                        if original_name.endswith(".utsk"):
                            output_name = original_name[:-5]
                        else:
                            output_name = "hasil_dekripsi.bin"

                    return send_file(
                        BytesIO(output_data),
                        as_attachment=True,
                        download_name=output_name,
                        mimetype="application/octet-stream",
                    )

                except (ValueError, UnicodeDecodeError):
                    error = (
                        "Gagal memproses file. "
                        "Periksa password dan file yang dipilih."
                    )

    return render_template(
        "index.html",
        error=error,
        result_text=result_text,
        result_action=result_action,
        text_input=text_input,
    )


if __name__ == "__main__":
    app.run(debug=True)