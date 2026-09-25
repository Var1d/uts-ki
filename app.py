from io import BytesIO
from pathlib import Path
from flask import Flask, render_template, request, send_file
from crypto_utils import encrypt_bytes, decrypt_bytes

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    error = None

    if request.method == "POST":
        action = request.form.get("action")
        password = request.form.get("password")
        uploaded_file = request.files.get("file")

        if not password:
            error = "Password tidak boleh kosong."
        elif not uploaded_file or uploaded_file.filename == "":
            error = "Pilih file terlebih dahulu."
        else:
            try:
                file_data = uploaded_file.read()
                original_name = Path(uploaded_file.filename).name

                if action == "encrypt":
                    encrypted_text = encrypt_bytes(file_data, password)
                    output_data = encrypted_text.encode("utf-8")
                    output_name = original_name + ".utsk"

                elif action == "decrypt":
                    encrypted_text = file_data.decode("utf-8")
                    output_data = decrypt_bytes(encrypted_text, password)

                    if original_name.endswith(".utsk"):
                        output_name = original_name[:-5]
                    else:
                        output_name = "hasil_dekripsi.bin"

                else:
                    error = "Pilihan tindakan tidak valid."

                if not error:
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

    return render_template("index.html", error=error)


if __name__ == "__main__":
    app.run(debug=True)