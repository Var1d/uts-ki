import os
from pathlib import Path
from PIL import Image
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto_utils import derive_key
from io import BytesIO


INPUT_IMAGE = Path("data_uji/gambar.png")
OUTPUT_DIR = Path("hasil_visualisasi")
PASSWORD = "PasswordVisualisasi123!"


def encrypt_ecb_image_data(data, key):
    """Enkripsi data piksel menggunakan AES-ECB untuk visualisasi."""

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
    )

    encryptor = cipher.encryptor()
    encrypted_data = (
        encryptor.update(padded_data)
        + encryptor.finalize()
    )

    # Samakan panjang dengan data piksel asli untuk visualisasi.
    return encrypted_data[:len(data)]


def encrypt_gcm_image_data(data, key):
    """Enkripsi data piksel menggunakan AES-GCM."""

    nonce = os.urandom(12)
    encrypted_data = AESGCM(key).encrypt(nonce, data, None)

    # Bagian akhir berisi authentication tag.
    # Untuk visualisasi, ambil bagian ciphertext saja.
    return encrypted_data[:len(data)]


def save_as_image(data, size, output_path):
    """Ubah byte hasil enkripsi menjadi gambar RGB."""

    image = Image.frombytes("RGB", size, data)
    image.save(output_path)

def image_to_bytes(image):
    """Mengubah objek gambar menjadi data PNG di memori."""
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def visualize_image_bytes(image_data, password):
    """
    Membuat visualisasi gambar asli, AES-ECB, dan AES-GCM.
    Hasil dikembalikan sebagai data PNG, bukan disimpan ke disk.
    """

    # Baca gambar yang dikirim dari aplikasi web.
    image = Image.open(BytesIO(image_data)).convert("RGB")

    width, height = image.size
    original_data = image.tobytes()

    # Buat salt acak dan turunkan kunci dari password.
    salt = os.urandom(16)
    key = derive_key(password, salt)

    # Enkripsi data piksel dengan ECB dan GCM.
    ecb_data = encrypt_ecb_image_data(original_data, key)
    gcm_data = encrypt_gcm_image_data(original_data, key)

    # Ubah kembali byte menjadi gambar RGB.
    ecb_image = Image.frombytes(
        "RGB",
        (width, height),
        ecb_data,
    )

    gcm_image = Image.frombytes(
        "RGB",
        (width, height),
        gcm_data,
    )

    # Kembalikan gambar sebagai data PNG.
    return (
        image_to_bytes(image),
        image_to_bytes(ecb_image),
        image_to_bytes(gcm_image),
    )

def main():
    if not INPUT_IMAGE.exists():
        raise FileNotFoundError(
            f"Gambar tidak ditemukan: {INPUT_IMAGE}"
        )

    OUTPUT_DIR.mkdir(exist_ok=True)

    # Baca gambar dan ubah ke RGB agar format piksel konsisten.
    with Image.open(INPUT_IMAGE) as source:
        image = source.convert("RGB")

    width, height = image.size
    original_data = image.tobytes()

    # Gunakan salt yang sama agar kunci hasil derivasi sama.
    salt = os.urandom(16)
    key = derive_key(PASSWORD, salt)

    # Enkripsi data piksel dengan kedua metode.
    ecb_data = encrypt_ecb_image_data(original_data, key)
    gcm_data = encrypt_gcm_image_data(original_data, key)

    # Simpan gambar hasil visualisasi.
    image.save(OUTPUT_DIR / "gambar_asli.png")

    save_as_image(
        ecb_data,
        (width, height),
        OUTPUT_DIR / "gambar_aes_ecb.png",
    )

    save_as_image(
        gcm_data,
        (width, height),
        OUTPUT_DIR / "gambar_aes_gcm.png",
    )

    print("Visualisasi selesai.")
    print(f"Ukuran gambar: {width} x {height}")
    print(f"Folder hasil: {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()