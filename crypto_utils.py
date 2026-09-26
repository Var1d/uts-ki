import base64
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import constant_time


# Penanda format ciphertext untuk mengenali algoritma
MAGIC_AES = b"UTSKI1"
MAGIC_CHACHA = b"UTSKC1"

# Konfigurasi
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 600_000


def derive_key(password: str, salt: bytes) -> bytes:
    """Mengubah password menjadi kunci enkripsi 32 byte."""
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(
    data: bytes,
    password: str,
    algorithm: str = "AES-256-GCM",
) -> str:
    """Mengenkripsi data bytes dan mengembalikan ciphertext Base64."""

    salt = __import__("os").urandom(SALT_SIZE)
    nonce = __import__("os").urandom(NONCE_SIZE)

    key = derive_key(password, salt)

    if algorithm == "AES-256-GCM":
        cipher = AESGCM(key)
        magic = MAGIC_AES
    elif algorithm == "ChaCha20-Poly1305":
        cipher = ChaCha20Poly1305(key)
        magic = MAGIC_CHACHA
    else:
        raise ValueError("Algoritma tidak didukung.")

    ciphertext = cipher.encrypt(nonce, data, None)

    payload = magic + salt + nonce + ciphertext

    return base64.b64encode(payload).decode("utf-8")


def decrypt_bytes(encoded_data: str, password: str) -> bytes:
    """Mendekripsi ciphertext Base64 dan mengenali algoritmanya."""

    try:
        payload = base64.b64decode(encoded_data, validate=True)
    except Exception as exc:
        raise ValueError("Format ciphertext Base64 tidak valid.") from exc

    minimum_size = len(MAGIC_AES) + SALT_SIZE + NONCE_SIZE + 16

    if len(payload) < minimum_size:
        raise ValueError("Ciphertext terlalu pendek atau tidak valid.")

    magic = payload[:len(MAGIC_AES)]

    if magic == MAGIC_AES:
        cipher_type = "AES-256-GCM"
    elif magic == MAGIC_CHACHA:
        cipher_type = "ChaCha20-Poly1305"
    else:
        raise ValueError("Format ciphertext tidak dikenali.")

    offset = len(MAGIC_AES)

    salt = payload[offset:offset + SALT_SIZE]
    offset += SALT_SIZE

    nonce = payload[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    ciphertext = payload[offset:]

    key = derive_key(password, salt)

    if cipher_type == "AES-256-GCM":
        cipher = AESGCM(key)
    else:
        cipher = ChaCha20Poly1305(key)

    try:
        return cipher.decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError(
            "Password salah atau ciphertext telah diubah."
        ) from exc


def encrypt_text(
    text: str,
    password: str,
    algorithm: str = "AES-256-GCM",
) -> str:
    """Mengenkripsi teks."""
    return encrypt_bytes(
        text.encode("utf-8"),
        password,
        algorithm,
    )


def decrypt_text(encoded_data: str, password: str) -> str:
    """Mendekripsi ciphertext menjadi teks."""
    plaintext = decrypt_bytes(encoded_data, password)
    return plaintext.decode("utf-8")


def encrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    algorithm: str = "AES-256-GCM",
) -> None:
    """Mengenkripsi file."""
    data = Path(input_path).read_bytes()
    encrypted_data = encrypt_bytes(data, password, algorithm)

    Path(output_path).write_text(
        encrypted_data,
        encoding="utf-8",
    )


def decrypt_file(
    input_path: str,
    output_path: str,
    password: str,
) -> None:
    """Mendekripsi file."""
    encrypted_data = Path(input_path).read_text(
        encoding="utf-8",
    )

    decrypted_data = decrypt_bytes(encrypted_data, password)

    Path(output_path).write_bytes(decrypted_data)