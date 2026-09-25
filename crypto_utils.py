from pathlib import Path
import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"UTSKI1"

SALT_SIZE = 16
NONCE_SIZE = 12

ITERATIONS = 600_000

def derive_key(password: str, salt: bytes) -> bytes:
    """Mengubah password menjadi kunci AES 256-bit."""
    if not password:
        raise ValueError("Password tidak boleh kosong.")

    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )

    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, password: str) -> str:
    """Mengenkripsi data bytes dan menghasilkan ciphertext Base64."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(nonce, data, None)

    payload = MAGIC + salt + nonce + ciphertext

    return base64.b64encode(payload).decode("ascii")


def decrypt_bytes(encoded_data: str, password: str) -> bytes:
    """Mendekripsi ciphertext Base64 menjadi data bytes."""
    try:
        payload = base64.b64decode(encoded_data, validate=True)
    except Exception:
        raise ValueError("Format ciphertext Base64 tidak valid.") from None

    minimum_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16

    if len(payload) < minimum_size:
        raise ValueError("Data ciphertext terlalu pendek.")

    if not payload.startswith(MAGIC):
        raise ValueError("Format data tidak dikenali.")

    start = len(MAGIC)

    salt = payload[start:start + SALT_SIZE]
    start += SALT_SIZE

    nonce = payload[start:start + NONCE_SIZE]
    start += NONCE_SIZE

    ciphertext = payload[start:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError(
            "Password salah atau ciphertext telah diubah."
        ) from None


def encrypt_text(plaintext: str, password: str) -> str:
    """Mengenkripsi teks."""
    return encrypt_bytes(plaintext.encode("utf-8"), password)


def decrypt_text(ciphertext: str, password: str) -> str:
    """Mendekripsi ciphertext menjadi teks."""
    plaintext = decrypt_bytes(ciphertext, password)
    return plaintext.decode("utf-8")

def encrypt_file(
    input_path: str,
    output_path: str,
    password: str,
) -> None:
    """Mengenkripsi file dan menyimpan ciphertext dalam format Base64."""
    input_file = Path(input_path)
    output_file = Path(output_path)

    data = input_file.read_bytes()
    ciphertext = encrypt_bytes(data, password)

    output_file.write_text(ciphertext, encoding="utf-8")


def decrypt_file(
    input_path: str,
    output_path: str,
    password: str,
) -> None:
    """Mendekripsi file Base64 dan menyimpan kembali data aslinya."""
    input_file = Path(input_path)
    output_file = Path(output_path)

    ciphertext = input_file.read_text(encoding="utf-8")
    decrypted_data = decrypt_bytes(ciphertext, password)

    output_file.write_bytes(decrypted_data)