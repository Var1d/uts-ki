import base64
import pytest
from demo_crypto import encrypt_bytes, decrypt_bytes, encrypt_text, decrypt_text


def test_text_encrypt_decrypt():
    """Teks yang dienkripsi harus kembali sama setelah didekripsi."""
    plaintext = "Halo, ini pesan rahasia."
    password = "PasswordContoh123!"

    ciphertext = encrypt_text(plaintext, password)
    result = decrypt_text(ciphertext, password)

    assert result == plaintext


def test_wrong_password_fails():
    """Password yang salah harus menyebabkan dekripsi gagal."""
    ciphertext = encrypt_text("Pesan rahasia", "PasswordBenar123!")

    with pytest.raises(ValueError):
        decrypt_text(ciphertext, "PasswordSalah123!")


def test_modified_ciphertext_fails():
    """Ciphertext yang diubah harus menyebabkan dekripsi gagal."""
    ciphertext = encrypt_text("Pesan rahasia", "PasswordContoh123!")

    # Ubah ciphertext Base64 menjadi bytes
    payload = bytearray(base64.b64decode(ciphertext))

    # Ubah satu byte pada bagian ciphertext, bukan header/salt/nonce
    payload[-1] ^= 1

    modified_ciphertext = base64.b64encode(payload).decode("ascii")

    with pytest.raises(ValueError):
        decrypt_text(modified_ciphertext, "PasswordContoh123!")


def test_binary_data_encrypt_decrypt():
    """Data biner harus tetap sama setelah enkripsi dan dekripsi."""
    original_data = bytes([0, 1, 2, 3, 100, 200, 255])
    password = "PasswordContoh123!"

    ciphertext = encrypt_bytes(original_data, password)
    result = decrypt_bytes(ciphertext, password)

    assert result == original_data


def test_each_encryption_is_different():
    """Enkripsi berulang dengan input sama menghasilkan ciphertext berbeda."""
    plaintext = "Pesan yang sama"
    password = "PasswordContoh123!"

    ciphertext_1 = encrypt_text(plaintext, password)
    ciphertext_2 = encrypt_text(plaintext, password)

    assert ciphertext_1 != ciphertext_2