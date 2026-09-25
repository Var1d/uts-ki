import base64
import pytest
from crypto_utils import encrypt_bytes, decrypt_bytes, encrypt_text, decrypt_text


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
    
def test_file_encrypt_decrypt(tmp_path):
    """File yang dienkripsi harus kembali sama setelah didekripsi."""
    from crypto_utils import encrypt_file, decrypt_file

    original_file = tmp_path / "dokumen.txt"
    encrypted_file = tmp_path / "dokumen.utsk"
    decrypted_file = tmp_path / "dokumen_pulih.txt"

    original_data = b"Ini contoh isi file rahasia."
    original_file.write_bytes(original_data)

    password = "PasswordContoh123!"

    encrypt_file(
        str(original_file),
        str(encrypted_file),
        password,
    )

    decrypt_file(
        str(encrypted_file),
        str(decrypted_file),
        password,
    )

    assert decrypted_file.read_bytes() == original_data


def test_file_wrong_password_fails(tmp_path):
    """File tidak dapat didekripsi dengan password yang salah."""
    from crypto_utils import encrypt_file, decrypt_file

    original_file = tmp_path / "dokumen.txt"
    encrypted_file = tmp_path / "dokumen.utsk"
    decrypted_file = tmp_path / "dokumen_pulih.txt"

    original_file.write_text("Pesan rahasia", encoding="utf-8")

    encrypt_file(
        str(original_file),
        str(encrypted_file),
        "PasswordBenar123!",
    )

    with pytest.raises(ValueError):
        decrypt_file(
            str(encrypted_file),
            str(decrypted_file),
            "PasswordSalah123!",
        )