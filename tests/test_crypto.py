import base64
import pytest
from crypto_utils import (
    encrypt_bytes,
    decrypt_bytes,
    encrypt_text,
    decrypt_text,
    encrypt_file,
    decrypt_file,
)

ALGORITHMS = [
    "AES-256-GCM",
    "ChaCha20-Poly1305",
]

@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_text_roundtrip(algorithm):
    """Teks yang dienkripsi harus kembali seperti semula."""
    text = "Halo CipherSafe!"
    password = "Rahasia123"

    ciphertext = encrypt_text(text, password, algorithm)
    plaintext = decrypt_text(ciphertext, password)

    assert plaintext == text


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_wrong_password_fails(algorithm):
    """Password yang salah harus ditolak."""
    ciphertext = encrypt_text(
        "Pesan rahasia",
        "PasswordBenar",
        algorithm,
    )

    with pytest.raises(ValueError):
        decrypt_text(ciphertext, "PasswordSalah")


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_modified_ciphertext_fails(algorithm):
    """Ciphertext yang diubah harus ditolak."""
    ciphertext = encrypt_bytes(
        b"Data rahasia",
        "Password123",
        algorithm,
    )

    payload = bytearray(base64.b64decode(ciphertext))

    # Ubah satu bit pada byte terakhir, yaitu bagian tag autentikasi
    payload[-1] ^= 1

    modified_ciphertext = base64.b64encode(payload).decode("utf-8")

    with pytest.raises(ValueError):
        decrypt_bytes(modified_ciphertext, "Password123")


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_binary_data_roundtrip(algorithm):
    """Data biner, termasuk byte nol, harus tetap utuh."""
    original_data = bytes([0, 1, 2, 10, 128, 255]) * 20

    ciphertext = encrypt_bytes(
        original_data,
        "Password123",
        algorithm,
    )

    decrypted_data = decrypt_bytes(ciphertext, "Password123")

    assert decrypted_data == original_data


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_file_roundtrip(tmp_path, algorithm):
    """File yang dienkripsi harus bisa dikembalikan."""
    input_file = tmp_path / "contoh.txt"
    encrypted_file = tmp_path / "contoh.txt.utsk"
    decrypted_file = tmp_path / "hasil.txt"

    original_data = b"Ini isi file untuk pengujian."
    input_file.write_bytes(original_data)

    encrypt_file(
        str(input_file),
        str(encrypted_file),
        "Password123",
        algorithm,
    )

    decrypt_file(
        str(encrypted_file),
        str(decrypted_file),
        "Password123",
    )

    assert decrypted_file.read_bytes() == original_data


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_random_encryption_output(algorithm):
    """Enkripsi berulang harus menghasilkan ciphertext berbeda."""
    text = "Teks yang sama"
    password = "Password123"

    ciphertext_1 = encrypt_text(text, password, algorithm)
    ciphertext_2 = encrypt_text(text, password, algorithm)

    assert ciphertext_1 != ciphertext_2


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_empty_data_roundtrip(algorithm):
    """Data kosong tetap bisa dienkripsi dan didekripsi."""
    ciphertext = encrypt_bytes(b"", "Password123", algorithm)

    decrypted_data = decrypt_bytes(ciphertext, "Password123")

    assert decrypted_data == b""


@pytest.mark.parametrize("algorithm, expected_marker", [
    ("AES-256-GCM", b"UTSKI1"),
    ("ChaCha20-Poly1305", b"UTSKC1"),
])
def test_ciphertext_has_correct_algorithm_marker(
    algorithm,
    expected_marker,
):
    """Ciphertext memiliki penanda algoritma yang sesuai."""
    ciphertext = encrypt_bytes(
        b"Data",
        "Password123",
        algorithm,
    )

    payload = base64.b64decode(ciphertext)

    assert payload.startswith(expected_marker)


def test_unsupported_algorithm_fails():
    """Nama algoritma yang tidak didukung harus ditolak."""
    with pytest.raises(ValueError):
        encrypt_bytes(
            b"Data",
            "Password123",
            "ALGORITMA-TIDAK-ADA",
        )