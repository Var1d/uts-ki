import csv
import secrets
import time
from pathlib import Path
from crypto_utils import encrypt_file, decrypt_file


ALGORITHMS = [
    "AES-256-GCM",
    "ChaCha20-Poly1305",
]

FILE_SIZES = [
    ("1 KB", 1024),
    ("1 MB", 1024 * 1024),
    ("10 MB", 10 * 1024 * 1024),
]

PASSWORD = "BenchmarkPassword123"
REPEAT = 3

TEST_DIR = Path("benchmark_files")
RESULT_FILE = Path("hasil_benchmark.csv")


def create_test_file(path, size_bytes):
    """Membuat file uji dengan ukuran tepat."""
    path.write_bytes(secrets.token_bytes(size_bytes))

    actual_size = path.stat().st_size
    if actual_size != size_bytes:
        raise ValueError(
            f"Ukuran file tidak sesuai: {actual_size} byte"
        )


def main():
    TEST_DIR.mkdir(exist_ok=True)
    results = []

    for size_name, size_bytes in FILE_SIZES:
        original_file = TEST_DIR / f"input_{size_name.replace(' ', '')}.bin"

        print(f"\nUkuran file: {size_name}")
        create_test_file(original_file, size_bytes)

        for algorithm in ALGORITHMS:
            encrypt_times = []
            decrypt_times = []

            print(f"  Menguji {algorithm}...")

            for run_number in range(1, REPEAT + 1):
                encrypted_file = TEST_DIR / (
                    f"encrypted_{size_name.replace(' ', '')}_"
                    f"{run_number}.utsk"
                )

                decrypted_file = TEST_DIR / (
                    f"decrypted_{size_name.replace(' ', '')}_"
                    f"{run_number}.bin"
                )

                # Ukur proses enkripsi file, termasuk baca dan tulis file
                start = time.perf_counter()
                encrypt_file(
                    str(original_file),
                    str(encrypted_file),
                    PASSWORD,
                    algorithm,
                )
                encrypt_time = time.perf_counter() - start

                # Ukur proses dekripsi file, termasuk baca dan tulis file
                start = time.perf_counter()
                decrypt_file(
                    str(encrypted_file),
                    str(decrypted_file),
                    PASSWORD,
                )
                decrypt_time = time.perf_counter() - start

                # Pastikan hasil dekripsi sama dengan file asli
                if original_file.read_bytes() != decrypted_file.read_bytes():
                    raise ValueError(
                        f"Hasil dekripsi tidak cocok: {decrypted_file}"
                    )

                encrypt_times.append(encrypt_time)
                decrypt_times.append(decrypt_time)

            avg_encrypt = sum(encrypt_times) / REPEAT
            avg_decrypt = sum(decrypt_times) / REPEAT

            results.append({
                "Ukuran File": size_name,
                "Ukuran (byte)": size_bytes,
                "Algoritma": algorithm,
                "Rata-rata Enkripsi (detik)": avg_encrypt,
                "Rata-rata Dekripsi (detik)": avg_decrypt,
                "Jumlah Pengulangan": REPEAT,
            })

            print(f"    Rata-rata enkripsi: {avg_encrypt:.6f} detik")
            print(f"    Rata-rata dekripsi: {avg_decrypt:.6f} detik")

    with RESULT_FILE.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as file:
        columns = [
            "Ukuran File",
            "Ukuran (byte)",
            "Algoritma",
            "Rata-rata Enkripsi (detik)",
            "Rata-rata Dekripsi (detik)",
            "Jumlah Pengulangan",
        ]

        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nSelesai. Hasil disimpan di {RESULT_FILE}")


if __name__ == "__main__":
    main()