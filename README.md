# CipherSafe

## Deskripsi

CipherSafe adalah aplikasi web lokal untuk mengenkripsi dan mendekripsi teks maupun file. Aplikasi ini dibuat sebagai proyek Aplikasi Kriptografi dengan AES-256-GCM dan ChaCha20-Poly1305.

## Cara Kerja

Pilih algoritma saat mengenkripsi teks atau file. Hasil enkripsi teks ditampilkan sebagai Base64, sedangkan file dapat diunduh dengan ekstensi `.utsk`. Saat dekripsi, aplikasi membaca penanda pada ciphertext untuk mengenali algoritmanya. Jika password salah atau ciphertext berubah, verifikasi autentikasi gagal dan data tidak didekripsi.

Kunci 32 byte diturunkan dari password menggunakan PBKDF2-HMAC-SHA256 dengan 600.000 iterasi. Setiap enkripsi memakai salt acak 16 byte dan nonce acak 12 byte. Keduanya disimpan bersama ciphertext agar dapat digunakan kembali saat dekripsi. Penanda `UTSKI1` menandai AES-256-GCM dan `UTSKC1` menandai ChaCha20-Poly1305.

## Instalasi

Pastikan Python 3.10 atau lebih baru tersedia. Dari PowerShell, buat environment dan pasang dependensi:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Menjalankan Aplikasi

Jalankan server dari folder proyek:

```powershell
python app.py
```

Buka `http://127.0.0.1:5000` di browser. Pilih fitur teks atau file untuk mengenkripsi dan mendekripsi. Untuk file, gunakan file `.utsk` saat dekripsi. Tekan `Ctrl+C` di terminal untuk menghentikan server.

## Contoh Penggunaan

Untuk mengenkripsi teks, buka fitur **Enkripsi dan Dekripsi Teks**, masukkan teks dan password, pilih AES-256-GCM atau ChaCha20-Poly1305, lalu tekan **Enkripsi Teks**. Hasilnya ditampilkan sebagai ciphertext Base64. Untuk mengembalikan teks, masukkan ciphertext tersebut dan password yang sama, lalu tekan **Dekripsi Teks**.

Untuk file, buka fitur **Enkripsi dan Dekripsi File**, pilih file, masukkan password, lalu pilih algoritma dan tekan **Enkripsi File**. Aplikasi mengunduh file dengan akhiran `.utsk`. Untuk mendekripsinya, pilih file `.utsk`, masukkan password yang sama, lalu tekan **Dekripsi File**.

## Pengujian

Jalankan tes unit dengan perintah berikut:

```powershell
python -m pytest -q
```

Tes mencakup enkripsi dan dekripsi teks, file, data biner, dan data kosong. Tes juga memastikan password salah dan ciphertext yang diubah ditolak.

Untuk membuat laporan pengujian lengkap, jalankan:

```powershell
python uji_pengujian.py
```

Skrip membuat sampel TXT, CSV, JSON, HTML, PDF, ZIP, BIN, PNG, JPG, dan GIF, lalu menguji semuanya dengan kedua algoritma. Skrip juga mengukur waktu enkripsi dan dekripsi untuk file 1 KB, 1 MB, dan 10 MB dengan tiga pengulangan. Hasilnya disimpan di `hasil_pengujian.xlsx`.

Laporan Excel memuat hasil dekripsi dan hash file, waktu proses, avalanche effect, entropi, histogram byte, serta perbandingan AES-256-GCM dengan ChaCha20-Poly1305. Pengukuran avalanche mengubah satu bit kunci pada setiap percobaan dan membandingkan ciphertext dengan nonce yang sama; tag autentikasi tidak dihitung. Pengukuran ini bersifat empiris dan bukan bukti formal keamanan. Tutup workbook di Excel sebelum membuat laporan baru agar file dapat ditimpa.

`benchmark.py` juga dapat dijalankan untuk membuat benchmark terpisah dalam format CSV.

## Anggota Kelompok

- Jamal Abdul Nasir — 247006111015
- M Fadhil Nurwahid — 247006111056
- Farid Dhiya Fairuz — 247006111058

## Visualisasi Gambar

Fitur Visualisasi Gambar membandingkan gambar asli dengan hasil AES-ECB dan AES-GCM. AES-ECB hanya disertakan untuk menunjukkan pola dan kelemahan mode tersebut. Fitur enkripsi teks dan file tidak menggunakan ECB. Jangan gunakan AES-ECB untuk melindungi data.

## Catatan Keamanan

CipherSafe dibuat untuk demonstrasi dan keperluan akademik, bukan untuk penggunaan produksi. Aplikasi berjalan dengan server pengembangan Flask dalam mode debug, jadi gunakan hanya di komputer lokal dan jangan paparkan ke jaringan publik. Simpan salinan file asli dan gunakan password yang kuat.
