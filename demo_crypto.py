from crypto_utils import encrypt_text, decrypt_text


password = "PasswordContoh123!"
plaintext = "Halo, ini pesan rahasia pertama."

ciphertext = encrypt_text(plaintext, password)

print("Teks asli:")
print(plaintext)

print("\nCiphertext Base64:")
print(ciphertext)

decrypted_text = decrypt_text(ciphertext, password)

print("\nHasil dekripsi:")
print(decrypted_text)

assert decrypted_text == plaintext

print("\nTes berhasil!")