import os
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Şifrelenmiş görüntüyü deşifre etme
def decrypt_photo(encrypted_photo_path, private_key_path, public_key_path):
    # ECC özel anahtarını ve ortak anahtarı yükleyin
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Şifrelenmiş fotoğrafı okuyun
    with open(encrypted_photo_path, "rb") as encrypted_file:
        iv = encrypted_file.read(12)
        tag = encrypted_file.read(16)
        encrypted_image = encrypted_file.read()

    # ECC ile ortak anahtarı oluşturma
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    # AES-GCM ile şifre çözme
    decryptor = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # Zaman ölçümünü başlat
    start_time = time.time()

    decrypted_image = decryptor.update(encrypted_image) + decryptor.finalize()

    # Zaman ölçümünü bitir
    decryption_time = time.time() - start_time
    print("Deşifreleme Süresi:", decryption_time, "saniye")

    # Çözülmüş fotoğrafı kaydedin
    decrypted_photo_path = "decrypted_photo.png"
    with open(decrypted_photo_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_image)

    print(f"Fotoğraf başarıyla çözüldü ve {decrypted_photo_path} olarak kaydedildi.")

# Şifrelenmiş fotoğrafı deşifre etme
encrypted_photo_path = "encrypted_photo.bin"
private_key_path = "private_key.pem"  # Özel anahtarın yolu
public_key_path = "public_key.pem"  # Ortak anahtarın yolu

decrypt_photo(encrypted_photo_path, private_key_path, public_key_path)