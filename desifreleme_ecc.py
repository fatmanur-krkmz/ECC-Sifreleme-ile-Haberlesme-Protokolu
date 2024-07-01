import hashlib
import json
import os
import time

from tinyec import ec, registry

curve = registry.get_curve('brainpoolP256r1')

def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]

def uncompress_point(compressed_point):
    x = int(compressed_point[:-1], 16)
    y_lsbit = int(compressed_point[-1], 16)
    y_square = (x ** 3 + curve.a * x + curve.b) % curve.field.p
    y = pow(y_square, (curve.field.p + 1) // 4, curve.field.p)
    if y % 2 != y_lsbit:
        y = curve.field.p - y
    return ec.Point(curve, x, y)

def ecc_decrypt(privKey, ciphertext, ciphertextPubKey):
    sharedECCKey = privKey * uncompress_point(ciphertextPubKey)
    sharedECCKey_int = int.from_bytes(compress_point(sharedECCKey).encode(), 'big')
    ciphertext_int = int(ciphertext, 16)
    message_int = ciphertext_int ^ sharedECCKey_int
    decrypted_message = message_int.to_bytes((message_int.bit_length() + 7) // 8, 'big')
    return decrypted_message

def compute_hash(data):
    return hashlib.sha256(data).digest()

def verify_signature(pubKey, message, signature):
    recovered_signature = uncompress_point(signature)
    return recovered_signature == (pubKey)

def main():
    if os.path.exists('private_key.json'):
        with open('private_key.json', 'r') as file:
            keys = json.load(file)
            private_key = int(keys['private_key'], 16)
    else:
        print("Anahtar dosyası bulunamadı. Lütfen şifreleme işlemi yapın.")
        return

    if not os.path.exists('encrypted_picture.txt'):
        print("Şifrelenmiş fotoğraf bulunamadı.")
        return

    with open('encrypted_picture.txt', 'r') as encrypted_file:
        lines = encrypted_file.readlines()
        ciphertext = lines[0].strip()
        ciphertextPubKey = lines[1].strip()
        received_hash = bytes.fromhex(lines[2].strip())
        signature = lines[3].strip()
        sender_pubKey = lines[4].strip()

    sender_pubKey_point = uncompress_point(sender_pubKey)

    # Fotoğrafı deşifreleme işlemini zamanla
    start_time_decrypt = time.time()

    # Fotoğrafı deşifreleyin
    decrypted_image_data = ecc_decrypt(private_key, ciphertext, ciphertextPubKey)

    decrypt_time = time.time() - start_time_decrypt
    print("Deşifreleme süresi:", decrypt_time, "saniye")

    if decrypted_image_data:
        with open('decrypted_picture.jpg', 'wb') as decrypted_file:
            decrypted_file.write(decrypted_image_data)
        print("Fotoğraf deşifre edildi ve kaydedildi: decrypted_picture.jpg")

        # Hash hesaplama işlemini zamanla
        start_time_hash = time.time()

        decrypted_hash = compute_hash(decrypted_image_data)

        hash_time = time.time() - start_time_hash
        print("Hash hesaplama süresi:", hash_time, "saniye")

        # İmzayı doğrulama işlemini zamanla
        start_time_verify = time.time()

        # İmzayı doğrula
        if verify_signature(sender_pubKey_point, decrypted_image_data, signature):
            print("İmza doğrulandı.")
            # Hash değerini doğrula
            if decrypted_hash == received_hash:
                print("Fotoğrafın bütünlüğü doğrulandı.")
            else:
                print("Hata: Fotoğrafın bütünlüğü doğrulanamadı. Veri bozulmuş olabilir.")
        else:
            print("Hata: İmza doğrulanamadı.")

        verify_time = time.time() - start_time_verify
        print("İmza doğrulama süresi:", verify_time, "saniye")
    else:
        print("Hata: Fotoğraf deşifre edilemedi.")

if __name__ == "__main__":
    main()
