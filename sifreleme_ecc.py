import hashlib
import json
import os
import secrets
import time

import cv2
import psutil
from djitellopy import Tello
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

def ecc_encrypt(pubKey, message):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    sharedECCKey = pubKey * ciphertextPrivKey
    sharedECCKey_int = int.from_bytes(compress_point(sharedECCKey).encode(), 'big')
    message_int = int.from_bytes(message, 'big')
    ciphertext_int = message_int ^ sharedECCKey_int
    ciphertext = hex(ciphertext_int)[2:]
    return ciphertext, compress_point(ciphertextPubKey)

def compute_hash(data):
    hash_value = hashlib.sha256(data).digest()
    return hash_value

def sign_message(privKey, message):
    hash_int = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
    signature = privKey * curve.g
    return compress_point(signature)

def monitor_resource_usage():
    process = psutil.Process(os.getpid())
    cpu_usage = process.cpu_percent(interval=1)
    memory_info = process.memory_info()
    memory_usage = memory_info.rss / (1024 * 1024)  # MB cinsinden
    return cpu_usage, memory_usage

def main():
    if os.path.exists('public_key.json'):
        with open('public_key.json', 'r') as file:
            public_key_data = json.load(file)
            public_key = uncompress_point(public_key_data['public_key'])
    else:
        print("Public key bulunamadı. Lütfen alıcıdan public key'i alınız.")
        return

    tello = Tello()
    tello.connect()
    print(f'Batarya: {tello.get_battery()}%')
    tello.streamon()
    time.sleep(2)
    frame_read = tello.get_frame_read()

    for i in range(30):
        frame = frame_read.frame
        cv2.imshow("Tello",frame)

        cv2.waitKey(1)

    cv2.imwrite('tello_picture.jpg', frame)
    print("Fotoğraf çekildi ve kaydedildi.")

    with open('tello_picture.jpg', 'rb') as image_file:
        image_data = image_file.read()

    original_hash = compute_hash(image_data)

    # Gönderici tarafında özel ve genel anahtar çifti oluştur
    sender_privKey = secrets.randbelow(curve.field.n)
    sender_pubKey = sender_privKey * curve.g

    # Mesajı imzala
    signature = sign_message(sender_privKey, image_data)

    # Fotoğrafı şifreleme işlemini zamanla
    start_time_encrypt = time.time()

    # Fotoğrafı şifrele
    ciphertext, ciphertextPubKey = ecc_encrypt(public_key, image_data)
    #print("Şifrelenmiş Fotoğraf:", ciphertext)

    encrypt_time = time.time() - start_time_encrypt
    print("Şifreleme süresi:", encrypt_time, "saniye")

    cpu_usage, memory_usage = monitor_resource_usage()
    print(f"Şifreleme sonrası CPU Kullanımı: {cpu_usage}%")
    print(f"Şifreleme sonrası Bellek Kullanımı: {memory_usage} MB")

    with open('encrypted_picture.txt', 'w') as encrypted_file:
        encrypted_file.write(f"{ciphertext}\n{ciphertextPubKey}\n{original_hash.hex()}\n{signature}\n{compress_point(sender_pubKey)}")

    tello.streamoff()
    tello.end()

if __name__ == "__main__":
    main()
