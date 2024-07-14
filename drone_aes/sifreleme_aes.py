import csv
import os
import time

import cv2
import psutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from djitellopy import Tello


# Kaynak kullanımını izleme fonksiyonu
def monitor_resource_usage():
    process = psutil.Process(os.getpid())
    cpu_usage_aes = process.cpu_percent(interval=None)
    memory_info = process.memory_info()
    memory_usage = memory_info.rss / (1024 * 1024)  # MB cinsinden
    return cpu_usage_aes, memory_usage

# Verileri CSV dosyasına yazma fonksiyonu
def log_data(stage_aes, cpu_usage_aes, memory_usage_aes, time_taken_aes, csv_writer):
    csv_writer.writerow([stage_aes, cpu_usage_aes, memory_usage_aes, time_taken_aes])

# Tello ile bağlantı kurma ve fotoğraf çekme
def capture_photo(csv_writer):
    tello = Tello()
    tello.connect()
    tello.streamon()
    time.sleep(2)
    frame_read = tello.get_frame_read()


    # Fotoğraf çekme
    for i in range(30):
        img = frame_read.frame
        cv2.imshow("Tello", img)
        cv2.waitKey(1)
    photo_path = "photo.png"
    cv2.imwrite(photo_path, img)



    # Kamerayı ve dron bağlantısını kapatma
    tello.streamoff()
    tello.end()

    return photo_path

# ECC ile anahtar oluşturma ve şifreleme
def encrypt_photo(photo_path, csv_writer):
    # ECC anahtar çiftini oluşturma
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()

    # Private anahtarı PEM formatında kaydetme
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("private_key.pem", "wb") as pem_out:
        pem_out.write(pem_private)

    # Public anahtarı PEM formatında kaydetme
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_key.pem", "wb") as pem_out:
        pem_out.write(pem_public)

    # Çekilen fotoğrafı okuma
    with open(photo_path, "rb") as image_file:
        image_data = image_file.read()

    # ECC ile ortak anahtarı oluşturma
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    # AES-GCM ile fotoğrafı şifreleme
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # Zaman ölçümünü başlat
    start_time = time.time()
    
    # CPU kullanımını ölçmeye başla
    initial_cpu_usage_aes = psutil.cpu_percent(interval=None)

    encrypted_image = encryptor.update(image_data) + encryptor.finalize()

    # Zaman ölçümünü bitir
    encryption_time = time.time() - start_time
    print("Şifreleme Süresi:", encryption_time, "saniye")
    
    # CPU kullanımını ölçmeyi bitir
    final_cpu_usage_aes = psutil.cpu_percent(interval=None)
    average_cpu_usage_aes = (initial_cpu_usage_aes + final_cpu_usage_aes) / 2

    # Kaynak kullanımı ölçümleri
    cpu_usage_aes, memory_usage_aes = monitor_resource_usage()
    log_data('Encrypt', average_cpu_usage_aes, memory_usage_aes, encryption_time, csv_writer)
    print(f"Şifreleme sonrası CPU Kullanımı: {average_cpu_usage_aes}%")
    print(f"Şifreleme sonrası Bellek Kullanımı: {memory_usage_aes} MB")

    tag = encryptor.tag

    # Şifrelenmiş fotoğrafı ve IV'yi kaydetme
    with open("encrypted_photo.bin", "wb") as encrypted_file:
        encrypted_file.write(iv + tag + encrypted_image)

    print("Fotoğraf başarıyla şifrelendi ve kaydedildi.")

# Fotoğraf çekme ve şifreleme
with open('resource_usage_aes.csv', 'w', newline='') as csvfile:
    csv_writer = csv.writer(csvfile)
    csv_writer.writerow(['Stage', 'CPU Usage (%)', 'Memory Usage (MB)', 'Time Taken (s)'])

    photo_path = capture_photo(csv_writer)
    encrypt_photo(photo_path, csv_writer)
