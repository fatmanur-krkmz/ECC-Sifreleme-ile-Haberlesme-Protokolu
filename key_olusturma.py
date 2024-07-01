import json
import secrets

from cryptography.fernet import Fernet
from tinyec import registry

# ECC curve
curve = registry.get_curve('brainpoolP256r1')

# Alıcının private ve public key'ini oluştur
private_key = secrets.randbelow(curve.field.n)
public_key = private_key * curve.g

# Public key'i sıkıştır
def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]

compressed_public_key = compress_point(public_key)

# Public key'i dosyaya kaydet
public_key_data = {
    'public_key': compressed_public_key
}

with open('public_key.json', 'w') as file:
    json.dump(public_key_data, file)

# Private key'i şifreleyip dosyaya kaydet
key = Fernet.generate_key()
cipher_suite = Fernet(key)
private_key_data = {
    'private_key': hex(private_key)
}
plaintext = json.dumps(private_key_data).encode()
encrypted_data = cipher_suite.encrypt(plaintext)

with open('private_key.json', 'w') as file:
    json.dump(private_key_data, file)

print(f"Public Key: {compressed_public_key}")
print("Public key public_key.json dosyasına kaydedildi.")
print("Private key private_key_encrypted.json dosyasına şifrelenmiş olarak kaydedildi.")