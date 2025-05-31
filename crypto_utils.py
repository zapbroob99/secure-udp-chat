# crypto_utils.py
import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
# cryptography.hazmat.primitives.hmac'i burada import etmeyeceğiz, çünkü compare_digest orada yok.
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

import hmac as std_hmac # Python'un standart hmac kütüphanesini import ediyoruz ve std_hmac olarak adlandırıyoruz

P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
G = 2
DH_PARAMETERS = dh.DHParameterNumbers(P, G).parameters(default_backend())

def generate_dh_keys():
    private_key = DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def derive_shared_key(private_key, peer_public_key_bytes):
    peer_public_key = serialization.load_der_public_key(
        peer_public_key_bytes,
        backend=default_backend()
    )
    if not isinstance(peer_public_key, dh.DHPublicKey):
        raise TypeError(f"Beklenmedik anahtar türü: {type(peer_public_key)}. DHPublicKey bekleniyordu.")
    shared_secret = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'aes session key',
        backend=default_backend()
    ).derive(shared_secret)
    return derived_key

def encrypt_aes_gcm(key, plaintext):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return base64.b64encode(nonce + encryptor.tag + ciphertext).decode('utf-8')
  
def decrypt_aes_gcm(key, encrypted_blob_b64):
    try:
        encrypted_blob = base64.b64decode(encrypted_blob_b64)
        nonce = encrypted_blob[:12]
        tag = encrypted_blob[12:28]
        ciphertext = encrypted_blob[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    except Exception as e:
        print(f"Deşifreleme hatası: {e}")
        return None

def hash_password(password):
    salt = os.urandom(16)
    # print(f"  [HASH_PASSWORD DEBUG] Oluşturulan salt (hex): {salt.hex()}")
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    # print(f"  [HASH_PASSWORD DEBUG] Oluşturulan hash (hex): {pwd_hash.hex()}")
    stored_value = base64.b64encode(salt + pwd_hash).decode('utf-8')
    # print(f"  [HASH_PASSWORD DEBUG] Saklanacak değer (base64): {stored_value}")
    return stored_value

def verify_password(stored_password_b64, provided_password):
    try:
        # print(f"\n  [VERIFY_PASSWORD DEBUG] === Başlangıç ===")
        # print(f"  [VERIFY_PASSWORD DEBUG] Gelen stored_password_b64: {stored_password_b64}")
        # print(f"  [VERIFY_PASSWORD DEBUG] Gelen provided_password (uzunluk): {len(provided_password)}, (ilk 3): {provided_password[:3] if provided_password else ''}...")

        decoded_stored_password = base64.b64decode(stored_password_b64)
        # print(f"  [VERIFY_PASSWORD DEBUG] Base64 çözülmüş stored_password (uzunluk): {len(decoded_stored_password)}")

        salt = decoded_stored_password[:16]
        stored_hash_from_db = decoded_stored_password[16:]
        
        # print(f"  [VERIFY_PASSWORD DEBUG] Çözülen salt (uzunluk): {len(salt)}, (hex): {salt.hex()}")
        # print(f"  [VERIFY_PASSWORD DEBUG] DB'den çözülen hash (uzunluk): {len(stored_hash_from_db)}, (hex): {stored_hash_from_db.hex()}")

        recalculated_hash = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt,
            100000,
            dklen=32
        )
        # print(f"  [VERIFY_PASSWORD DEBUG] Yeniden hesaplanan hash (uzunluk): {len(recalculated_hash)}, (hex): {recalculated_hash.hex()}")
        
        # Düzeltilmiş satır: std_hmac.compare_digest kullanılıyor
        is_match = std_hmac.compare_digest(recalculated_hash, stored_hash_from_db)
        # print(f"  [VERIFY_PASSWORD DEBUG] Karşılaştırma sonucu (is_match): {is_match}")
        # print(f"  [VERIFY_PASSWORD DEBUG] === Bitiş ===\n")
        return is_match
    except Exception as e:
        print(f"  [VERIFY_PASSWORD DEBUG HATA] verify_password içinde istisna: {e}")
        import traceback
        traceback.print_exc()
        # print(f"  [VERIFY_PASSWORD DEBUG] === Hata ile Bitiş ===\n")
        return False

# Test için (isteğe bağlı)
if __name__ == '__main__':
    password = "çokGüçlüParola123!"
    print("Hashleme ve doğrulama testi başlıyor...")
    hashed = hash_password(password)
    print(f"Oluşturulan Hashed Parola: {hashed}")
    
    print("\nDoğru parola ile doğrulama testi:")
    is_correct_verified = verify_password(hashed, password)
    print(f"Doğru parola doğrulama sonucu: {is_correct_verified}")
    assert is_correct_verified
    
    print("\nYanlış parola ile doğrulama testi:")
    is_incorrect_verified = verify_password(hashed, "yanlisParola")
    print(f"Yanlış parola doğrulama sonucu: {is_incorrect_verified}")
    assert not is_incorrect_verified
    
    print("\nParola Hashleme/Doğrulama Başarılı!")