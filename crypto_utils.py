import os
import base64
import hashlib
import struct # Sayaçları baytlara dönüştürmek için
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.backends import default_backend
import hmac as std_hmac

# ... (P, G, DH_PARAMETERS, DH fonksiyonları, Parola fonksiyonları, İmzalama fonksiyonları aynı kalacak) ...
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
G = 2
DH_PARAMETERS = dh.DHParameterNumbers(P, G).parameters(default_backend())

# --- Diffie-Hellman Fonksiyonları ---
def generate_dh_keys():
    private_key = DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key): # DH Genel Anahtarı için
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

# --- Parola Karma Fonksiyonları ---
def hash_password(password):
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    stored_value = base64.b64encode(salt + pwd_hash).decode('utf-8')
    return stored_value

def verify_password(stored_password_b64, provided_password):
    try:
        decoded_stored_password = base64.b64decode(stored_password_b64)
        salt = decoded_stored_password[:16]
        stored_hash_from_db = decoded_stored_password[16:]
        recalculated_hash = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt,
            100000,
            dklen=32
        )
        return std_hmac.compare_digest(recalculated_hash, stored_hash_from_db)
    except Exception as e:
        # print(f"Parola doğrulama hatası: {e}") # İsteğe bağlı loglama
        return False

# --- Sunucu İmzalama Fonksiyonları (RSA ile) ---
def generate_signing_keys(): # Sunucu için imzalama anahtar çifti üretir
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048, 
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(signing_private_key, data): # Veriyi imzalar
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    signature = signing_private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(signing_public_key, signature, data): # İmzayı doğrular
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    try:
        signing_public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception: 
        return False

def serialize_signing_public_key_pem(public_key): 
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_signing_public_key_from_pem(pem_bytes): 
    return serialization.load_pem_public_key(
        pem_bytes,
        backend=default_backend()
    )

def serialize_signing_private_key_pem(private_key, password=None): 
    encryption_algo = serialization.BestAvailableEncryption(password.encode('utf-8')) if password else serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    )

def load_signing_private_key_from_pem(pem_bytes, password=None): 
    return serialization.load_pem_private_key(
        pem_bytes,
        password=password.encode('utf-8') if password else None,
        backend=default_backend()
    )


# --- AES-GCM Şifreleme Fonksiyonları (Sıralı Nonce ile Güncellendi) ---
NONCE_RANDOM_PART_LEN = 8
NONCE_COUNTER_PART_LEN = 4 # 4 bayt = 32 bit sayaç
NONCE_LEN = NONCE_RANDOM_PART_LEN + NONCE_COUNTER_PART_LEN # Toplam 12 bayt

def encrypt_aes_gcm(key, plaintext, message_counter):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    random_part = os.urandom(NONCE_RANDOM_PART_LEN)
    # Mesaj sayacını 4 baytlık big-endian unsigned integer olarak paketle
    counter_part = struct.pack('>I', message_counter) # >I: big-endian unsigned int (4 bayt)
    
    if len(counter_part) > NONCE_COUNTER_PART_LEN:
        raise ValueError("Mesaj sayacı çok büyük, nonce'a sığmıyor.")
    # Gerekirse padding (normalde struct.pack doğru boyutu verir)
    counter_part = counter_part.rjust(NONCE_COUNTER_PART_LEN, b'\x00')


    nonce = random_part + counter_part
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"Nonce uzunluğu hatalı: beklenen {NONCE_LEN}, gelen {len(nonce)}")

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # Nonce şifreli blobun başına ekleniyor, bu zaten GCM için standart.
    # Alıcı nonce'ı ayırıp sayacı çıkaracak.
    return base64.b64encode(nonce + encryptor.tag + ciphertext).decode('utf-8')

def decrypt_aes_gcm(key, encrypted_blob_b64):
    try:
        encrypted_blob = base64.b64decode(encrypted_blob_b64)
        
        nonce = encrypted_blob[:NONCE_LEN]
        tag = encrypted_blob[NONCE_LEN : NONCE_LEN + 16] # GCM tag her zaman 16 bayttır
        ciphertext = encrypted_blob[NONCE_LEN + 16:]

        # Nonce'dan mesaj sayacını çıkar
        # random_part = nonce[:NONCE_RANDOM_PART_LEN] # Aslında deşifreleme için gerekmiyor
        counter_part = nonce[NONCE_RANDOM_PART_LEN:]
        message_counter = struct.unpack('>I', counter_part)[0] # tuple döner, ilk elemanı alırız

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        # plaintext ve çıkarılan mesaj sayacını döndür
        print(plaintext_bytes.decode('utf-8'), message_counter)
        return plaintext_bytes.decode('utf-8'), message_counter
    except Exception as e:
        print(f"Deşifreleme/Sayaç çıkarma hatası: {e}")
        return None, -1 # Başarısızlık durumunda geçersiz sayaç değeri