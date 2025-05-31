# security_tester.py
import socket
import threading
import json
import time
import base64
import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from crypto_utils import (
        generate_dh_keys,
        serialize_public_key,
        derive_shared_key,
        encrypt_aes_gcm,
        decrypt_aes_gcm
    )
except ImportError as e:
    print(f"HATA: crypto_utils import edilemedi: {e}")
    sys.exit(1)

# TEST_SERVER_HOST ve PORT, test_server.py'deki ayarlarla eşleşmeli
TEST_SERVER_HOST = '127.0.0.1'
TEST_SERVER_PORT = 65432

ALICE_USERNAME = "alice_victim"
ALICE_PASSWORD = "password_alice"
BOB_USERNAME = "bob_receiver"
BOB_PASSWORD = "password_bob"
MALLORY_USERNAME = "test_user_mallory" # Bu, test_server.py'deki ile aynı olmalı
MALLORY_PASSWORD = "password_mallory"


# --- Yardımcı İstemci Fonksiyonları (Bir öncekiyle büyük ölçüde aynı) ---
def create_socket_and_connect(user_label="İstemci"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((TEST_SERVER_HOST, TEST_SERVER_PORT))
        print(f"{user_label}: {TEST_SERVER_HOST}:{TEST_SERVER_PORT} adresine bağlanıldı.")
        return sock
    except ConnectionRefusedError:
        print(f"{user_label} HATA: Sunucuya bağlanılamadı. TEST Sunucusu çalışıyor mu?")
        return None

def perform_dh_exchange_for_tester(sock, user_label="İstemci"):
    try:
        dh_init_data = sock.recv(2048).strip()
        if not dh_init_data.startswith(b"DH_INIT_SERVER_PUBKEY:"):
            print(f"{user_label} HATA: Geçersiz DH başlatma mesajı.")
            return None
        server_public_key_b64 = dh_init_data[len(b"DH_INIT_SERVER_PUBKEY:"):]
        server_public_key_bytes = base64.b64decode(server_public_key_b64)
        
        priv_key, pub_key = generate_dh_keys()
        pub_key_bytes = serialize_public_key(pub_key)
        sock.sendall(b"DH_CLIENT_PUBKEY:" + base64.b64encode(pub_key_bytes) + b"\n")
        
        session_key = derive_shared_key(priv_key, server_public_key_bytes)
        
        confirmation = sock.recv(1024).strip()
        if confirmation == b"DH_SUCCESS":
            print(f"{user_label}: DH başarılı. Oturum Anahtarı (ilk 8 byte hex): {session_key.hex()[:16]}")
            return session_key
        else:
            print(f"{user_label} HATA: DH onayı alınamadı.")
            return None
    except Exception as e:
        print(f"{user_label} HATA: DH sırasında: {e}")
        return None

def send_command_and_get_response(sock, session_key, command_type, payload_dict, user_label="İstemci", expect_response=True, timeout=2.0):
    if not session_key:
        print(f"{user_label} HATA: Oturum anahtarı yok.")
        return None, None
    try:
        payload_str = json.dumps(payload_dict)
        encrypted_payload = encrypt_aes_gcm(session_key, payload_str)
        full_message_to_send = f"{command_type}:{encrypted_payload}\n"
        # print(f"{user_label} GÖNDERİYOR: {full_message_to_send.strip()[:70]}...")
        sock.sendall(full_message_to_send.encode('utf-8'))
        
        if not expect_response:
            return full_message_to_send.strip(), None # Ham gönderilen mesaj ve boş yanıt

        sock.settimeout(timeout) # Yanıt için bekleme süresi
        response_data = sock.recv(8192).strip() # Daha büyük yanıtlar için tamponu artır
        sock.settimeout(None) # Timeout'u sıfırla

        if response_data:
            raw_response = response_data.decode('utf-8')
            # print(f"{user_label} ALDI (HAM): {raw_response[:100]}")
            try:
                resp_command, resp_encrypted_blob = raw_response.split(":", 1)
                decrypted_str = decrypt_aes_gcm(session_key, resp_encrypted_blob)
                if decrypted_str:
                    return raw_response, json.loads(decrypted_str)
                else:
                    print(f"{user_label} UYARI: Yanıt deşifre edilemedi. Ham: {raw_response}")
            except Exception as e:
                print(f"{user_label} UYARI: Yanıt parse hatası: {e}. Ham: {raw_response}")
            return raw_response, None # Ham yanıt, çözülmemiş payload
        return None, None # Yanıt yok
    except socket.timeout:
        print(f"{user_label} HATA: Sunucudan yanıt alınamadı (timeout).")
        return None, None
    except Exception as e:
        print(f"{user_label} HATA: Gönderme/alma sırasında: {e}")
        return None, None


def signup_user(sock, session_key, username, password, user_label="İstemci"):
    _, resp_payload = send_command_and_get_response(
        sock, session_key, "SECURE_SIGNUP", {"username": username, "password": password}, user_label
    )
    if resp_payload and resp_payload.get("status") == "success":
        print(f"{user_label}: '{username}' kaydı başarılı.")
        return True
    print(f"{user_label}: '{username}' kaydı BAŞARISIZ. Yanıt: {resp_payload}")
    return False

def signin_user(sock, session_key, username, password, user_label="İstemci"):
    _, resp_payload = send_command_and_get_response(
        sock, session_key, "SECURE_SIGNIN", {"username": username, "password": password}, user_label
    )
    if resp_payload and resp_payload.get("status") == "success":
        print(f"{user_label}: '{username}' girişi başarılı.")
        return True
    print(f"{user_label}: '{username}' girişi BAŞARISIZ. Yanıt: {resp_payload}")
    return False

# --- Mallory'nin Özel Fonksiyonları ---
def mallory_request_snooped_data(mallory_sock, mallory_session_key):
    print(f"Mallory: Sunucudan sızdırılmış veri talebinde bulunuyor...")
    # SNOOP_REQUEST şifrelenmeden gönderiliyor, sunucu bunu özel olarak ele alacak
    mallory_sock.sendall(b"SNOOP_REQUEST\n")
    
    # Sunucunun yanıtı şifreli olacak
    _, response_payload = send_command_and_get_response(
        mallory_sock, mallory_session_key, "SNOOP_RESPONSE_EXPECTED", {}, user_label="Mallory", expect_response=True
    )
    # send_command_and_get_response SNOOP_RESPONSE_EXPECTED'i normal bir komut gibi işleyecektir.
    # Ancak sunucu SNOOP_REQUEST'e doğrudan SNOOP_RESPONSE ile yanıt verecek.
    # Bu nedenle, send_command_and_get_response'u kandırmak için sahte bir komut adı kullanabiliriz
    # veya SNOOP_REQUEST için ayrı bir gönderme/alma mantığı yazabiliriz.

    # Daha basit bir yaklaşım: SNOOP_REQUEST'i gönder, sonra doğrudan şifreli yanıtı al ve çöz.
    try:
        mallory_sock.settimeout(2.0)
        response_data = mallory_sock.recv(8192).strip() # Daha büyük veri için artır
        mallory_sock.settimeout(None)
        if response_data:
            raw_response = response_data.decode('utf-8')
            if raw_response.startswith("SNOOP_RESPONSE:"):
                _, encrypted_snoop_blob = raw_response.split(":", 1)
                decrypted_snoop_str = decrypt_aes_gcm(mallory_session_key, encrypted_snoop_blob)
                if decrypted_snoop_str:
                    snoop_payload = json.loads(decrypted_snoop_str)
                    if snoop_payload.get("status") == "success":
                        print(f"Mallory: Başarıyla {len(snoop_payload.get('snooped_data', []))} adet sızdırılmış veri aldı.")
                        return snoop_payload.get("snooped_data", [])
                    else:
                        print(f"Mallory: Sızdırılmış veri talebi başarısız: {snoop_payload.get('message')}")
                else:
                    print("Mallory: Sızdırılmış veri yanıtı deşifre edilemedi.")
            else:
                print(f"Mallory: Beklenmedik sızdırılmış veri yanıt formatı: {raw_response[:50]}")
        else:
            print("Mallory: Sızdırılmış veri için sunucudan yanıt alınamadı.")
    except socket.timeout:
        print("Mallory: Sızdırılmış veri talebi timeout.")
    except Exception as e:
        print(f"Mallory: Sızdırılmış veri alırken hata: {e}")
    return []

# --- Test Senaryoları ---

def test_scenario_impersonate_alice_to_bob(snooped_data, mallory_sock, mallory_session_key):
    print("\n--- Senaryo: Alice Adına Bob'a Mesaj Gönderme (Impersonation Denemesi) ---")
    # Mallory, kendi oturum anahtarıyla bir mesaj şifreler, ama payload'da göndericiyi Alice olarak göstermeye çalışır.
    # Sunucu, şifrelemeyi Mallory'nin anahtarıyla çözeceği için gerçek göndericinin Mallory olduğunu bilmeli.
    
    fake_sender_payload = {
        "sender": ALICE_USERNAME, # Sahte gönderici
        "to": BOB_USERNAME,
        "content": f"Bu mesaj güya Alice'ten Bob'a, ama Mallory gönderdi! - {time.time()}"
    }
    print(f"Mallory: Bob'a '{ALICE_USERNAME}' adına mesaj göndermeyi deniyor...")
    # Sunucu SECURE_MESSAGE komutunda sender alanını dikkate almamalı, kimliği doğrulanmış kullanıcıyı kullanmalı.
    send_command_and_get_response(mallory_sock, mallory_session_key, "SECURE_MESSAGE", fake_sender_payload, user_label="Mallory (Impersonating Alice)", expect_response=False)
    print("Impersonation mesajı gönderildi. Bob'un mesajı Mallory'den aldığını doğrulayın (sunucu logları veya Bob istemcisi).")
    print("BEKLENEN: Bob mesajı alırsa, gönderenin 'test_user_mallory' olması gerekir.")

def test_scenario_replay_alice_broadcast(snooped_data, mallory_sock, mallory_session_key):
    print("\n--- Senaryo: Alice'in Broadcast Mesajını Tekrar Oynatma ---")
    # Mallory, Alice'in orijinal şifreli broadcast mesajını bulup tekrar gönderir.
    
    alice_broadcast_blob = None
    for item in snooped_data:
        if item.get("type") == "raw_broadcast_from_client" and item.get("sender") == ALICE_USERNAME:
            alice_broadcast_blob = item.get("encrypted_blob_from_client")
            print(f"Mallory: Alice'in bir broadcast mesajını buldu: {alice_broadcast_blob[:50]}...")
            break
            
    if alice_broadcast_blob:
        replayed_message = f"BROADCAST:{alice_broadcast_blob}\n"
        print("Mallory: Alice'in orijinal şifreli broadcast mesajını TEKRAR gönderiyor...")
        mallory_sock.sendall(replayed_message.encode('utf-8')) # Kendi soketinden gönderiyor
        print("Replay broadcast gönderildi.")
        print("BEKLENEN (Mevcut Durumda - Replay Koruması Yoksa): Mesajın tekrar yayınlanması.")
        print("BEKLENEN (Replay Koruması Varsa): Sunucunun bu mesajı reddetmesi veya Mallory'nin anahtarıyla çözememesi.")
        # Eğer Mallory kendi soketinden gönderiyorsa, sunucu bunu Mallory'nin anahtarıyla çözmeye çalışır ve başarısız olur (InvalidTag).
        # Bu, "ağdan yakalayıp rastgele enjekte etme" senaryosuna daha yakın.
    else:
        print("Mallory: Alice'e ait sızdırılmış bir broadcast mesajı bulunamadı.")

def test_scenario_decrypt_alice_dm_to_bob(snooped_data, mallory_sock, mallory_session_key):
    print("\n--- Senaryo: Alice'in Bob'a Gönderdiği DM'i Deşifre Etme (Anahtarlar Sızdırılırsa) ---")
    
    alice_key_hex = None
    bob_key_hex = None # Bob'un anahtarı da gerekebilir, eğer sunucu Bob'a onun anahtarıyla şifreleyip gönderiyorsa.
                      # Bizim sızdırma mekanizmamızda alıcının anahtarı da var.
    
    dm_blob_for_bob = None
    original_dm_sender = None
    intended_dm_recipient = None
    recipient_actual_key_hex = None

    for item in snooped_data:
        if item.get("type") == "user_signin_session_key" and item.get("user") == ALICE_USERNAME:
            alice_key_hex = item.get("session_key_hex")
            print(f"Mallory: Alice'in oturum anahtarını sızdırdı (hex): {alice_key_hex[:16]}")
        if item.get("type") == "direct_message_encrypted_for_recipient":
            # Alice'in Bob'a gönderdiği ve Bob'un anahtarıyla şifrelenmiş mesajı bul
            if item.get("original_sender") == ALICE_USERNAME and item.get("intended_recipient") == BOB_USERNAME:
                dm_blob_for_bob = item.get("encrypted_blob_for_recipient")
                original_dm_sender = item.get("original_sender")
                intended_dm_recipient = item.get("intended_recipient")
                recipient_actual_key_hex = item.get("recipient_session_key_hex") # Bu Bob'un anahtarı olmalı
                print(f"Mallory: {original_dm_sender}'den {intended_dm_recipient}'e giden DM'in şifreli blob'unu buldu.")
                print(f"Bu mesaj için kullanılan alıcı ({BOB_USERNAME}) anahtarının bir kısmı (hex): {recipient_actual_key_hex}")
                break # İlk bulunanı alalım

    if dm_blob_for_bob and recipient_actual_key_hex:
        try:
            # Mallory'nin Bob'un oturum anahtarını bilmesi gerekiyor.
            # Bizim sızdırma mekanizmamız bu bilgiyi sağlıyor.
            bob_session_key_bytes = bytes.fromhex(recipient_actual_key_hex) # Tam anahtar sızdırılmış olmalı test_server'da
            decrypted_dm_str = decrypt_aes_gcm(bob_session_key_bytes, dm_blob_for_bob)
            if decrypted_dm_str:
                dm_payload = json.loads(decrypted_dm_str)
                print(f"Mallory BAŞARILI: Alice'in Bob'a gönderdiği DM'i DEŞİFRE ETTİ: {dm_payload.get('content')}")
            else:
                print("Mallory BAŞARISIZ: DM deşifre edilemedi (yanlış anahtar veya bozuk veri).")
        except Exception as e:
            print(f"Mallory BAŞARISIZ: DM deşifre ederken hata: {e}")
    else:
        print("Mallory: Alice'ten Bob'a sızdırılmış bir DM veya Bob'un anahtarı bulunamadı.")


# --- Ana Test Akışı ---
if __name__ == "__main__":
    print("Güvenlik Tester Başlatılıyor (TEST Sunucusuna Karşı)...")

    # 1. Alice'i hazırla (kayıt ol, giriş yap)
    alice_sock = create_socket_and_connect("Alice")
    alice_session_key = None
    if alice_sock:
        alice_session_key = perform_dh_exchange_for_tester(alice_sock, "Alice")
        if alice_session_key:
            if not signup_user(alice_sock, alice_session_key, ALICE_USERNAME, ALICE_PASSWORD, "Alice"):
                signin_user(alice_sock, alice_session_key, ALICE_USERNAME, ALICE_PASSWORD, "Alice") # Zaten kayıtlıysa giriş yap
        else:
            alice_sock.close()
            alice_sock = None
    
    # 2. Bob'u hazırla (kayıt ol, giriş yap)
    bob_sock = create_socket_and_connect("Bob")
    bob_session_key = None
    if bob_sock:
        bob_session_key = perform_dh_exchange_for_tester(bob_sock, "Bob")
        if bob_session_key:
            if not signup_user(bob_sock, bob_session_key, BOB_USERNAME, BOB_PASSWORD, "Bob"):
                signin_user(bob_sock, bob_session_key, BOB_USERNAME, BOB_PASSWORD, "Bob")
        else:
            bob_sock.close()
            bob_sock = None

    # 3. Mallory'i hazırla (kayıt ol, giriş yap)
    mallory_sock = create_socket_and_connect("Mallory")
    mallory_session_key = None
    if mallory_sock:
        mallory_session_key = perform_dh_exchange_for_tester(mallory_sock, "Mallory")
        if mallory_session_key:
            if not signup_user(mallory_sock, mallory_session_key, MALLORY_USERNAME, MALLORY_PASSWORD, "Mallory"):
                signin_user(mallory_sock, mallory_session_key, MALLORY_USERNAME, MALLORY_PASSWORD, "Mallory")
        else:
            mallory_sock.close()
            mallory_sock = None

    if not (alice_sock and bob_sock and mallory_sock and alice_session_key and bob_session_key and mallory_session_key):
        print("HATA: Tüm test istemcileri (Alice, Bob, Mallory) düzgün başlatılamadı. Testler iptal.")
        if alice_sock: alice_sock.close()
        if bob_sock: bob_sock.close()
        if mallory_sock: mallory_sock.close()
        sys.exit(1)

    print("\n--- Test Öncesi Hazırlık Tamamlandı. Alice, Bob ve Mallory bağlı ve giriş yapmış olmalı. ---")
    time.sleep(1) # Sunucunun işlemesi için

    # Alice bir broadcast yapsın ve Bob'a DM atsın (Mallory'nin sızdırması için veri oluşsun)
    print(f"\n{ALICE_USERNAME} test mesajları gönderiyor...")
    send_command_and_get_response(alice_sock, alice_session_key, "BROADCAST", {"content": f"Alice'ten herkese genel duyuru! - {time.time()}"}, "Alice", False)
    time.sleep(0.2)
    send_command_and_get_response(alice_sock, alice_session_key, "SECURE_MESSAGE", {"to": BOB_USERNAME, "content": f"Selam {BOB_USERNAME}, bu Alice'ten gizli bir mesaj. - {time.time()}"}, "Alice", False)
    time.sleep(1) # Sızdırılacak verilerin oluşması ve sunucunun işlemesi için

    # Mallory sızdırılmış verileri alsın
    snooped_data = []
    if mallory_sock and mallory_session_key:
        snooped_data = mallory_request_snooped_data(mallory_sock, mallory_session_key)
        if snooped_data:
            print("Sızdırılan bazı veriler:")
            for i, item in enumerate(snooped_data[:3]): # İlk 3 öğeyi göster
                print(f"  Item {i}: Type='{item.get('type')}', Sender='{item.get('sender', item.get('user', 'N/A'))}'")
        else:
            print("Mallory sunucudan sızdırılmış veri alamadı.")
    
    time.sleep(1)

    # Şimdi sızdırılmış verilerle saldırı senaryolarını çalıştır
    if mallory_sock and mallory_session_key:
        test_scenario_impersonate_alice_to_bob(snooped_data, mallory_sock, mallory_session_key)
        time.sleep(1)
        test_scenario_replay_alice_broadcast(snooped_data, mallory_sock, mallory_session_key)
        time.sleep(1)
        test_scenario_decrypt_alice_dm_to_bob(snooped_data, mallory_sock, mallory_session_key)

    # Bağlantıları kapat
    print("\nTestler tamamlanıyor, bağlantılar kapatılıyor...")
    if alice_sock: alice_sock.close()
    if bob_sock: bob_sock.close()
    if mallory_sock: mallory_sock.close()

    print("\nSecurity Tester Tamamlandı.")