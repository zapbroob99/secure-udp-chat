import socket
import threading
import json
import getpass
import base64
import time
import os
import traceback
from crypto_utils import (
    generate_dh_keys, serialize_public_key, derive_shared_key,
    encrypt_aes_gcm, decrypt_aes_gcm, # decrypt_aes_gcm artık sayaç döndürüyor
    load_signing_public_key_from_pem, verify_signature
)

HOST = '127.0.0.1'
PORT = 65432
SERVER_SIGNING_PUBLIC_KEY_FILE = "server_signing_public.pem"

server_signing_public_key = None
client_socket = None
session_key = None
is_authenticated = False
username_cache = None

# İstemci tarafı sayaçları
# Sunucuya giden mesajlar için istemcinin tuttuğu sayaç
outgoing_message_counter_to_server = 0
# Sunucudan gelen mesajlar için istemcinin beklediği bir sonraki sayaç
expected_incoming_message_counter_from_server = 0


def load_server_verification_key():
    # ... (Aynı kaldı) ...
    global server_signing_public_key
    if not os.path.exists(SERVER_SIGNING_PUBLIC_KEY_FILE):
        print(f"[HATA] Sunucu doğrulama anahtar dosyası ('{SERVER_SIGNING_PUBLIC_KEY_FILE}') bulunamadı.")
        return False
    try:
        with open(SERVER_SIGNING_PUBLIC_KEY_FILE, "rb") as f: pem_bytes = f.read()
        server_signing_public_key = load_signing_public_key_from_pem(pem_bytes)
        print(f"[BİLGİ] Sunucu doğrulama genel anahtarı '{SERVER_SIGNING_PUBLIC_KEY_FILE}' dosyasından yüklendi.")
        return True
    except Exception as e:
        print(f"[HATA] Sunucu doğrulama genel anahtarı yüklenemedi: {e}"); traceback.print_exc(); return False

def receive_messages(sock):
    global is_authenticated, expected_incoming_message_counter_from_server
    try:
        while True:
            data = sock.recv(4096)
            if not data: print("\nSunucu bağlantısı kesildi."); break
            
            messages = data.decode('utf-8').split('\n')
            for message_str in messages:
                if not message_str: continue
                print(f"\n[RAW]: {message_str[:100]}")
                try:
                    command, blob = message_str.split(":", 1)
                except ValueError: print(f"\n[HATA] Format: {message_str}"); continue
                
                if command == "DH_SUCCESS": # Şifresiz, sayaç yok
                    print("\n[BİLGİ] DH anahtar değişimi başarılı!"); continue
                
                current_session_key = session_key
                if not current_session_key: print("\n[HATA] Oturum anahtarı yok."); continue

                # Mesajı deşifre et ve sunucunun gönderdiği sayacı al
                decrypted_payload_str, received_server_counter = decrypt_aes_gcm(current_session_key, blob)
                
                if decrypted_payload_str is None:
                    print(f"\n[HATA] Mesaj çözülemedi (sunucu sayacı: {received_server_counter}): {command}"); continue
                
                # Tekrar oynatma saldırısı kontrolü
                if received_server_counter < expected_incoming_message_counter_from_server:
                    print(f"\n[HATA] Sunucudan tekrar oynatma/eski mesaj! "
                          f"Beklenen: {expected_incoming_message_counter_from_server}, Alınan: {received_server_counter}")
                    continue # Mesajı işleme
                
                expected_incoming_message_counter_from_server = received_server_counter + 1
                
                payload = json.loads(decrypted_payload_str)
                print(f"\n[DEŞİFRELİ (Sunucu Sayacı {received_server_counter})]: {command} - {payload}")


                if command in ["SECURE_SIGNUP_RESPONSE", "SECURE_SIGNIN_RESPONSE"]:
                    # ... (payload işleme aynı) ...
                    status, message = payload.get("status"), payload.get("message")
                    if status == "success": print(f"[BAŞARILI] {message}"); is_authenticated = True
                    else: print(f"[HATA] {message}"); is_authenticated = False
                elif command == "BROADCAST": print(f"[YAYIN] {payload.get('sender')}: {payload.get('content')}")
                elif command == "SECURE_MESSAGE": print(f"[ÖZEL] {payload.get('sender')}: {payload.get('content')}")
                elif command in ["SERVER_ERROR", "SERVER_RESPONSE"]: print(f"[SUNUCU] {payload.get('error', payload.get('message', 'Yanıt'))}")
                else: print(f"[BİLİNMEYEN] {command}: {payload}")
    except ConnectionResetError: print("\nSunucu bağlantıyı kapattı.")
    except BrokenPipeError: print("\nSunucu ile bağlantı koptu (Broken Pipe).")
    except Exception as e: print(f"\nMesaj alırken hata: {e}"); traceback.print_exc()
    finally:
        if client_socket: 
            try: client_socket.close()
            except: pass
        print("Bağlantı kapatıldı. Çıkmak için Enter.")

def send_secure_command(sock, command_type, payload_dict):
    global outgoing_message_counter_to_server
    current_session_key = session_key
    if not current_session_key: print("Oturum anahtarı yok."); return False
    
    # Giden mesaj sayacını kullan ve artır
    current_counter = outgoing_message_counter_to_server
    outgoing_message_counter_to_server += 1
    
    try:
        encrypted_payload = encrypt_aes_gcm(current_session_key, json.dumps(payload_dict), current_counter)
        sock.sendall(f"{command_type}:{encrypted_payload}\n".encode('utf-8'))
        return True
    except Exception as e:
        print(f"Mesaj gönderirken hata: {e}"); return False

def perform_dh_key_exchange(sock):
    # ... (DH kısmı aynı, sadece session_key atandıktan sonra sayaçları sıfırla) ...
    global session_key, outgoing_message_counter_to_server, expected_incoming_message_counter_from_server
    if not server_signing_public_key: print("[HATA] Sunucu doğrulama anahtarı yüklenmedi."); return False
    try:
        dh_init_full_data = sock.recv(4096).strip() # Boyut artırılabilir
        parts = dh_init_full_data.split(b":")
        if len(parts) != 3 or parts[0] != b"DH_INIT_SERVER_PUBKEY":
            print("Geçersiz DH başlatma mesaj formatı."); return False
            
        server_dh_public_key_bytes = base64.b64decode(parts[1])
        signature_bytes = base64.b64decode(parts[2])

        if not verify_signature(server_signing_public_key, signature_bytes, server_dh_public_key_bytes):
            print("[HATA] Sunucu imzası GEÇERSİZ!"); return False
        print("[BİLGİ] Sunucu imzası doğrulandı.")

        client_dh_private_key, client_dh_public_key = generate_dh_keys()
        client_public_key_bytes = serialize_public_key(client_dh_public_key)
        sock.sendall(b"DH_CLIENT_PUBKEY:" + base64.b64encode(client_public_key_bytes) + b"\n")
        print("[BİLGİ] İstemci DH genel anahtarı gönderildi.")

        session_key = derive_shared_key(client_dh_private_key, server_dh_public_key_bytes) # Global session_key atanıyor
        print(f"[BİLGİ] Oturum anahtarı türetildi.")
        
        confirmation = sock.recv(1024).strip()
        if confirmation == b"DH_SUCCESS":
            print("[BİLGİ] DH başarı onayı alındı.")
            # DH başarılı, sayaçları sıfırla/başlat
            outgoing_message_counter_to_server = 0
            expected_incoming_message_counter_from_server = 0
            return True
        else:
            print(f"[HATA] DH onayı alınamadı: {confirmation.decode()}"); session_key = None; return False
    except Exception as e:
        print(f"DH sırasında hata: {e}"); traceback.print_exc(); session_key = None; return False


def main():
    # ... (main fonksiyonunun başı aynı) ...
    global client_socket, is_authenticated, username_cache
    if not load_server_verification_key(): print("İstemci başlatılamıyor."); return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT)); print(f"{HOST}:{PORT} adresine bağlanıldı.")
        if not perform_dh_key_exchange(client_socket):
            print("Anahtar değişimi/Sunucu doğrulaması başarısız. Çıkılıyor."); client_socket.close(); return
        
        threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

        while True:
            if not is_authenticated:
                # ... (Giriş/kayıt kısmı aynı, send_secure_command zaten sayaç kullanıyor) ...
                action = input("Giriş ('signin'), Kayıt ('signup'), Çıkış ('exit'): ").strip().lower()
                if action == "exit": break
                elif action == "signup":
                    username = input("Kullanıcı adı: "); pw = getpass.getpass("Parola: "); cpw = getpass.getpass("Parola (tekrar): ")
                    if not username or not pw: print("Alanlar boş olamaz."); continue
                    if pw != cpw: print("Parolalar eşleşmiyor."); continue
                    if send_secure_command(client_socket, "SECURE_SIGNUP", {"username": username, "password": pw}):
                        username_cache = username; time.sleep(0.2); continue 
                elif action == "signin":
                    username = input("Kullanıcı adı: "); pw = getpass.getpass("Parola: ")
                    if not username or not pw: print("Alanlar boş olamaz."); continue
                    if send_secure_command(client_socket, "SECURE_SIGNIN", {"username": username, "password": pw}):
                        username_cache = username; time.sleep(0.2); continue
                else: print("Geçersiz komut.")
            else:
                # ... (Mesaj gönderme kısmı aynı, send_secure_command zaten sayaç kullanıyor) ...
                user_input = input(f"[{username_cache}] ('broadcast msg' / 'dm user msg' / 'logout' / 'exit'): ").strip()
                if user_input.lower() == "exit": break
                if user_input.lower() == "logout": is_authenticated=False; username_cache=None; print("Oturum kapatıldı."); continue
                parts = user_input.split(" ", 2); cmd = parts[0].lower()
                if cmd == "broadcast" and len(parts) >= 2: send_secure_command(client_socket, "BROADCAST", {"content": " ".join(parts[1:])})
                elif cmd == "dm" and len(parts) == 3: send_secure_command(client_socket, "SECURE_MESSAGE", {"to": parts[1], "content": parts[2]})
                else: print("Geçersiz format.")
    except ConnectionRefusedError: print(f"{HOST}:{PORT} bağlanılamadı.")
    except KeyboardInterrupt: print("\nİstemci kapatılıyor...")
    except Exception as e: print(f"Ana döngüde hata: {e}"); traceback.print_exc()
    finally:
        if client_socket: 
            try: client_socket.close()
            except: pass
        print("İstemci sonlandırıldı.")

if __name__ == "__main__":
    main()