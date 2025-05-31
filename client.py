# client.py
import socket
import threading
import json
import getpass # Parolayı gizli girmek için
import base64
import time
from crypto_utils import (
    generate_dh_keys,
    serialize_public_key,
    derive_shared_key,
    encrypt_aes_gcm,
    decrypt_aes_gcm
)

HOST = '127.0.0.1'
PORT = 65432
client_socket = None
session_key = None # Bu istemciye özel oturum anahtarı
is_authenticated = False
username_cache = None # Giriş yapıldıktan sonra kullanıcı adını tutar

def receive_messages(sock):
    """Sunucudan gelen mesajları dinler ve ekrana basar."""
    global is_authenticated
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                print("\nSunucu bağlantısı kesildi.")
                break
            
            messages = data.decode('utf-8').split('\n')
            for message_str in messages:
                if not message_str:
                    continue

                print(f"\n[SUNUCUDAN RAW]: {message_str[:100]}") # Debug için

                try:
                    command, encrypted_blob = message_str.split(":", 1)
                except ValueError:
                    print(f"\n[HATA] Sunucudan geçersiz format: {message_str}")
                    continue
                
                if command == "DH_SUCCESS": # Bu şifrelenmemiş bir kontrol mesajı
                    print("\n[BİLGİ] Diffie-Hellman anahtar değişimi başarılı!")
                    continue # Bu mesajın deşifrelenmesine gerek yok
                
                if command.startswith("DH_INIT_SERVER_PUBKEY"): # Bu da şifrelenmemiş
                    # Bu mesaj normalde handle_server_init'te işlenir, receive_messages'a gelmemeli.
                    # Ama gelirse diye loglayalım.
                    print(f"\n[DEBUG] DH_INIT_SERVER_PUBKEY beklenmedik bir şekilde alındı: {command}")
                    continue

                # Diğer tüm mesajlar şifreli olmalı
                if not session_key:
                    print("\n[HATA] Oturum anahtarı henüz oluşturulmadı, mesaj çözülemiyor.")
                    continue

                decrypted_payload_str = decrypt_aes_gcm(session_key, encrypted_blob)
                if not decrypted_payload_str:
                    print(f"\n[HATA] Sunucudan gelen mesaj çözülemedi: {command}")
                    continue
                
                payload = json.loads(decrypted_payload_str)
                # print(f"\n[SUNUCUDAN DEŞİFRELİ PAYLOAD]: {payload}") # Debug için

                if command == "SECURE_SIGNUP_RESPONSE" or command == "SECURE_SIGNIN_RESPONSE":
                    status = payload.get("status")
                    message = payload.get("message")
                    if status == "success":
                        print(f"\n[BAŞARILI] {message}")
                        is_authenticated = True
                        # Kullanıcı adını global değişkene ata (sign_in veya sign_up'tan sonra)
                        # Bu bilgi zaten `username_cache` içinde olmalı.
                    else:
                        print(f"\n[HATA] {message}")
                        is_authenticated = False
                
                elif command == "BROADCAST":
                    sender = payload.get("sender")
                    content = payload.get("content")
                    print(f"\n[YAYIN MESAJI] {sender}: {content}")
                
                elif command == "SECURE_MESSAGE":
                    sender = payload.get("sender")
                    content = payload.get("content")
                    print(f"\n[ÖZEL MESAJ] {sender}: {content}")

                elif command == "SERVER_ERROR" or command == "SERVER_RESPONSE": # Sunucudan gelen genel hatalar/yanıtlar
                    error_msg = payload.get("error", payload.get("message", "Bilinmeyen sunucu yanıtı"))
                    print(f"\n[SUNUCU YANITI/HATASI] {error_msg}")
                
                else:
                    print(f"\n[BİLİNMEYEN SUNUCU KOMUTU] {command}: {payload}")

    except ConnectionResetError:
        print("\nSunucu bağlantıyı kapattı.")
    except Exception as e:
        print(f"\nMesaj alırken hata: {e}")
    finally:
        if client_socket:
            client_socket.close()
        print("Bağlantı kapatıldı. Çıkmak için Enter'a basın.")


def send_secure_command(sock, command_type, payload_dict):
    """Verilen komut ve payload'u şifreleyip sunucuya gönderir."""
    if not session_key:
        print("Oturum anahtarı yok. Mesaj gönderilemiyor.")
        return False
    try:
        payload_str = json.dumps(payload_dict)
        encrypted_payload = encrypt_aes_gcm(session_key, payload_str)
        full_message = f"{command_type}:{encrypted_payload}\n"
        sock.sendall(full_message.encode('utf-8'))
        return True
    except Exception as e:
        print(f"Mesaj gönderirken hata: {e}")
        return False

def perform_dh_key_exchange(sock):
    """Sunucu ile Diffie-Hellman anahtar değişimini gerçekleştirir."""
    global session_key
    try:
        # Sunucudan DH başlatma mesajını ve genel anahtarını al
        dh_init_data = sock.recv(2048).strip()
        if not dh_init_data.startswith(b"DH_INIT_SERVER_PUBKEY:"):
            print("Geçersiz DH başlatma mesajı alındı.")
            return False
        
        server_public_key_b64 = dh_init_data[len(b"DH_INIT_SERVER_PUBKEY:"):]
        server_public_key_bytes = base64.b64decode(server_public_key_b64)
        print("[BİLGİ] Sunucu DH genel anahtarı alındı.")

        # İstemci DH anahtarlarını üret
        client_dh_private_key, client_dh_public_key = generate_dh_keys()
        client_public_key_bytes = serialize_public_key(client_dh_public_key)

        # İstemci genel anahtarını sunucuya gönder
        sock.sendall(b"DH_CLIENT_PUBKEY:" + base64.b64encode(client_public_key_bytes) + b"\n")
        print("[BİLGİ] İstemci DH genel anahtarı sunucuya gönderildi.")

        # Ortak gizli anahtarı türet
        session_key = derive_shared_key(client_dh_private_key, server_public_key_bytes)
        print(f"[BİLGİ] Ortak oturum anahtarı başarıyla türetildi: {base64.b64encode(session_key).decode()[:10]}...")
        
        # Sunucudan DH başarı onayını bekle
        confirmation = sock.recv(1024).strip()
        if confirmation == b"DH_SUCCESS":
            print("[BİLGİ] Sunucudan DH başarı onayı alındı.")
            return True
        else:
            print(f"[HATA] DH başarı onayı alınamadı, alınan: {confirmation.decode()}")
            session_key = None # Başarısız olursa anahtarı sıfırla
            return False

    except Exception as e:
        print(f"DH Anahtar değişimi sırasında hata: {e}")
        session_key = None
        return False

def main():
    global client_socket, is_authenticated, username_cache
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
        print(f"{HOST}:{PORT} adresine bağlanıldı.")

        # 1. Diffie-Hellman Anahtar Değişimi
        if not perform_dh_key_exchange(client_socket):
            print("Anahtar değişimi başarısız. Çıkılıyor.")
            client_socket.close()
            return
        
        # Anahtar değişimi başarılı ise mesaj alma thread'ini başlat
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket,), daemon=True)
        receive_thread.start()

        while True:
            if not is_authenticated:
                action = input("Giriş yapmak için 'signin', kaydolmak için 'signup', çıkmak için 'exit' yazın: ").strip().lower()
                if action == "exit":
                    break
                elif action == "signup":
                    username = input("Kullanıcı adı: ")
                    password = getpass.getpass("Parola: ") # Parolayı gizli al
                    confirm_password = getpass.getpass("Parola (tekrar): ")
                    if password != confirm_password:
                        print("Parolalar eşleşmiyor.")
                        continue
                    payload = {"username": username, "password": password}
                    username_cache = username # Yanıt gelene kadar tut
                    if send_secure_command(client_socket, "SECURE_SIGNUP", payload):
                        time.sleep(0.15)
                        continue
                elif action == "signin":
                    username = input("Kullanıcı adı: ")
                    password = getpass.getpass("Parola: ")
                    payload = {"username": username, "password": password}
                    username_cache = username
                    if send_secure_command(client_socket, "SECURE_SIGNIN", payload):
                        time.sleep(0.15)
                        continue
                    

                else:
                    print("Geçersiz komut.")
            else: # Kimlik doğrulandıysa
                prompt = f"[{username_cache}] Mesaj ('broadcast mesajınız' / 'dm alıcı_adı mesajınız' / 'logout' / 'exit'): "
                user_input = input(prompt).strip()
                if user_input.lower() == "exit":
                    break
                if user_input.lower() == "logout":
                    is_authenticated = False
                    username_cache = None
                    print("Oturum kapatıldı.")
                    # Sunucuya bir logout mesajı göndermek iyi bir pratik olabilir ama bu örnekte yok.
                    continue

                parts = user_input.split(" ", 2) # 'dm alıcı mesaj' için 3 parça
                command = parts[0].lower()

                if command == "broadcast" and len(parts) > 1:
                    message_content = " ".join(parts[1:]) # Birden fazla kelime varsa birleştir
                    payload = {"content": message_content}
                    send_secure_command(client_socket, "BROADCAST", payload)
                elif command == "dm" and len(parts) > 2:
                    recipient = parts[1]
                    message_content = parts[2]
                    payload = {"to": recipient, "content": message_content}
                    send_secure_command(client_socket, "SECURE_MESSAGE", payload)
                else:
                    print("Geçersiz mesaj formatı. Örnekler:\n  broadcast Herkese merhaba\n  dm kullanici_b Nasılsın?")
            
            # Sunucudan yanıt gelmesi için kısa bir bekleme (isteğe bağlı, UI'ı daha akıcı yapabilir)
            # import time
            # time.sleep(0.1)

    except ConnectionRefusedError:
        print(f"{HOST}:{PORT} adresine bağlanılamadı. Sunucu çalışıyor mu?")
    except KeyboardInterrupt:
        print("\nİstemci kapatılıyor...")
    except Exception as e:
        print(f"Ana istemci döngüsünde bir hata oluştu: {e}")
    finally:
        if client_socket:
            print("Bağlantı sonlandırılıyor.")
            client_socket.close()

if __name__ == "__main__":
    main()