import socket
import threading
import json
import base64
import os
import traceback
from crypto_utils import (
    generate_dh_keys, serialize_public_key, derive_shared_key,
    encrypt_aes_gcm, decrypt_aes_gcm,  # decrypt_aes_gcm artık sayaç döndürüyor
    hash_password, verify_password,
    generate_signing_keys, sign_data, serialize_signing_public_key_pem,
    load_signing_private_key_from_pem, serialize_signing_private_key_pem
)

HOST = '127.0.0.1'
PORT = 65432

SERVER_SIGNING_PRIVATE_KEY_FILE = "server_signing_private.pem"
SERVER_SIGNING_PUBLIC_KEY_FILE = "server_signing_public.pem"
SERVER_SIGNING_KEY_PASSWORD = None
server_signing_private_key = None

user_credentials = {}
# clients sözlüğü artık sayaçları da tutacak:
# client_socket -> { ..., "outgoing_message_counter": int, "expected_incoming_message_counter": int }
clients = {}

# --- Anahtar Yönetimi ---
def load_or_generate_server_signing_keys():
    # ... (Bu fonksiyon bir önceki yanıttaki gibi kalacak, değişiklik yok) ...
    global server_signing_private_key
    if os.path.exists(SERVER_SIGNING_PRIVATE_KEY_FILE):
        try:
            with open(SERVER_SIGNING_PRIVATE_KEY_FILE, "rb") as f: pem_data = f.read()
            server_signing_private_key = load_signing_private_key_from_pem(pem_data, SERVER_SIGNING_KEY_PASSWORD)
            print(f"Sunucu imzalama özel anahtarı '{SERVER_SIGNING_PRIVATE_KEY_FILE}' dosyasından yüklendi.")
            if not os.path.exists(SERVER_SIGNING_PUBLIC_KEY_FILE):
                print(f"Uyarı: '{SERVER_SIGNING_PUBLIC_KEY_FILE}' bulunamadı, yeniden oluşturuluyor...")
                public_key = server_signing_private_key.public_key()
                with open(SERVER_SIGNING_PUBLIC_KEY_FILE, "wb") as f: f.write(serialize_signing_public_key_pem(public_key))
                print(f"Sunucu imzalama genel anahtarı '{SERVER_SIGNING_PUBLIC_KEY_FILE}' dosyasına kaydedildi.")
        except Exception as e:
            print(f"'{SERVER_SIGNING_PRIVATE_KEY_FILE}' yüklenirken hata: {e}. Yeni anahtar üretilecek.")
            server_signing_private_key = None
    if not server_signing_private_key:
        print(f"Yeni sunucu imzalama anahtar çifti üretiliyor...")
        try:
            priv_key, pub_key = generate_signing_keys()
            server_signing_private_key = priv_key
            with open(SERVER_SIGNING_PRIVATE_KEY_FILE, "wb") as f: f.write(serialize_signing_private_key_pem(priv_key, SERVER_SIGNING_KEY_PASSWORD))
            print(f"Sunucu imzalama özel anahtarı '{SERVER_SIGNING_PRIVATE_KEY_FILE}' dosyasına kaydedildi.")
            with open(SERVER_SIGNING_PUBLIC_KEY_FILE, "wb") as f: f.write(serialize_signing_public_key_pem(pub_key))
            print(f"Sunucu imzalama genel anahtarı '{SERVER_SIGNING_PUBLIC_KEY_FILE}' dosyasına kaydedildi.")
        except Exception as e:
            print(f"Yeni imzalama anahtarları üretilirken/kaydedilirken hata: {e}"); traceback.print_exc(); return False
    return True

# --- Yardımcı Fonksiyon: İstemciye Güvenli Mesaj Gönderme ---
def send_encrypted_message_to_client(client_socket, command_type, payload_dict):
    client_info = clients.get(client_socket)
    if not client_info or "session_key" not in client_info:
        print(f"Hata: {client_info.get('address') if client_info else 'Bilinmeyen istemci'} için oturum anahtarı yok.")
        return False
    
    session_key = client_info["session_key"]
    # Giden mesaj sayacını al ve artır
    message_counter = client_info.get("outgoing_message_counter", 0)
    client_info["outgoing_message_counter"] = message_counter + 1
    
    try:
        payload_str = json.dumps(payload_dict)
        encrypted_payload = encrypt_aes_gcm(session_key, payload_str, message_counter)
        full_message = f"{command_type}:{encrypted_payload}\n"
        client_socket.sendall(full_message.encode('utf-8'))
        return True
    except Exception as e:
        print(f"Şifreli mesaj gönderirken hata ({client_info.get('username', 'Unauth')}): {e}")
        remove_client(client_socket) # Gönderim hatası ciddi bir sorun olabilir
        return False

# --- Mesajlaşma Fonksiyonları (send_encrypted_message_to_client kullanacak şekilde güncellendi) ---
def broadcast_message(message_content, sender_conn, sender_username):
    print(f"[BROADCAST] {sender_username} tarafından: {message_content[:30]}...")
    broadcast_payload = {"sender": sender_username, "content": message_content, "type": "broadcast"}
    for client_socket, client_info in list(clients.items()):
        if client_socket != sender_conn and client_info.get("session_key") and client_info.get("username"):
            send_encrypted_message_to_client(client_socket, "BROADCAST", broadcast_payload)

def send_direct_message(message_content, sender_conn, sender_username, recipient_username):
    print(f"[DIRECT] {sender_username} -> {recipient_username}: {message_content[:30]}...")
    recipient_socket = None
    for sock, info in clients.items():
        if info.get("username") == recipient_username and info.get("session_key"):
            recipient_socket = sock
            break
    
    direct_payload = {"sender": sender_username, "content": message_content, "type": "direct"}
    if recipient_socket:
        send_encrypted_message_to_client(recipient_socket, "SECURE_MESSAGE", direct_payload)
    else:
        error_payload = {"error": f"User '{recipient_username}' not found or not authenticated."}
        send_encrypted_message_to_client(sender_conn, "SERVER_ERROR", error_payload)


def remove_client(client_socket):
    # ... (Aynı kaldı) ...
    if client_socket in clients:
        username = clients[client_socket].get("username", "Bilinmeyen")
        address_info = clients[client_socket].get('address', 'Adres Yok')
        print(f"İstemci {username} ({address_info}) bağlantısı kesildi.")
        del clients[client_socket]
    try:
        client_socket.close()
    except Exception:
        pass

def handle_client(conn, addr):
    print(f"Yeni bağlantı: {addr}")
    # Sayaçları başlat
    clients[conn] = {
        "address": addr,
        "outgoing_message_counter": 0, # Sunucudan istemciye giden mesajlar için
        "expected_incoming_message_counter": 0 # İstemciden sunucuya gelen mesajlar için
    }

    # DH ve Sunucu Kimlik Doğrulama
    try:
        # ... (DH ve imzalama kısmı aynı, sadece conn.sendall yerine send_encrypted_message_to_client kullanılmayacak
        #     çünkü bu ilk mesajlar henüz oturum anahtarı olmadan gidiyor. DH_SUCCESS mesajı da şifresiz.) ...
        server_dh_private_key, server_dh_public_key = generate_dh_keys()
        clients[conn]["dh_private_key"] = server_dh_private_key
        server_dh_public_key_bytes_serialized = serialize_public_key(server_dh_public_key)
        
        if not server_signing_private_key:
            print(f"[{addr}] Sunucu imzalama anahtarı yüklenmemiş. Bağlantı reddediliyor.")
            conn.sendall(b"SERVER_ERROR:KEY_ERROR\n")
            remove_client(conn)
            return
            
        signature_on_dh_pubkey = sign_data(server_signing_private_key, server_dh_public_key_bytes_serialized)
        message_to_client = b"DH_INIT_SERVER_PUBKEY:" + \
                            base64.b64encode(server_dh_public_key_bytes_serialized) + \
                            b":" + \
                            base64.b64encode(signature_on_dh_pubkey) + \
                            b"\n"
        conn.sendall(message_to_client)
        print(f"[{addr}] Sunucu DH genel anahtarı ve imzası gönderildi.")

        client_pubkey_data = conn.recv(2048).strip()
        if not client_pubkey_data.startswith(b"DH_CLIENT_PUBKEY:"):
            print(f"[{addr}] Geçersiz DH istemci genel anahtar formatı.")
            remove_client(conn)
            return
        
        client_public_key_b64 = client_pubkey_data[len(b"DH_CLIENT_PUBKEY:"):]
        client_public_key_bytes_serialized = base64.b64decode(client_public_key_b64)
        print(f"[{addr}] İstemci DH genel anahtarı alındı.")

        session_key = derive_shared_key(server_dh_private_key, client_public_key_bytes_serialized)
        clients[conn]["session_key"] = session_key # Oturum anahtarı burada atanıyor
        print(f"[{addr}] Ortak oturum anahtarı başarıyla türetildi.")
        conn.sendall(b"DH_SUCCESS\n") # Bu şifresiz bir onay mesajı

    except Exception as e:
        print(f"[{addr}] DH/Kimlik Doğrulama sırasında hata: {e}"); traceback.print_exc(); remove_client(conn); return

    authenticated_user = None
    client_info = clients[conn] # Kolay erişim için

    try:
        while True:
            data = conn.recv(4096)
            if not data: break 
            
            messages = data.decode('utf-8').split('\n')
            for message_str in messages:
                if not message_str: continue
                print(f"[{addr} - {authenticated_user or 'Unauth'}] Ham: {message_str[:100]}")
                
                try:
                    command, encrypted_blob = message_str.split(":", 1)
                except ValueError:
                    print(f"[{addr}] Geçersiz format: {message_str}")
                    send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Invalid message format."})
                    continue

                # Mesajı deşifre et ve mesaj sayacını al
                decrypted_payload_str, received_counter = decrypt_aes_gcm(client_info["session_key"], encrypted_blob)
                
                if decrypted_payload_str is None: # Deşifreleme başarısız
                    print(f"[{addr}] Şifre çözme başarısız veya geçersiz sayaç (-1).")
                    send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Decryption/counter extraction failed."})
                    continue

                # Tekrar oynatma saldırısı kontrolü
                expected_counter = client_info["expected_incoming_message_counter"]
                if received_counter < expected_counter : # Sıkı kontrol, sadece büyük veya eşit kabul edilebilir
                                                           # Eğer arada kaybolan mesajlara izin vermek istiyorsanız:
                                                           # if received_counter < expected_counter: (veya <=)
                    print(f"[{addr}] Tekrar oynatma saldırısı veya eski mesaj tespit edildi! "
                          f"Beklenen sayaç: {expected_counter}, Alınan sayaç: {received_counter}")
                    send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Replay attack or old message detected."})
                    continue # Mesajı işleme
                
                # Sayaç geçerliyse, beklenen bir sonraki sayacı güncelle
                client_info["expected_incoming_message_counter"] = received_counter + 1
                
                print(f"[{addr} - {authenticated_user or 'Unauth'}] Deşifreli (Sayaç {received_counter}): {decrypted_payload_str[:100]}")
                payload = json.loads(decrypted_payload_str)

                if command == "SECURE_SIGNUP":
                    # ... (İçerik aynı, sadece yanıt send_encrypted_message_to_client ile gönderilecek) ...
                    username = payload.get("username"); password = payload.get("password")
                    response_payload = {}
                    if username and password:
                        if username in user_credentials:
                            response_payload = {"status": "error", "message": "Username already exists."}
                        else:
                            user_credentials[username] = hash_password(password)
                            authenticated_user = username
                            client_info["username"] = username
                            response_payload = {"status": "success", "message": "Signup successful. Logged in."}
                            print(f"Kullanıcı '{username}' kaydoldu ve giriş yaptı.")
                    else: response_payload = {"status": "error", "message": "Username or password missing."}
                    send_encrypted_message_to_client(conn, "SECURE_SIGNUP_RESPONSE", response_payload)

                elif command == "SECURE_SIGNIN":
                    # ... (İçerik aynı, sadece yanıt send_encrypted_message_to_client ile gönderilecek) ...
                    username = payload.get("username"); password = payload.get("password")
                    response_payload = {}
                    if username and password:
                        stored_hash = user_credentials.get(username)
                        if stored_hash and verify_password(stored_hash, password):
                            authenticated_user = username
                            client_info["username"] = username
                            response_payload = {"status": "success", "message": "Signin successful."}
                            print(f"Kullanıcı '{username}' giriş yaptı.")
                        else: response_payload = {"status": "error", "message": "Invalid username or password."}
                    else: response_payload = {"status": "error", "message": "Username or password missing."}
                    send_encrypted_message_to_client(conn, "SECURE_SIGNIN_RESPONSE", response_payload)
                
                elif command == "BROADCAST":
                    if authenticated_user:
                        message_content = payload.get("content")
                        if message_content: broadcast_message(message_content, conn, authenticated_user)
                        else: send_encrypted_message_to_client(conn, "SERVER_RESPONSE", {"status": "error", "message": "Broadcast content missing."})
                    else: send_encrypted_message_to_client(conn, "SERVER_RESPONSE", {"status": "error", "message": "Not authenticated."})
                
                elif command == "SECURE_MESSAGE":
                    if authenticated_user:
                        recipient = payload.get("to"); message_content = payload.get("content")
                        if recipient and message_content: send_direct_message(message_content, conn, authenticated_user, recipient)
                        else: send_encrypted_message_to_client(conn, "SERVER_RESPONSE", {"status": "error", "message": "Recipient or content missing."})
                    else: send_encrypted_message_to_client(conn, "SERVER_RESPONSE", {"status": "error", "message": "Not authenticated."})
                else:
                    send_encrypted_message_to_client(conn, "SERVER_RESPONSE", {"status": "error", "message": f"Unknown command: {command}"})
    
    except ConnectionResetError: print(f"İstemci {addr} bağlantıyı aniden kapattı.")
    except BrokenPipeError: print(f"İstemci {addr} ile bağlantı koptu (Broken Pipe).")
    except Exception as e: print(f"İstemci {addr} ({authenticated_user or 'Unauth'}) ile iletişimde hata: {e}"); traceback.print_exc()
    finally: remove_client(conn)

if __name__ == "__main__":
    if not load_or_generate_server_signing_keys(): print("Sunucu başlatılamıyor."); exit()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT)); s.listen()
        print(f"Sunucu {HOST}:{PORT} adresinde dinlemede...")
        try:
            while True:
                conn, addr = s.accept()
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt: print("\nSunucu kapatılıyor...")
        except Exception as e: print(f"Ana döngüde hata: {e}"); traceback.print_exc()
        finally:
            print("Tüm istemci bağlantıları kapatılıyor..."); 
            for sock_key in list(clients.keys()): remove_client(sock_key)
            s.close(); print("Sunucu başarıyla kapatıldı.")