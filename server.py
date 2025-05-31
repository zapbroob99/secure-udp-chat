# server.py
import socket
import threading
import json
import base64 # base64.b64encode'u session_key loglaması için ekledim.
from crypto_utils import (
    generate_dh_keys,
    serialize_public_key,
    derive_shared_key,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    hash_password,
    verify_password
)

HOST = '127.0.0.1'
PORT = 65432

# Basit bir kullanıcı veritabanı (gerçek uygulamada dosya/veritabanı olmalı)
# username: hashed_password
user_credentials = {}

# Aktif istemciler: conn: {"username": str, "session_key": bytes, "dh_private_key": DH_PrivKey}
clients = {} # client_socket -> { "username": str, "session_key": bytes, "address": tuple, "dh_private_key": DH_PrivKey}

def broadcast_message(message_content, sender_conn, sender_username):
    """Bir mesajı tüm bağlı ve kimliği doğrulanmış istemcilere yayınlar."""
    print(f"[BROADCAST] {sender_username} tarafından: {message_content[:30]}...")
    
    broadcast_payload = {
        "sender": sender_username,
        "content": message_content,
        "type": "broadcast"
    }
    payload_str = json.dumps(broadcast_payload)

    for client_socket, client_info in list(clients.items()):
        if client_socket != sender_conn and client_info.get("session_key") and client_info.get("username"):
            try:
                encrypted_payload = encrypt_aes_gcm(client_info["session_key"], payload_str)
                full_message = f"BROADCAST:{encrypted_payload}\n"
                client_socket.sendall(full_message.encode('utf-8'))
            except Exception as e:
                print(f"Yayın sırasında {client_info.get('username', 'Bilinmeyen')} istemcisine hata: {e}")
                remove_client(client_socket)

def send_direct_message(message_content, sender_conn, sender_username, recipient_username):
    """Belirli bir istemciye doğrudan mesaj gönderir."""
    print(f"[DIRECT] {sender_username} -> {recipient_username}: {message_content[:30]}...")
    
    recipient_socket = None
    recipient_session_key = None

    for sock, info in clients.items():
        if info.get("username") == recipient_username and info.get("session_key"):
            recipient_socket = sock
            recipient_session_key = info["session_key"]
            break
    
    if recipient_socket and recipient_session_key:
        direct_payload = {
            "sender": sender_username,
            "content": message_content,
            "type": "direct"
        }
        payload_str = json.dumps(direct_payload)
        try:
            encrypted_payload = encrypt_aes_gcm(recipient_session_key, payload_str)
            full_message = f"SECURE_MESSAGE:{encrypted_payload}\n"
            recipient_socket.sendall(full_message.encode('utf-8'))
        except Exception as e:
            print(f"Doğrudan mesaj gönderirken {recipient_username} istemcisine hata: {e}")
            remove_client(recipient_socket)
    else:
        try:
            error_payload_str = json.dumps({"error": f"User '{recipient_username}' not found or not authenticated."})
            sender_session_key = clients[sender_conn]["session_key"]
            encrypted_error = encrypt_aes_gcm(sender_session_key, error_payload_str)
            sender_conn.sendall(f"SERVER_ERROR:{encrypted_error}\n".encode('utf-8'))
        except Exception as e:
            print(f"Hata mesajı gönderirken {sender_username} istemcisine hata: {e}")


def remove_client(client_socket):
    """İstemciyi listeden kaldırır ve bağlantıyı kapatır."""
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
    clients[conn] = {"address": addr}

    try:
        server_dh_private_key, server_dh_public_key = generate_dh_keys()
        clients[conn]["dh_private_key"] = server_dh_private_key
        
        server_public_key_bytes_serialized = serialize_public_key(server_dh_public_key)
        
        conn.sendall(b"DH_INIT_SERVER_PUBKEY:" + base64.b64encode(server_public_key_bytes_serialized) + b"\n")
        print(f"[{addr}] Sunucu DH genel anahtarı gönderildi.")

        client_pubkey_data = conn.recv(2048).strip()
        if not client_pubkey_data.startswith(b"DH_CLIENT_PUBKEY:"):
            print(f"[{addr}] Geçersiz DH istemci genel anahtar formatı.")
            remove_client(conn)
            return
        
        client_public_key_b64 = client_pubkey_data[len(b"DH_CLIENT_PUBKEY:"):]
        client_public_key_bytes_serialized = base64.b64decode(client_public_key_b64)
        print(f"[{addr}] İstemci DH genel anahtarı alındı.")

        session_key = derive_shared_key(server_dh_private_key, client_public_key_bytes_serialized)
        clients[conn]["session_key"] = session_key
        print(f"[{addr}] Ortak oturum anahtarı başarıyla türetildi: {base64.b64encode(session_key).decode()[:10]}...")
        conn.sendall(b"DH_SUCCESS\n")

    except Exception as e:
        print(f"[{addr}] DH Anahtar değişimi sırasında hata: {e}")
        remove_client(conn)
        return

    authenticated_user = None
    # session_key zaten yukarıda bu bağlantı için ayarlandı ve clients[conn]["session_key"] içinde mevcut.

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break 
            
            messages = data.decode('utf-8').split('\n')
            for message_str in messages:
                if not message_str:
                    continue

                print(f"[{addr} - {authenticated_user if authenticated_user else 'Unauth'}] Ham mesaj alındı: {message_str[:100]}")

                try:
                    command, encrypted_blob = message_str.split(":", 1)
                except ValueError:
                    print(f"[{addr}] Geçersiz mesaj formatı: {message_str}")
                    error_payload = json.dumps({"error": "Invalid message format."})
                    if clients[conn].get("session_key"): # session_key varsa şifrele
                         encrypted_error = encrypt_aes_gcm(clients[conn]["session_key"], error_payload)
                         conn.sendall(f"SERVER_ERROR:{encrypted_error}\n".encode('utf-8'))
                    continue

                decrypted_payload_str = decrypt_aes_gcm(clients[conn]["session_key"], encrypted_blob)
                if not decrypted_payload_str:
                    print(f"[{addr}] Şifreli blob çözülemedi veya geçersiz.")
                    error_payload = json.dumps({"error": "Decryption failed or invalid data."})
                    if clients[conn].get("session_key"):
                        encrypted_error = encrypt_aes_gcm(clients[conn]["session_key"], error_payload)
                        conn.sendall(f"SERVER_ERROR:{encrypted_error}\n".encode('utf-8'))
                    continue
                
                print(f"[{addr} - {authenticated_user if authenticated_user else 'Unauth'}] Deşifrelenmiş payload: {decrypted_payload_str[:100]}")
                payload = json.loads(decrypted_payload_str)

                current_session_key = clients[conn]["session_key"] # Yanıtları şifrelemek için

                if command == "SECURE_SIGNUP":
                    username = payload.get("username")
                    password = payload.get("password")
                    if username and password:
                        if username in user_credentials:
                            response = {"status": "error", "message": "Username already exists."}
                        else:
                            user_credentials[username] = hash_password(password)
                            print(f"[SIGNUP DEBUG] Kullanıcı '{username}' kaydedildi. Hash: {user_credentials[username]}")
                            authenticated_user = username
                            clients[conn]["username"] = username
                            response = {"status": "success", "message": "Signup successful. You are now logged in."}
                            print(f"Kullanıcı '{username}' kaydoldu ve giriş yaptı.")
                        
                        encrypted_response = encrypt_aes_gcm(current_session_key, json.dumps(response))
                        conn.sendall(f"SECURE_SIGNUP_RESPONSE:{encrypted_response}\n".encode('utf-8'))
                    else:
                        response = {"status": "error", "message": "Username or password missing in signup."}
                        encrypted_response = encrypt_aes_gcm(current_session_key, json.dumps(response))
                        conn.sendall(f"SECURE_SIGNUP_RESPONSE:{encrypted_response}\n".encode('utf-8'))


                elif command == "SECURE_SIGNIN":
                    username = payload.get("username")
                    password = payload.get("password")

                    print(f"\n[SIGNIN DEBUG] Alınan - Kullanıcı: '{username}', Parola (ilk 3): '{password[:3] if password else ''}...'")
                    print(f"[SIGNIN DEBUG] user_credentials: {user_credentials}")

                    if username and password:
                        stored_hash = user_credentials.get(username)
                        print(f"[SIGNIN DEBUG] '{username}' için saklanan hash: {stored_hash}")

                        if stored_hash:
                            is_password_correct = verify_password(stored_hash, password)
                            print(f"[SIGNIN DEBUG] verify_password sonucu '{username}' için: {is_password_correct}")
                            if is_password_correct:
                                authenticated_user = username
                                clients[conn]["username"] = username
                                response = {"status": "success", "message": "Signin successful."}
                                print(f"Kullanıcı '{username}' giriş yaptı.")
                            else:
                                response = {"status": "error", "message": "Invalid username or password."}
                                print(f"[SIGNIN DEBUG HATA] Parola doğrulaması BAŞARISIZ: '{username}'")
                        else:
                            response = {"status": "error", "message": "Invalid username or password."} # Kullanıcı bulunamadı mesajını da bu kapsar.
                            print(f"[SIGNIN DEBUG HATA] Kullanıcı bulunamadı veya parola yanlış: '{username}'")
                        
                        encrypted_response = encrypt_aes_gcm(current_session_key, json.dumps(response))
                        conn.sendall(f"SECURE_SIGNIN_RESPONSE:{encrypted_response}\n".encode('utf-8'))
                    else:
                        response = {"status": "error", "message": "Username or password missing in signin."}
                        print("[SIGNIN DEBUG HATA] Kullanıcı adı veya parola eksik.")
                        encrypted_response = encrypt_aes_gcm(current_session_key, json.dumps(response))
                        conn.sendall(f"SECURE_SIGNIN_RESPONSE:{encrypted_response}\n".encode('utf-8'))


                elif command == "BROADCAST":
                    if authenticated_user:
                        message_content = payload.get("content")
                        if message_content:
                            broadcast_message(message_content, conn, authenticated_user)
                        else:
                            response = {"status": "error", "message": "Broadcast message content missing."}
                            encrypted_response = encrypt_aes_gcm(current_session_key, json.dumps(response))
                            conn.sendall(f"SERVER_RESPONSE:{encrypted_response}\n".encode('utf-8'))
                    else:
                        response = {"status": "error", "message": "Not authenticated. Sign in first."}
                        encrypted_response = encrypt_aes_gcm(current_session_key, json.dumps(response))
                        conn.sendall(f"SERVER_RESPONSE:{encrypted_response}\n".encode('utf-8'))

                elif command == "SECURE_MESSAGE":
                    if authenticated_user:
                        recipient_username = payload.get("to")
                        message_content = payload.get("content")
                        if recipient_username and message_content:
                            send_direct_message(message_content, conn, authenticated_user, recipient_username)
                        else:
                            response = {"status": "error", "message": "Recipient or message content missing for direct message."}
                            encrypted_response = encrypt_aes_gcm(current_session_key, json.dumps(response))
                            conn.sendall(f"SERVER_RESPONSE:{encrypted_response}\n".encode('utf-8'))
                    else:
                        response = {"status": "error", "message": "Not authenticated. Sign in first."}
                        encrypted_response = encrypt_aes_gcm(current_session_key, json.dumps(response))
                        conn.sendall(f"SERVER_RESPONSE:{encrypted_response}\n".encode('utf-8'))
                
                else:
                    print(f"[{addr}] Bilinmeyen komut: {command}")
                    response = {"status": "error", "message": f"Unknown command: {command}"}
                    encrypted_response = encrypt_aes_gcm(current_session_key, json.dumps(response))
                    conn.sendall(f"SERVER_RESPONSE:{encrypted_response}\n".encode('utf-8'))

    except ConnectionResetError:
        print(f"İstemci {addr} bağlantıyı aniden kapattı.")
    except BrokenPipeError: # Bazen ConnectionResetError yerine bu gelir
        print(f"İstemci {addr} ile bağlantı koptu (Broken Pipe).")
    except Exception as e:
        print(f"İstemci {addr} ({authenticated_user if authenticated_user else 'Unauth'}) ile iletişimde hata: {e}")
        import traceback
        traceback.print_exc() # Hatanın detaylarını görmek için
    finally:
        remove_client(conn)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"Sunucu {HOST}:{PORT} adresinde dinlemede...")
    try:
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\nSunucu kapatılıyor...")
    except Exception as e:
        print(f"Ana sunucu döngüsünde bir hata oluştu: {e}")
    finally:
        print("Tüm istemci bağlantıları kapatılıyor...")
        for client_socket_key in list(clients.keys()): # Kopyasını alarak iterasyon
            remove_client(client_socket_key)
        print("Soket kapatılıyor.")
        s.close()
        print("Sunucu başarıyla kapatıldı.")