# test_server.py
import socket
import threading
import json
import base64
import os
import time # os.urandom için

# Orijinal server.py'den crypto_utils importları
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
PORT = 65432 # Test için farklı bir port da kullanabilirsiniz, karışmaması için. Ama aynı da olabilir.

user_credentials = {}
clients = {} # client_socket -> { "username": str, "session_key": bytes, "address": tuple, ...}

# --- TEST İÇİN SIZDIRMA MEKANİZMASI ---
# Mallory'nin (test_user_mallory) erişebileceği sızdırılmış bilgiler
snooped_data_for_mallory = []
# snooped_data_for_mallory listesi şu formatta girdiler içerebilir:
# {"type": "session_key", "user": "alice", "key_hex": "...", "timestamp": ...}
# {"type": "sent_message", "sender": "alice", "recipient": "bob"/"BROADCAST", "encrypted_blob": "...", "timestamp": ...}

MALLORY_USERNAME = "test_user_mallory" # Mallory için özel kullanıcı adı
# --- TEST İÇİN SIZDIRMA MEKANİZMASI SONU ---


def broadcast_message(message_content, sender_conn, sender_username):
    print(f"[BROADCAST by {sender_username}]: {message_content[:30]}...")
    broadcast_payload = {
        "sender": sender_username,
        "content": message_content,
        "type": "broadcast"
    }
    payload_str = json.dumps(broadcast_payload)

    # --- TEST İÇİN SIZDIRMA ---
    if sender_username != MALLORY_USERNAME:
        # Mallory dışındaki bir kullanıcı broadcast yapıyorsa, bu bilgiyi sızdır
        encrypted_blob_for_snoop = encrypt_aes_gcm(clients[sender_conn]["session_key"], payload_str) # Bu zaten istemcinin gönderdiği olacak
        snooped_data_for_mallory.append({
            "type": "broadcast_sent",
            "sender": sender_username,
            "session_key_hex": clients[sender_conn]["session_key"].hex()[:16], # Sadece bir kısmı
            "decrypted_payload_str_preview": payload_str[:50], # Deşifrelenmiş mesajın önizlemesi
            "timestamp": time.time()
        })
    # --- TEST İÇİN SIZDIRMA SONU ---

    for client_socket, client_info in list(clients.items()):
        if client_socket != sender_conn and client_info.get("session_key") and client_info.get("username"):
            try:
                # Her alıcı için kendi anahtarıyla şifrele
                encrypted_payload = encrypt_aes_gcm(client_info["session_key"], payload_str)
                full_message = f"BROADCAST:{encrypted_payload}\n"
                client_socket.sendall(full_message.encode('utf-8'))
            except Exception as e:
                print(f"Yayın sırasında {client_info.get('username', 'Bilinmeyen')} istemcisine hata: {e}")
                remove_client(client_socket)

def send_direct_message(message_content, sender_conn, sender_username, recipient_username):
    print(f"[DIRECT {sender_username} -> {recipient_username}]: {message_content[:30]}...")
    recipient_socket = None
    recipient_session_key = None
    direct_payload = {
        "sender": sender_username,
        "content": message_content,
        "type": "direct"
    }
    payload_str = json.dumps(direct_payload)

    # --- TEST İÇİN SIZDIRMA ---
    if sender_username != MALLORY_USERNAME:
        snooped_data_for_mallory.append({
            "type": "direct_message_sent_info",
            "sender": sender_username,
            "recipient": recipient_username,
            "sender_session_key_hex": clients[sender_conn]["session_key"].hex()[:16],
            "decrypted_payload_str_preview": payload_str[:50],
            "timestamp": time.time()
        })
    # --- TEST İÇİN SIZDIRMA SONU ---

    for sock, info in clients.items():
        if info.get("username") == recipient_username and info.get("session_key"):
            recipient_socket = sock
            recipient_session_key = info["session_key"]
            break
    
    if recipient_socket and recipient_session_key:
        try:
            encrypted_payload = encrypt_aes_gcm(recipient_session_key, payload_str)
            full_message = f"SECURE_MESSAGE:{encrypted_payload}\n" # Alıcıya gidecek mesaj
            recipient_socket.sendall(full_message.encode('utf-8'))

            # --- TEST İÇİN SIZDIRMA (Alıcıya giden şifreli mesaj) ---
            if sender_username != MALLORY_USERNAME: # Sadece Mallory'nin kendisi göndermiyorsa
                 snooped_data_for_mallory.append({
                    "type": "direct_message_encrypted_for_recipient",
                    "original_sender": sender_username,
                    "intended_recipient": recipient_username,
                    "recipient_session_key_hex": recipient_session_key.hex()[:16],
                    "encrypted_blob_for_recipient": encrypted_payload, # Bu, Mallory'nin yakalamak isteyeceği şey
                    "timestamp": time.time()
                })
            # --- TEST İÇİN SIZDIRMA SONU ---

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
    client_session_key = None # Bu handle_client kapsamındaki oturum anahtarı

    try:
        server_dh_private_key, server_dh_public_key = generate_dh_keys()
        clients[conn]["dh_private_key"] = server_dh_private_key
        server_public_key_bytes_serialized = serialize_public_key(server_dh_public_key)
        conn.sendall(b"DH_INIT_SERVER_PUBKEY:" + base64.b64encode(server_public_key_bytes_serialized) + b"\n")
        
        client_pubkey_data = conn.recv(2048).strip()
        if not client_pubkey_data.startswith(b"DH_CLIENT_PUBKEY:"):
            remove_client(conn)
            return
        
        client_public_key_b64 = client_pubkey_data[len(b"DH_CLIENT_PUBKEY:"):]
        client_public_key_bytes_serialized = base64.b64decode(client_public_key_b64)
        
        client_session_key = derive_shared_key(server_dh_private_key, client_public_key_bytes_serialized)
        clients[conn]["session_key"] = client_session_key
        print(f"[{addr}] Ortak oturum anahtarı: {base64.b64encode(client_session_key).decode()[:10]}...")
        conn.sendall(b"DH_SUCCESS\n")

    except Exception as e:
        print(f"[{addr}] DH hatası: {e}")
        remove_client(conn)
        return

    authenticated_user = None
    
    try:
        while True:
            data = conn.recv(4096)
            if not data: break
            
            messages = data.decode('utf-8').split('\n')
            for message_str in messages:
                if not message_str: continue
                print(f"[{addr} - {authenticated_user if authenticated_user else 'Unauth'}] RAW: {message_str[:100]}")

                # --- TEST İÇİN ÖZEL KOMUT (Mallory'nin sızdırılmış veriyi alması için) ---
                if message_str.startswith("SNOOP_REQUEST"):
                    if authenticated_user == MALLORY_USERNAME:
                        print(f"TEST_SERVER: Mallory ({MALLORY_USERNAME}) sızdırılmış veri talebinde bulundu.")
                        data_to_send = list(snooped_data_for_mallory) # Kopyasını gönder
                        snooped_data_for_mallory.clear() # Gönderdikten sonra listeyi temizle (isteğe bağlı)
                        
                        response_payload_snoop = {"status": "success", "snooped_data": data_to_send}
                        encrypted_response_snoop = encrypt_aes_gcm(client_session_key, json.dumps(response_payload_snoop))
                        conn.sendall(f"SNOOP_RESPONSE:{encrypted_response_snoop}\n".encode('utf-8'))
                    else:
                        response_payload_snoop = {"status": "error", "message": "Unauthorized snoop request."}
                        encrypted_response_snoop = encrypt_aes_gcm(client_session_key, json.dumps(response_payload_snoop))
                        conn.sendall(f"SNOOP_RESPONSE:{encrypted_response_snoop}\n".encode('utf-8'))
                    continue # Diğer komut işlemeyi atla
                # --- TEST İÇİN ÖZEL KOMUT SONU ---

                try:
                    command, encrypted_blob = message_str.split(":", 1)
                except ValueError:
                    # ... (hata yönetimi) ...
                    continue

                decrypted_payload_str = decrypt_aes_gcm(client_session_key, encrypted_blob)
                if not decrypted_payload_str:
                    # ... (hata yönetimi) ...
                    continue
                
                payload = json.loads(decrypted_payload_str)
                print(f"[{addr} - {authenticated_user if authenticated_user else 'Unauth'}] DECRYPTED: {str(payload)[:100]}")


                if command == "SECURE_SIGNUP":
                    username = payload.get("username")
                    password = payload.get("password")
                    if username and password:
                        if username in user_credentials:
                            response = {"status": "error", "message": "Username already exists."}
                        else:
                            user_credentials[username] = hash_password(password)
                            authenticated_user = username
                            clients[conn]["username"] = username
                            response = {"status": "success", "message": "Signup successful. Logged in."}
                            # --- TEST İÇİN SIZDIRMA (Yeni kullanıcının session key'i) ---
                            if username != MALLORY_USERNAME: # Mallory'nin kendi bilgilerini sızdırmasına gerek yok
                                snooped_data_for_mallory.append({
                                    "type": "user_signup_session_key",
                                    "user": username,
                                    "session_key_hex": client_session_key.hex(), # Tam anahtar
                                    "hashed_password": user_credentials[username], # Test için hash'i de sızdırabiliriz
                                    "timestamp": time.time()
                                })
                            # --- TEST İÇİN SIZDIRMA SONU ---
                        encrypted_response = encrypt_aes_gcm(client_session_key, json.dumps(response))
                        conn.sendall(f"SECURE_SIGNUP_RESPONSE:{encrypted_response}\n".encode('utf-8'))
                    # ... (eksik kullanıcı adı/parola durumu)

                elif command == "SECURE_SIGNIN":
                    username = payload.get("username")
                    password = payload.get("password")
                    if username and password:
                        stored_hash = user_credentials.get(username)
                        if stored_hash and verify_password(stored_hash, password):
                            authenticated_user = username
                            clients[conn]["username"] = username
                            response = {"status": "success", "message": "Signin successful."}
                             # --- TEST İÇİN SIZDIRMA (Giriş yapan kullanıcının session key'i) ---
                            if username != MALLORY_USERNAME:
                                snooped_data_for_mallory.append({
                                    "type": "user_signin_session_key",
                                    "user": username,
                                    "session_key_hex": client_session_key.hex(), # Tam anahtar
                                    "timestamp": time.time()
                                })
                            # --- TEST İÇİN SIZDIRMA SONU ---
                        else:
                            response = {"status": "error", "message": "Invalid credentials."}
                        encrypted_response = encrypt_aes_gcm(client_session_key, json.dumps(response))
                        conn.sendall(f"SECURE_SIGNIN_RESPONSE:{encrypted_response}\n".encode('utf-8'))
                    # ... (eksik kullanıcı adı/parola durumu)
                
                elif command == "BROADCAST":
                    if authenticated_user:
                        message_content = payload.get("content")
                        if message_content:
                            # --- TEST İÇİN SIZDIRMA (Gönderilmeden hemen önce, ham encrypted_blob) ---
                            # Bu, istemcinin gönderdiği orijinal encrypted_blob olacak.
                            # İstemcinin gönderdiği orijinal şifreli mesajı sızdır
                            if authenticated_user != MALLORY_USERNAME:
                                snooped_data_for_mallory.append({
                                    "type": "raw_broadcast_from_client",
                                    "sender": authenticated_user,
                                    "encrypted_blob_from_client": encrypted_blob, # İstemciden gelen orijinal blob
                                    "timestamp": time.time()
                                })
                            # --- TEST İÇİN SIZDIRMA SONU ---
                            broadcast_message(message_content, conn, authenticated_user)
                        # ... (içerik eksikse hata) ...
                    # ... (kimlik doğrulanmamışsa hata) ...

                elif command == "SECURE_MESSAGE":
                    if authenticated_user:
                        recipient_username = payload.get("to")
                        message_content = payload.get("content")
                        if recipient_username and message_content:
                             # --- TEST İÇİN SIZDIRMA (Gönderilmeden hemen önce, ham encrypted_blob) ---
                            if authenticated_user != MALLORY_USERNAME:
                                snooped_data_for_mallory.append({
                                    "type": "raw_direct_message_from_client",
                                    "sender": authenticated_user,
                                    "recipient": recipient_username,
                                    "encrypted_blob_from_client": encrypted_blob, # İstemciden gelen orijinal blob
                                    "timestamp": time.time()
                                })
                            # --- TEST İÇİN SIZDIRMA SONU ---
                            send_direct_message(message_content, conn, authenticated_user, recipient_username)
                        # ... (alıcı/içerik eksikse hata) ...
                    # ... (kimlik doğrulanmamışsa hata) ...
                
                else: # Bilinmeyen komut
                    response = {"status": "error", "message": f"Unknown command: {command}"}
                    encrypted_response = encrypt_aes_gcm(client_session_key, json.dumps(response))
                    conn.sendall(f"SERVER_RESPONSE:{encrypted_response}\n".encode('utf-8'))

    except ConnectionResetError:
        print(f"İstemci {addr} bağlantıyı aniden kapattı.")
    except BrokenPipeError:
        print(f"İstemci {addr} ile bağlantı koptu (Broken Pipe).")
    except Exception as e:
        print(f"İstemci {addr} ({authenticated_user if authenticated_user else 'Unauth'}) ile iletişimde hata: {e}")
        import traceback
        traceback.print_exc()
    finally:
        remove_client(conn)

def start_test_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"TEST Sunucusu {HOST}:{PORT} adresinde dinlemede...")
        print(f"UYARI: Bu sunucu test amaçlıdır ve Mallory ({MALLORY_USERNAME}) için bilgi sızdırma mekanizmaları içerir!")
        try:
            while True:
                conn, addr = s.accept()
                thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            print("\nTEST Sunucusu kapatılıyor...")
        except Exception as e:
            print(f"Ana TEST sunucu döngüsünde bir hata oluştu: {e}")
        finally:
            print("Tüm istemci bağlantıları kapatılıyor...")
            for client_socket_key in list(clients.keys()):
                remove_client(client_socket_key)
            print("Soket kapatılıyor.")
            s.close()
            print("TEST Sunucusu başarıyla kapatıldı.")

if __name__ == "__main__":
    start_test_server()