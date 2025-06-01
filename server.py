import socket
import threading
import json
import base64
import os
import traceback
from crypto_utils import (
    generate_dh_keys, serialize_public_key, derive_shared_key,
    encrypt_aes_gcm, decrypt_aes_gcm,
    hash_password, verify_password,
    generate_signing_keys, sign_data,
    serialize_signing_public_key_pem, load_signing_public_key_from_pem,
    serialize_signing_private_key_pem, load_signing_private_key_from_pem
)

HOST = '127.0.0.1'
PORT = 65432

SERVER_SIGNING_PRIVATE_KEY_FILE = "server_signing_private.pem"
SERVER_SIGNING_PUBLIC_KEY_FILE = "server_signing_public.pem"
SERVER_SIGNING_KEY_PASSWORD = None
server_signing_private_key = None

# username: {"hashed_password": "...", "e2e_public_key_pem": "PEM_STRING..."}
user_credentials = {}
clients = {} # Sayaçlar ve diğer bilgiler burada

def load_or_generate_server_signing_keys():
    global server_signing_private_key
    if os.path.exists(SERVER_SIGNING_PRIVATE_KEY_FILE):
        try:
            with open(SERVER_SIGNING_PRIVATE_KEY_FILE, "rb") as f: pem_data = f.read()
            server_signing_private_key = load_signing_private_key_from_pem(pem_data, SERVER_SIGNING_KEY_PASSWORD)
            print(f"Sunucu imzalama özel anahtarı '{SERVER_SIGNING_PRIVATE_KEY_FILE}' dosyasından yüklendi.")
            if not os.path.exists(SERVER_SIGNING_PUBLIC_KEY_FILE):
                public_key = server_signing_private_key.public_key()
                with open(SERVER_SIGNING_PUBLIC_KEY_FILE, "wb") as f: f.write(serialize_signing_public_key_pem(public_key))
                print(f"Sunucu imzalama genel anahtarı '{SERVER_SIGNING_PUBLIC_KEY_FILE}' dosyasına kaydedildi.")
        except Exception as e:
            print(f"'{SERVER_SIGNING_PRIVATE_KEY_FILE}' yüklenirken hata: {e}. Yeni anahtar üretilecek."); server_signing_private_key = None
    if not server_signing_private_key:
        print(f"Yeni sunucu imzalama anahtar çifti üretiliyor...")
        try:
            priv_key, pub_key = generate_signing_keys()
            server_signing_private_key = priv_key
            with open(SERVER_SIGNING_PRIVATE_KEY_FILE, "wb") as f: f.write(serialize_signing_private_key_pem(priv_key, SERVER_SIGNING_KEY_PASSWORD))
            print(f"Sunucu imzalama özel anahtarı '{SERVER_SIGNING_PRIVATE_KEY_FILE}' dosyasına kaydedildi.")
            with open(SERVER_SIGNING_PUBLIC_KEY_FILE, "wb") as f: f.write(serialize_signing_public_key_pem(pub_key))
            print(f"Sunucu imzalama genel anahtarı '{SERVER_SIGNING_PUBLIC_KEY_FILE}' dosyasına kaydedildi.")
        except Exception as e: print(f"Yeni imzalama anahtarları üretilirken hata: {e}"); traceback.print_exc(); return False
    return True

def send_encrypted_message_to_client(client_socket, command_type, payload_dict):
    client_info = clients.get(client_socket)
    if not client_info or "session_key" not in client_info: return False
    session_key = client_info["session_key"]
    message_counter = client_info.get("outgoing_message_counter", 0)
    client_info["outgoing_message_counter"] = message_counter + 1
    try:
        encrypted_payload = encrypt_aes_gcm(session_key, json.dumps(payload_dict), message_counter)
        client_socket.sendall(f"{command_type}:{encrypted_payload}\n".encode('utf-8'))
        return True
    except Exception as e: print(f"Şifreli mesaj gönderirken hata: {e}"); remove_client(client_socket); return False

def broadcast_message(message_content, sender_conn, sender_username):
    print(f"[BROADCAST] {sender_username}: {message_content[:30]}...")
    broadcast_payload = {"sender": sender_username, "content": message_content, "type": "broadcast"}
    for client_socket, client_info in list(clients.items()):
        if client_socket != sender_conn and client_info.get("session_key") and client_info.get("username"):
            send_encrypted_message_to_client(client_socket, "BROADCAST", broadcast_payload)

# Eski send_direct_message artık E2EE DM için kullanılmıyor.
# Bu fonksiyon ya kaldırılır ya da sunucudan istemciye özel mesajlar için (sunucunun okuyabildiği) kalır.
# Şimdilik yorum satırı yapalım veya kaldıralım. E2EE yönlendirmesi handle_client içinde.
# def send_direct_message(message_content, sender_conn, sender_username, recipient_username):
#     pass 

def remove_client(client_socket):
    if client_socket in clients: print(f"İstemci {clients[client_socket].get('username', 'Bilinmeyen')} kesildi."); del clients[client_socket]
    try: client_socket.close()
    except: pass

def handle_client(conn, addr):
    print(f"Yeni bağlantı: {addr}")
    clients[conn] = {"address": addr, "outgoing_message_counter": 0, "expected_incoming_message_counter": 0}
    client_info = clients[conn] # Kolay erişim

    try: # DH ve Sunucu Kimlik Doğrulama
        server_dh_priv, server_dh_pub = generate_dh_keys()
        client_info["dh_private_key"] = server_dh_priv
        server_dh_pub_bytes = serialize_public_key(server_dh_pub)
        if not server_signing_private_key: conn.sendall(b"SERVER_ERROR:KEY_ERROR\n"); remove_client(conn); return
        signature = sign_data(server_signing_private_key, server_dh_pub_bytes)
        conn.sendall(b"DH_INIT_SERVER_PUBKEY:" + base64.b64encode(server_dh_pub_bytes) + b":" + base64.b64encode(signature) + b"\n")
        print(f"[{addr}] Sunucu DH genel anahtarı ve imzası gönderildi.")
        client_pubkey_data = conn.recv(2048).strip()
        if not client_pubkey_data.startswith(b"DH_CLIENT_PUBKEY:"): remove_client(conn); return
        client_dh_pub_bytes = base64.b64decode(client_pubkey_data[len(b"DH_CLIENT_PUBKEY:"):])
        session_key = derive_shared_key(server_dh_priv, client_dh_pub_bytes)
        client_info["session_key"] = session_key
        print(f"[{addr}] Oturum anahtarı türetildi.")
        conn.sendall(b"DH_SUCCESS\n")
    except Exception as e: print(f"[{addr}] DH/Auth hatası: {e}"); traceback.print_exc(); remove_client(conn); return

    authenticated_user = None
    try:
        while True:
            data = conn.recv(4096)
            if not data: break
            messages = data.decode('utf-8').split('\n')
            for msg_str in messages:
                if not msg_str: continue
                print(f"[{addr} - {authenticated_user or 'Unauth'}] Ham: {msg_str[:100]}")
                if not client_info.get("session_key"): continue # Oturum anahtarı yoksa devam etme

                try: command, enc_blob = msg_str.split(":", 1)
                except ValueError: send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Invalid format."}); continue

                payload_str, rcv_count = decrypt_aes_gcm(client_info["session_key"], enc_blob)
                if payload_str is None: send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Decryption failed."}); continue
                
                exp_count = client_info["expected_incoming_message_counter"]
                if rcv_count < exp_count:
                    print(f"[{addr}] Replay/Eski mesaj! Bek: {exp_count}, Alınan: {rcv_count}")
                    send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Replay/Old message."}); continue
                client_info["expected_incoming_message_counter"] = rcv_count + 1
                
                payload = json.loads(payload_str)
                print(f"[{addr} - {authenticated_user or 'Unauth'}] Deşifreli (Sayaç {rcv_count}): {payload_str[:100]}")

                if command == "REGISTER_E2E_PUBKEY":
                    if authenticated_user:
                        e2e_pem = payload.get("e2e_public_key_pem")
                        resp = {}
                        if e2e_pem and authenticated_user in user_credentials:
                            user_credentials[authenticated_user]["e2e_public_key_pem"] = e2e_pem
                            print(f"Kullanıcı '{authenticated_user}' E2EE genel anahtarı kaydetti.")
                            resp = {"status": "success", "message": "E2E public key registered."}
                        else: resp = {"status": "error", "message": "Key missing or user not in DB."}
                        send_encrypted_message_to_client(conn, "REGISTER_E2E_PUBKEY_RESPONSE", resp)
                    else: send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Not authenticated."})
                
                elif command == "GET_E2E_PUBKEY":
                    if authenticated_user:
                        target = payload.get("target_username")
                        resp = {}
                        if target in user_credentials and user_credentials[target].get("e2e_public_key_pem"):
                            resp = {"status": "success", "target_username": target, 
                                    "e2e_public_key_pem": user_credentials[target]["e2e_public_key_pem"]}
                        else: resp = {"status": "error", "message": f"E2E key for '{target}' not found."}
                        send_encrypted_message_to_client(conn, "GET_E2E_PUBKEY_RESPONSE", resp)
                    else: send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Not authenticated."})

                elif command == "E2E_DM_INIT" or command == "E2E_DM_MESSAGE": # İkisi de yönlendirme yapar
                    if authenticated_user:
                        recipient_user = payload.get("to")
                        recipient_sock = None
                        for sock, info_peer in clients.items():
                            if info_peer.get("username") == recipient_user: recipient_sock = sock; break
                        
                        if recipient_sock:
                            # Payload'a göndereni ekle, alıcı bilsin
                            # Bu payload ZATEN istemci tarafından sunucuya gönderilirken şifrelenmişti (sunucu-istemci oturum anahtarıyla).
                            # Şimdi bu deşifrelenmiş payload'u alıp (içinde E2EE şifreli kısımlar var)
                            # alıcının sunucuyla olan oturum anahtarıyla tekrar şifreleyip gönderiyoruz.
                            # Yani E2EE payload'u, sunucu-alıcı kanalı üzerinden güvenli taşınıyor.
                            forward_payload = payload.copy() # Orijinal payload'u değiştirmeyelim
                            forward_payload["from_user"] = authenticated_user
                            forward_payload["type"] = "e2e_dm_init" if command == "E2E_DM_INIT" else "e2e_dm_message"
                            
                            print(f"'{authenticated_user}' -> '{recipient_user}' için {command} yönlendiriliyor.")
                            send_encrypted_message_to_client(recipient_sock, "INCOMING_E2E_DM", forward_payload)
                        else:
                            send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": f"User '{recipient_user}' not online."})
                    else: send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Not authenticated."})

                elif command == "SECURE_SIGNUP":
                    uname, passwd = payload.get("username"), payload.get("password"); resp = {}
                    if uname and passwd:
                        if uname in user_credentials: resp = {"status": "error", "message": "Username exists."}
                        else:
                            user_credentials[uname] = {"hashed_password": hash_password(passwd)} # E2E anahtarı sonra kaydedilecek
                            authenticated_user = uname; client_info["username"] = uname
                            resp = {"status": "success", "message": "Signup OK. Logged in."}
                            print(f"User '{uname}' signed up."); 
                    else: resp = {"status": "error", "message": "User/Pass missing."}
                    send_encrypted_message_to_client(conn, "SECURE_SIGNUP_RESPONSE", resp)

                elif command == "SECURE_SIGNIN":
                    uname, passwd = payload.get("username"), payload.get("password"); resp = {}
                    if uname and passwd:
                        cred = user_credentials.get(uname)
                        if cred and verify_password(cred["hashed_password"], passwd):
                            authenticated_user = uname; client_info["username"] = uname
                            resp = {"status": "success", "message": "Signin OK."}
                            print(f"User '{uname}' signed in.")
                        else: resp = {"status": "error", "message": "Invalid user/pass."}
                    else: resp = {"status": "error", "message": "User/Pass missing."}
                    send_encrypted_message_to_client(conn, "SECURE_SIGNIN_RESPONSE", resp)
                
                elif command == "BROADCAST":
                    if authenticated_user:
                        content = payload.get("content")
                        if content: broadcast_message(content, conn, authenticated_user)
                        else: send_encrypted_message_to_client(conn, "SERVER_RESPONSE", {"error": "Broadcast content missing."})
                    else: send_encrypted_message_to_client(conn, "SERVER_RESPONSE", {"error": "Not authenticated."})
                else:
                    send_encrypted_message_to_client(conn, "SERVER_RESPONSE", {"error": f"Unknown command: {command}"})
    except ConnectionResetError: print(f"İstemci {addr} kapattı.")
    except BrokenPipeError: print(f"İstemci {addr} pipe bozuk.")
    except Exception as e: print(f"İstemci {addr} ({authenticated_user or 'Unauth'}) hata: {e}"); traceback.print_exc()
    finally: remove_client(conn)

if __name__ == "__main__":
    if not load_or_generate_server_signing_keys(): print("Sunucu başlatılamıyor."); exit()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((HOST, PORT)); s.listen()
        print(f"Sunucu {HOST}:{PORT} dinlemede...")
        try:
            while True:
                conn, addr = s.accept(); threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt: print("\nSunucu kapatılıyor...")
        except Exception as e: print(f"Ana döngüde hata: {e}"); traceback.print_exc()
        finally:
            print("Bağlantılar kapatılıyor..."); 
            for sk in list(clients.keys()): remove_client(sk)
            s.close(); print("Sunucu kapatıldı.")