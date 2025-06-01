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
    encrypt_aes_gcm, decrypt_aes_gcm,
    load_signing_public_key_from_pem, verify_signature,
    generate_signing_keys, serialize_signing_public_key_pem,
    serialize_signing_private_key_pem, load_signing_private_key_from_pem,
    encrypt_with_rsa_public_key, decrypt_with_rsa_private_key,
    generate_symmetric_key
)

HOST = '127.0.0.1'
PORT = 65432
SERVER_SIGNING_PUBLIC_KEY_FILE = "server_signing_public.pem"
CLIENT_E2E_PRIVATE_KEY_FILE = "client_e2e_private.pem"
CLIENT_E2E_KEY_PASSWORD = None

server_signing_public_key = None
my_e2e_private_key = None
my_e2e_public_key_pem = None

active_e2e_dm_sessions = {} # {"target_user": {"key": bytes, "send_counter": int, "recv_counter": int}}
received_e2e_public_keys_cache = {} # {"target_user": "PEM_STRING"}

client_socket = None
session_key = None
is_authenticated = False
username_cache = None

outgoing_message_counter_to_server = 0
expected_incoming_message_counter_from_server = 0
e2e_key_registered_this_session = False

# E2E genel anahtar istekleri için bir kilit ve durum değişkeni
# Bu, aynı anda birden fazla anahtar isteği yapılmasını veya gereksiz istekleri önlemeye yardımcı olabilir.
# { "target_username": "pending" / "failed" }
e2e_pubkey_request_status = {}
e2e_pubkey_request_lock = threading.Lock()


def load_server_verification_key():
    global server_signing_public_key
    if not os.path.exists(SERVER_SIGNING_PUBLIC_KEY_FILE):
        print(f"[HATA] Sunucu doğrulama dosyası ('{SERVER_SIGNING_PUBLIC_KEY_FILE}') bulunamadı."); return False
    try:
        with open(SERVER_SIGNING_PUBLIC_KEY_FILE, "rb") as f: server_signing_public_key = load_signing_public_key_from_pem(f.read())
        print(f"[BİLGİ] Sunucu doğrulama anahtarı '{SERVER_SIGNING_PUBLIC_KEY_FILE}' yüklendi."); return True
    except Exception as e: print(f"[HATA] Sunucu doğrulama anahtarı yüklenemedi: {e}"); traceback.print_exc(); return False

def load_or_generate_my_e2e_keys():
    global my_e2e_private_key, my_e2e_public_key_pem
    if os.path.exists(CLIENT_E2E_PRIVATE_KEY_FILE):
        try:
            with open(CLIENT_E2E_PRIVATE_KEY_FILE, "rb") as f: pem_data = f.read()
            my_e2e_private_key = load_signing_private_key_from_pem(pem_data, CLIENT_E2E_KEY_PASSWORD)
            my_e2e_public_key_pem = serialize_signing_public_key_pem(my_e2e_private_key.public_key()).decode('utf-8')
            print(f"Kişisel E2EE anahtarları '{CLIENT_E2E_PRIVATE_KEY_FILE}' yüklendi."); return True
        except Exception as e: print(f"'{CLIENT_E2E_PRIVATE_KEY_FILE}' yüklenirken hata: {e}. Yeni üretilecek."); my_e2e_private_key = None
    print("Yeni kişisel E2EE anahtar çifti üretiliyor...")
    try:
        my_e2e_private_key, public_key = generate_signing_keys()
        my_e2e_public_key_pem = serialize_signing_public_key_pem(public_key).decode('utf-8')
        with open(CLIENT_E2E_PRIVATE_KEY_FILE, "wb") as f: f.write(serialize_signing_private_key_pem(my_e2e_private_key, CLIENT_E2E_KEY_PASSWORD))
        print(f"Kişisel E2EE anahtarları üretildi ve '{CLIENT_E2E_PRIVATE_KEY_FILE}' kaydedildi."); return True
    except Exception as e: print(f"Kişisel E2E anahtarları üretilirken hata: {e}"); traceback.print_exc(); return False

def register_my_e2e_key_with_server():
    global e2e_key_registered_this_session
    if my_e2e_public_key_pem and client_socket and session_key and is_authenticated:
        if not e2e_key_registered_this_session:
            print("Kişisel E2EE genel anahtarı sunucuya kaydediliyor...")
            if send_secure_command(client_socket, "REGISTER_E2E_PUBKEY", {"e2e_public_key_pem": my_e2e_public_key_pem}):
                # Durumu hemen True yapmayalım, sunucudan yanıtı bekleyelim.
                # receive_messages'da yanıt gelince e2e_key_registered_this_session True yapılacak.
                pass 
            else: print("[HATA] E2EE genel anahtar kaydı sunucuya gönderilemedi.")

def request_e2e_public_key(target_username):
    with e2e_pubkey_request_lock:
        if target_username in received_e2e_public_keys_cache:
            return # Zaten var
        if e2e_pubkey_request_status.get(target_username) == "pending":
            print(f"'{target_username}' için genel anahtar isteği zaten beklemede.")
            return
        
        print(f"'{target_username}' için E2EE genel anahtar sunucudan isteniyor...")
        if send_secure_command(client_socket, "GET_E2E_PUBKEY", {"target_username": target_username}):
            e2e_pubkey_request_status[target_username] = "pending"
        else:
            e2e_pubkey_request_status[target_username] = "failed" # Gönderim başarısız

def receive_messages(sock):
    global is_authenticated, expected_incoming_message_counter_from_server 
    global received_e2e_public_keys_cache, e2e_key_registered_this_session, e2e_pubkey_request_status
    try:
        while True:
            data = sock.recv(4096)
            if not data: print("\nSunucu bağlantısı kesildi."); e2e_key_registered_this_session = False; break
            messages = data.decode('utf-8').split('\n')
            for msg_str in messages:
                if not msg_str: continue
                print(f"\n[RAW]: {msg_str[:150]}")
                try: command, blob = msg_str.split(":", 1)
                except ValueError: print(f"\n[HATA] Format: {msg_str}"); continue
                
                if command == "DH_SUCCESS": print("\n[BİLGİ] DH başarılı!"); continue
                
                current_sess_key = session_key
                if not current_sess_key: print("\n[HATA] Oturum anahtarı yok."); continue

                payload_str, rcv_serv_count = decrypt_aes_gcm(current_sess_key, blob)
                if payload_str is None: print(f"\n[HATA] Mesaj çözülemedi: {command}"); continue
                
                if rcv_serv_count < expected_incoming_message_counter_from_server:
                    print(f"\n[HATA] Sunucudan replay! Bek: {expected_incoming_message_counter_from_server}, Alınan: {rcv_serv_count}"); continue
                expected_incoming_message_counter_from_server = rcv_serv_count + 1
                
                payload = json.loads(payload_str)
                print(f"\n[DEŞİFRELİ (Sunucu Sayaç {rcv_serv_count})]: {command} - {payload_str[:150]}")

                if command in ["SECURE_SIGNUP_RESPONSE", "SECURE_SIGNIN_RESPONSE"]:
                    status, message = payload.get("status"), payload.get("message")
                    if status == "success":
                        print(f"[BAŞARILI] {message}"); is_authenticated = True
                        if my_e2e_public_key_pem: register_my_e2e_key_with_server()
                    else: print(f"[HATA] {message}"); is_authenticated = False; e2e_key_registered_this_session = False
                
                elif command == "BROADCAST": print(f"[YAYIN] {payload.get('sender')}: {payload.get('content')}")
                
                elif command == "REGISTER_E2E_PUBKEY_RESPONSE":
                    status = payload.get("status"); message = payload.get("message")
                    if status == "success":
                        print(f"[SUNUCU BİLGİ] E2EE Anahtar Kaydı: {message}")
                        e2e_key_registered_this_session = True # Sunucudan onay geldi
                    else:
                        print(f"[SUNUCU HATA] E2EE Anahtar Kaydı: {message}")
                        e2e_key_registered_this_session = False
                
                elif command == "GET_E2E_PUBKEY_RESPONSE":
                    target = payload.get("target_username")
                    with e2e_pubkey_request_lock: # Cache'i güncellerken kilitle
                        if payload.get("status") == "success":
                            pem_key = payload.get("e2e_public_key_pem")
                            received_e2e_public_keys_cache[target] = pem_key
                            e2e_pubkey_request_status.pop(target, None) # Beklemeden çıkar
                            print(f"[BİLGİ] '{target}' için E2EE genel anahtarı alındı ve cache'lendi.")
                        else:
                            print(f"[HATA] '{target}' E2EE anahtar alma: {payload.get('message')}")
                            e2e_pubkey_request_status[target] = "failed" # Başarısız oldu
                
                elif command == "INCOMING_E2E_DM":
                    dm_type = payload.get("type"); from_user = payload.get("from_user")
                    if not my_e2e_private_key: print(f"\n[HATA] '{from_user}' E2EE DM, özel anahtarınız yok!"); continue

                    if dm_type == "e2e_dm_init":
                        enc_dm_key_b64 = payload.get("encrypted_dm_key_b64"); enc_msg_b64 = payload.get("encrypted_message_b64")
                        try:
                            dec_sess_dm_key_bytes = decrypt_with_rsa_private_key(my_e2e_private_key, base64.b64decode(enc_dm_key_b64))
                            active_e2e_dm_sessions[from_user] = {"key": dec_sess_dm_key_bytes, "send_counter": 0, "recv_counter": 0}
                            print(f"\n[E2EE] '{from_user}' ile yeni E2EE DM oturumu kuruldu.")
                            dec_e2e_msg_str, e2e_msg_counter = decrypt_aes_gcm(dec_sess_dm_key_bytes, enc_msg_b64)
                            if dec_e2e_msg_str is not None:
                                if e2e_msg_counter == active_e2e_dm_sessions[from_user]["recv_counter"]:
                                    print(f"[E2EE DM] {from_user}: {dec_e2e_msg_str}")
                                    active_e2e_dm_sessions[from_user]["recv_counter"] += 1
                                else: print(f"[HATA] '{from_user}' E2EE ilk mesaj sayacı hatalı! Bek: 0, Alınan: {e2e_msg_counter}")
                            else: print(f"[HATA] '{from_user}' E2EE ilk mesajı çözülemedi.")
                        except Exception as e: print(f"[HATA] '{from_user}' E2E_DM_INIT işlenirken: {e}"); traceback.print_exc()
                    
                    elif dm_type == "e2e_dm_message":
                        enc_content_b64 = payload.get("e2e_encrypted_content_b64")
                        session_info = active_e2e_dm_sessions.get(from_user)
                        if session_info:
                            try:
                                dec_e2e_msg_str, e2e_msg_counter = decrypt_aes_gcm(session_info["key"], enc_content_b64)
                                if dec_e2e_msg_str is not None:
                                    expected_e2e_recv_counter = session_info["recv_counter"]
                                    if e2e_msg_counter == expected_e2e_recv_counter:
                                        print(f"[E2EE DM] {from_user}: {dec_e2e_msg_str}")
                                        session_info["recv_counter"] += 1
                                    else: print(f"[HATA] '{from_user}' E2EE mesaj sayacı hatalı! Bek: {expected_e2e_recv_counter}, Alınan: {e2e_msg_counter}")
                                else: print(f"[HATA] '{from_user}' E2EE mesajı çözülemedi.")
                            except Exception as e: print(f"[HATA] '{from_user}' E2EE_DM_MESSAGE işlenirken: {e}"); traceback.print_exc()
                        else: print(f"[HATA] '{from_user}' E2EE DM, aktif oturum yok.")
                
                elif command in ["SERVER_ERROR", "SERVER_RESPONSE"]: print(f"[SUNUCU] {payload.get('error', payload.get('message', 'Yanıt'))}")
                else: print(f"[BİLİNMEYEN] {command}: {payload}")
    except ConnectionResetError: print("\nSunucu kapattı."); e2e_key_registered_this_session = False
    except BrokenPipeError: print("\nSunucu pipe bozuk."); e2e_key_registered_this_session = False
    except Exception as e: print(f"\nMesaj alırken hata: {e}"); traceback.print_exc()
    finally:
        if client_socket: 
            try: client_socket.close()
            except: pass
        print("Bağlantı kapatıldı. Çıkmak için Enter."); e2e_key_registered_this_session = False

def send_secure_command(sock, command_type, payload_dict):
    global outgoing_message_counter_to_server
    current_sess_key = session_key
    if not current_sess_key: print("Oturum anahtarı yok."); return False
    current_counter = outgoing_message_counter_to_server; outgoing_message_counter_to_server += 1
    try:
        enc_payload = encrypt_aes_gcm(current_sess_key, json.dumps(payload_dict), current_counter)
        sock.sendall(f"{command_type}:{enc_payload}\n".encode('utf-8')); return True
    except Exception as e: print(f"Mesaj gönderirken hata: {e}"); outgoing_message_counter_to_server = current_counter; return False

def perform_dh_key_exchange(sock):
    global session_key, outgoing_message_counter_to_server, expected_incoming_message_counter_from_server
    if not server_signing_public_key: print("[HATA] Sunucu doğrulama anahtarı yüklenmedi."); return False
    try:
        dh_init_data = sock.recv(4096).strip(); parts = dh_init_data.split(b":")
        if len(parts) != 3 or parts[0] != b"DH_INIT_SERVER_PUBKEY": print("Geçersiz DH formatı."); return False
        serv_dh_pub_bytes = base64.b64decode(parts[1]); sig_bytes = base64.b64decode(parts[2])
        if not verify_signature(server_signing_public_key, sig_bytes, serv_dh_pub_bytes): print("[HATA] Sunucu imzası GEÇERSİZ!"); return False
        print("[BİLGİ] Sunucu imzası doğrulandı.")
        cli_dh_priv, cli_dh_pub = generate_dh_keys(); cli_dh_pub_bytes = serialize_public_key(cli_dh_pub)
        sock.sendall(b"DH_CLIENT_PUBKEY:" + base64.b64encode(cli_dh_pub_bytes) + b"\n")
        print("[BİLGİ] İstemci DH genel anahtarı gönderildi.")
        session_key = derive_shared_key(cli_dh_priv, serv_dh_pub_bytes); print(f"[BİLGİ] Oturum anahtarı türetildi.")
        if sock.recv(1024).strip() == b"DH_SUCCESS":
            print("[BİLGİ] DH başarı onayı alındı.")
            outgoing_message_counter_to_server = 0; expected_incoming_message_counter_from_server = 0
            return True
        else: print(f"[HATA] DH onayı alınamadı."); session_key = None; return False
    except Exception as e: print(f"DH sırasında hata: {e}"); traceback.print_exc(); session_key = None; return False

def handle_dm_command(recipient_username, message_content):
    global active_e2e_dm_sessions, received_e2e_public_keys_cache, e2e_pubkey_request_status

    if not my_e2e_private_key:
        print("Kişisel E2EE özel anahtarınız yüklenmemiş. DM gönderilemiyor."); return

    # 1. Alıcının E2EE genel anahtarı cache'de var mı veya istek beklemede mi?
    recipient_e2e_pubkey_pem = received_e2e_public_keys_cache.get(recipient_username)
    
    if not recipient_e2e_pubkey_pem:
        if e2e_pubkey_request_status.get(recipient_username) == "pending":
            print(f"'{recipient_username}' için genel anahtar sunucudan bekleniyor. Lütfen biraz sonra tekrar deneyin.")
            return
        elif e2e_pubkey_request_status.get(recipient_username) == "failed":
            print(f"'{recipient_username}' için genel anahtar daha önce istenmiş ancak alınamamış. Tekrar isteniyor...")
            request_e2e_public_key(recipient_username) # Tekrar iste
            print(f"'{recipient_username}' için genel anahtar isteği gönderildi. Lütfen biraz sonra mesajı tekrar göndermeyi deneyin.")
            return
        else: # İlk kez isteniyor
            request_e2e_public_key(recipient_username)
            print(f"'{recipient_username}' için genel anahtar isteği gönderildi. Lütfen biraz sonra mesajı tekrar göndermeyi deneyin.")
            return
            
    try:
        recipient_e2e_public_key_obj = load_signing_public_key_from_pem(recipient_e2e_pubkey_pem)
    except Exception as e:
        print(f"'{recipient_username}' kullanıcısının cache'deki genel anahtarı yüklenemedi: {e}"); return

    # 2. Aktif E2EE oturumu var mı?
    session_info = active_e2e_dm_sessions.get(recipient_username)

    if not session_info: # Yeni oturum başlat (E2E_DM_INIT)
        print(f"'{recipient_username}' ile yeni E2EE oturumu başlatılıyor...")
        temp_dm_key_bytes = generate_symmetric_key()
        encrypted_temp_dm_key_bytes = encrypt_with_rsa_public_key(recipient_e2e_public_key_obj, temp_dm_key_bytes)
        
        # E2EE mesajları için sayaçları başlat. İlk mesajın sayacı 0.
        e2e_send_counter = 0 
        encrypted_e2e_message_b64 = encrypt_aes_gcm(temp_dm_key_bytes, message_content, e2e_send_counter)
        
        e2e_init_payload = {
            "to": recipient_username,
            "encrypted_dm_key_b64": base64.b64encode(encrypted_temp_dm_key_bytes).decode('utf-8'),
            "encrypted_message_b64": encrypted_e2e_message_b64
        }
        if send_secure_command(client_socket, "E2E_DM_INIT", e2e_init_payload):
            active_e2e_dm_sessions[recipient_username] = {
                "key": temp_dm_key_bytes, 
                "send_counter": e2e_send_counter + 1, # Bir sonraki gönderilecek mesajın sayacı
                "recv_counter": 0 # Henüz mesaj alınmadı
            }
            print(f"'{recipient_username}' kullanıcısına E2E DM başlatma isteği gönderildi.")
        else:
            print(f"'{recipient_username}' kullanıcısına E2E DM başlatma isteği gönderilemedi.")
    else: # Mevcut oturumda mesaj gönder (E2E_DM_MESSAGE)
        current_e2e_send_counter = session_info["send_counter"]
        encrypted_e2e_message_b64 = encrypt_aes_gcm(session_info["key"], message_content, current_e2e_send_counter)
        session_info["send_counter"] = current_e2e_send_counter + 1

        e2e_message_payload = {
            "to": recipient_username,
            "e2e_encrypted_content_b64": encrypted_e2e_message_b64
        }
        if send_secure_command(client_socket, "E2E_DM_MESSAGE", e2e_message_payload):
            print(f"'{recipient_username}' kullanıcısına E2EE mesaj gönderildi (sayaç: {current_e2e_send_counter}).")
        else:
            print(f"'{recipient_username}' kullanıcısına E2EE mesaj gönderilemedi.")


def main():
    global client_socket, is_authenticated, username_cache, e2e_key_registered_this_session

    if not load_server_verification_key(): print("İstemci başlatılamıyor (sunucu doğrulama)."); return
    if not load_or_generate_my_e2e_keys(): print("İstemci başlatılamıyor (kişisel E2EE)."); return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT)); print(f"{HOST}:{PORT} bağlandı.")
        if not perform_dh_key_exchange(client_socket):
            print("Anahtar değişimi/Sunucu doğrulaması başarısız."); client_socket.close(); return
        
        threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

        while True:
            if not is_authenticated:
                action = input("Giriş ('signin'), Kayıt ('signup'), Çıkış ('exit'): ").strip().lower()
                if action == "exit": break
                elif action == "signup":
                    uname=input("K.Adı: "); passwd=getpass.getpass("Parola: "); cpasswd=getpass.getpass("Parola Tekrar: ")
                    if not uname or not passwd: print("Boş bırakılamaz."); continue
                    if passwd != cpasswd: print("Parolalar eşleşmiyor."); continue
                    if send_secure_command(client_socket, "SECURE_SIGNUP", {"username":uname, "password":passwd}):
                        username_cache=uname; time.sleep(0.3); continue 
                elif action == "signin":
                    uname=input("K.Adı: "); passwd=getpass.getpass("Parola: ")
                    if not uname or not passwd: print("Boş bırakılamaz."); continue
                    if send_secure_command(client_socket, "SECURE_SIGNIN", {"username":uname, "password":passwd}):
                        username_cache=uname; time.sleep(0.3); continue 
                else: print("Geçersiz komut.")
            else: 
                prompt_options = "'broadcast <msg>', 'dm <user> <msg>', 'logout', 'exit'"
                user_input = input(f"[{username_cache}] ({prompt_options}): ").strip()
                if user_input.lower() == "exit": break
                if user_input.lower() == "logout": 
                    is_authenticated=False; username_cache=None; 
                    active_e2e_dm_sessions.clear(); received_e2e_public_keys_cache.clear()
                    e2e_key_registered_this_session = False; e2e_pubkey_request_status.clear()
                    print("Oturum kapatıldı."); continue
                
                parts = user_input.split(" ", 2); cmd = parts[0].lower()

                if cmd == "broadcast" and len(parts) >= 2: 
                    send_secure_command(client_socket, "BROADCAST", {"content": " ".join(parts[1:])})
                elif cmd == "dm" and len(parts) == 3:
                    recipient_username, message_content = parts[1], parts[2]
                    handle_dm_command(recipient_username, message_content)
                # 'gete2ekey', 'e2edm', 'e2emsg' komutları artık doğrudan kullanıcı arayüzünde değil.
                else: print("Geçersiz format veya komut. Kullanılabilir: broadcast, dm, logout, exit")
    except ConnectionRefusedError: print(f"{HOST}:{PORT} bağlanılamadı.")
    except KeyboardInterrupt: print("\nİstemci kapatılıyor...")
    except Exception as e: print(f"Ana döngüde hata: {e}"); traceback.print_exc()
    finally:
        if client_socket: 
            try: client_socket.close()
            except: pass
        e2e_key_registered_this_session = False
        print("İstemci sonlandırıldı.")

if __name__ == "__main__":
    main()