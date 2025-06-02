import socket
import threading
import json
import getpass
import base64
import time
import os
import traceback
# Unix benzeri sistemlerde prompt'u yeniden çizmek için bir deneme
# Windows'ta bu kısım farklı çalışabilir veya sorun çıkarabilir.
# Eğer sorun olursa, is_windows kontrolü ile bu kısmı atlayabiliriz.
# import readline # Bu kütüphane prompt geçmişi ve düzenleme için de iyidir.
#                 # Ancak sadece prompt'u yeniden çizmek için direkt bir çözümü olmayabilir.

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

active_e2e_dm_sessions = {}
received_e2e_public_keys_cache = {}

client_socket = None
session_key = None
is_authenticated = False
username_cache = None # Giriş yapan kullanıcının adı burada saklanacak

outgoing_message_counter_to_server = 0
expected_incoming_message_counter_from_server = 0
e2e_key_registered_this_session = False

e2e_pubkey_request_status = {}
e2e_pubkey_request_lock = threading.Lock()

# --- Renkler ve Formatlama (İsteğe Bağlı) ---
class TermColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Windows'ta renk kodları çalışmayabilir, bu yüzden basit bir kontrol ekleyelim
IS_WINDOWS = os.name == 'nt'

def color_text(text, color_code):
    if IS_WINDOWS:
        return text # Windows'ta renk yok
    return f"{color_code}{text}{TermColors.ENDC}"

def print_system_message(message, level="info"):
    # Mevcut input satırını silip mesajı yazdırıp, input satırını geri getirme denemesi
    # Bu kısım `readline` gibi kütüphanelerle daha iyi yapılabilir.
    # Basit bir \r (carriage return) ile satır başına dönüp boşlukla silmeye çalışalım.
    # Ancak bu, kullanıcının o anda yazdığı şeyi silebilir.
    # Daha güvenli yöntem, sadece yeni satıra yazdırmak.
    
    # print("\r" + " " * 80 + "\r", end="") # Önceki satırı sil (deneme)
    if level == "error":
        print(f"\n{color_text('[HATA]', TermColors.FAIL)} {message}")
    elif level == "warning":
        print(f"\n{color_text('[UYARI]', TermColors.WARNING)} {message}")
    elif level == "success":
        print(f"\n{color_text('[BAŞARILI]', TermColors.OKGREEN)} {message}")
    else: # info
        print(f"\n{color_text('[BİLGİ]', TermColors.OKBLUE)} {message}")
    
    # Prompt'u yeniden yazdırmayı dene (eğer kullanıcı bir şey giriyorsa sorun olabilir)
    # Bu kısım çok güvenilir değil, daha iyi bir UI kütüphanesi gerekir.
    # if is_authenticated and username_cache:
    #     current_prompt = f"{color_text(username_cache, TermColors.OKCYAN)}{TermColors.BOLD}:{TermColors.ENDC} "
    #     print(current_prompt, end="", flush=True)
    # elif not is_authenticated:
    #      print("Giriş/Kayıt/Çıkış: ", end="", flush=True)


# --- Anahtar Yönetimi Fonksiyonları (Aynı) ---
def load_server_verification_key():
    global server_signing_public_key
    if not os.path.exists(SERVER_SIGNING_PUBLIC_KEY_FILE):
        print_system_message(f"Sunucu doğrulama dosyası ('{SERVER_SIGNING_PUBLIC_KEY_FILE}') bulunamadı.", "error"); return False
    try:
        with open(SERVER_SIGNING_PUBLIC_KEY_FILE, "rb") as f: server_signing_public_key = load_signing_public_key_from_pem(f.read())
        print_system_message(f"Sunucu doğrulama anahtarı '{SERVER_SIGNING_PUBLIC_KEY_FILE}' yüklendi.", "info"); return True
    except Exception as e: print_system_message(f"Sunucu doğrulama anahtarı yüklenemedi: {e}", "error"); traceback.print_exc(); return False

def load_or_generate_my_e2e_keys():
    global my_e2e_private_key, my_e2e_public_key_pem
    if os.path.exists(CLIENT_E2E_PRIVATE_KEY_FILE):
        try:
            with open(CLIENT_E2E_PRIVATE_KEY_FILE, "rb") as f: pem_data = f.read()
            my_e2e_private_key = load_signing_private_key_from_pem(pem_data, CLIENT_E2E_KEY_PASSWORD)
            my_e2e_public_key_pem = serialize_signing_public_key_pem(my_e2e_private_key.public_key()).decode('utf-8')
            print_system_message(f"Kişisel E2EE anahtarları '{CLIENT_E2E_PRIVATE_KEY_FILE}' yüklendi.", "info"); return True
        except Exception as e: print_system_message(f"'{CLIENT_E2E_PRIVATE_KEY_FILE}' yüklenirken hata: {e}. Yeni üretilecek.", "warning"); my_e2e_private_key = None
    print_system_message("Yeni kişisel E2EE anahtar çifti üretiliyor...", "info")
    try:
        my_e2e_private_key, public_key = generate_signing_keys()
        my_e2e_public_key_pem = serialize_signing_public_key_pem(public_key).decode('utf-8')
        with open(CLIENT_E2E_PRIVATE_KEY_FILE, "wb") as f: f.write(serialize_signing_private_key_pem(my_e2e_private_key, CLIENT_E2E_KEY_PASSWORD))
        print_system_message(f"Kişisel E2EE anahtarları üretildi ve '{CLIENT_E2E_PRIVATE_KEY_FILE}' kaydedildi.", "success"); return True
    except Exception as e: print_system_message(f"Kişisel E2EE anahtarları üretilirken hata: {e}", "error"); traceback.print_exc(); return False

def register_my_e2e_key_with_server():
    global e2e_key_registered_this_session
    if my_e2e_public_key_pem and client_socket and session_key and is_authenticated:
        if not e2e_key_registered_this_session:
            print_system_message("Kişisel E2EE genel anahtarı sunucuya kaydediliyor...", "info")
            if send_secure_command(client_socket, "REGISTER_E2E_PUBKEY", {"e2e_public_key_pem": my_e2e_public_key_pem}):
                pass # Yanıt receive_messages'da işlenecek
            else: print_system_message("E2EE genel anahtar kaydı sunucuya gönderilemedi.", "error")

def request_e2e_public_key(target_username):
    with e2e_pubkey_request_lock:
        if target_username in received_e2e_public_keys_cache: return
        if e2e_pubkey_request_status.get(target_username) == "pending":
            print_system_message(f"'{target_username}' için genel anahtar isteği zaten beklemede.", "info"); return
        print_system_message(f"'{target_username}' için E2EE genel anahtar sunucudan isteniyor...", "info")
        if send_secure_command(client_socket, "GET_E2E_PUBKEY", {"target_username": target_username}):
            e2e_pubkey_request_status[target_username] = "pending"
        else: e2e_pubkey_request_status[target_username] = "failed"


def receive_messages(sock):
    global is_authenticated, expected_incoming_message_counter_from_server, received_e2e_public_keys_cache, e2e_key_registered_this_session, e2e_pubkey_request_status
    try:
        while True:
            data = sock.recv(4096)
            if not data: print_system_message("Sunucu bağlantısı kesildi.", "warning"); e2e_key_registered_this_session = False; break
            messages = data.decode('utf-8').split('\n')
            for msg_str in messages:
                if not msg_str: continue
              
                try: command, blob = msg_str.split(":", 1)
                except ValueError: print_system_message(f"Sunucudan geçersiz format: {msg_str}", "error"); continue
                
                if command == "DH_SUCCESS": print_system_message("DH anahtar değişimi başarılı!", "success"); continue
                
                current_sess_key = session_key
                if not current_sess_key: print_system_message("Oturum anahtarı yok, mesaj çözülemiyor.", "error"); continue

                payload_str, rcv_serv_count = decrypt_aes_gcm(current_sess_key, blob)
                if payload_str is None: print_system_message(f"Mesaj çözülemedi (komut: {command})", "error"); continue
                
                if rcv_serv_count < expected_incoming_message_counter_from_server:
                    print_system_message(f"Sunucudan tekrar oynatma/eski mesaj! Bek: {expected_incoming_message_counter_from_server}, Alınan: {rcv_serv_count}", "warning"); continue
                expected_incoming_message_counter_from_server = rcv_serv_count + 1
                
                payload = json.loads(payload_str)
                # print_system_message(f"Deşifreli (Sunucu Sayaç {rcv_serv_count}): {command} - {payload_str[:100]}", "info") # Daha iyi formatlama aşağıda

                if command in ["SECURE_SIGNUP_RESPONSE", "SECURE_SIGNIN_RESPONSE"]:
                    status, message = payload.get("status"), payload.get("message")
                    if status == "success":
                        print_system_message(message, "success"); is_authenticated = True
                        if my_e2e_public_key_pem: register_my_e2e_key_with_server()
                    else: print_system_message(message, "error"); is_authenticated = False; e2e_key_registered_this_session = False
                
                elif command == "BROADCAST":
                    print(f"\n{color_text('[YAYIN]', TermColors.HEADER)} {color_text(payload.get('sender', 'Bilinmeyen'), TermColors.OKGREEN)}{TermColors.BOLD}:{TermColors.ENDC} {payload.get('content')}")
                
                elif command == "REGISTER_E2E_PUBKEY_RESPONSE":
                    status = payload.get("status"); message = payload.get("message")
                    level = "success" if status == "success" else "error"
                    print_system_message(f"E2EE Anahtar Kaydı: {message}", level)
                    if status == "success": e2e_key_registered_this_session = True
                    else: e2e_key_registered_this_session = False
                
                elif command == "GET_E2E_PUBKEY_RESPONSE":
                    target = payload.get("target_username")
                    with e2e_pubkey_request_lock:
                        if payload.get("status") == "success":
                            pem_key = payload.get("e2e_public_key_pem")
                            received_e2e_public_keys_cache[target] = pem_key
                            e2e_pubkey_request_status.pop(target, None)
                            print_system_message(f"'{target}' için E2EE genel anahtarı alındı ve cache'lendi.", "info")
                        else:
                            print_system_message(f"'{target}' için E2EE anahtar alma başarısız: {payload.get('message')}", "error")
                            e2e_pubkey_request_status[target] = "failed"
                
                elif command == "INCOMING_E2E_DM":
                    dm_type = payload.get("type"); from_user = payload.get("from_user")
                    if not my_e2e_private_key: print_system_message(f"'{from_user}' E2EE DM, özel anahtarınız yok!", "error"); continue

                    if dm_type == "e2e_dm_init":
                        enc_dm_key_b64 = payload.get("encrypted_dm_key_b64"); enc_msg_b64 = payload.get("encrypted_message_b64")
                        try:
                            dec_sess_dm_key_bytes = decrypt_with_rsa_private_key(my_e2e_private_key, base64.b64decode(enc_dm_key_b64))
                            active_e2e_dm_sessions[from_user] = {"key": dec_sess_dm_key_bytes, "send_counter": 0, "recv_counter": 0}
                            print_system_message(f"'{from_user}' ile yeni E2EE DM oturumu kuruldu.", "success")
                            dec_e2e_msg_str, e2e_msg_counter = decrypt_aes_gcm(dec_sess_dm_key_bytes, enc_msg_b64)
                            if dec_e2e_msg_str is not None:
                                if e2e_msg_counter == active_e2e_dm_sessions[from_user]["recv_counter"]:
                                    print(f"\n{color_text('[E2EE DM]', TermColors.OKCYAN)} {color_text(from_user, TermColors.OKGREEN)}{TermColors.BOLD}:{TermColors.ENDC} {dec_e2e_msg_str}")
                                    active_e2e_dm_sessions[from_user]["recv_counter"] += 1
                                else: print_system_message(f"'{from_user}' E2EE ilk mesaj sayacı hatalı! Bek: 0, Alınan: {e2e_msg_counter}", "error")
                            else: print_system_message(f"'{from_user}' E2EE ilk mesajı çözülemedi.", "error")
                        except Exception as e: print_system_message(f"'{from_user}' E2E_DM_INIT işlenirken hata: {e}", "error"); traceback.print_exc()
                    
                    elif dm_type == "e2e_dm_message":
                        enc_content_b64 = payload.get("e2e_encrypted_content_b64")
                        session_info = active_e2e_dm_sessions.get(from_user)
                        if session_info:
                            try:
                                dec_e2e_msg_str, e2e_msg_counter = decrypt_aes_gcm(session_info["key"], enc_content_b64)
                                if dec_e2e_msg_str is not None:
                                    expected_e2e_recv_counter = session_info["recv_counter"]
                                    if e2e_msg_counter == expected_e2e_recv_counter:
                                        print(f"\n{color_text('[E2EE DM]', TermColors.OKCYAN)} {color_text(from_user, TermColors.OKGREEN)}{TermColors.BOLD}:{TermColors.ENDC} {dec_e2e_msg_str}")
                                        session_info["recv_counter"] += 1
                                    else: print_system_message(f"'{from_user}' E2EE mesaj sayacı hatalı! Bek: {expected_e2e_recv_counter}, Alınan: {e2e_msg_counter}", "error")
                                else: print_system_message(f"'{from_user}' E2EE mesajı çözülemedi.", "error")
                            except Exception as e: print_system_message(f"'{from_user}' E2EE_DM_MESSAGE işlenirken hata: {e}", "error"); traceback.print_exc()
                        else: print_system_message(f"'{from_user}' E2EE DM, aktif oturum yok.", "warning")
                
                elif command in ["SERVER_ERROR", "SERVER_RESPONSE"]:
                    print_system_message(f"{payload.get('error', payload.get('message', 'Bilinmeyen sunucu yanıtı'))}", "warning")
                else:
                    print_system_message(f"Sunucudan bilinmeyen komut: {command}, Payload: {payload}", "warning")
                
                # Prompt'u yeniden çizme denemesi (isteğe bağlı ve platforma göre hassas)
                # if sys.stdout.isatty(): # Sadece terminalde çalışıyorsa
                #     current_prompt_text = ""
                #     if is_authenticated and username_cache:
                #         current_prompt_text = f"{color_text(username_cache, TermColors.OKCYAN)}{TermColors.BOLD}:{TermColors.ENDC} "
                #     elif not is_authenticated:
                #         current_prompt_text = "Giriş/Kayıt/Çıkış: "
                #     # readline.redisplay() # Eğer readline kullanılıyorsa
                #     print(current_prompt_text, end="", flush=True)


    except ConnectionResetError: print_system_message("Sunucu bağlantıyı kapattı.", "warning"); e2e_key_registered_this_session = False
    except BrokenPipeError: print_system_message("Sunucu ile bağlantı koptu (Broken Pipe).", "warning"); e2e_key_registered_this_session = False
    except Exception as e: print_system_message(f"Mesaj alırken hata: {e}", "error"); traceback.print_exc()
    finally:
        if client_socket: 
            try: client_socket.close()
            except: pass
        print_system_message("Bağlantı kapatıldı. Çıkmak için Enter'a basın.", "info"); e2e_key_registered_this_session = False

def send_secure_command(sock, command_type, payload_dict):
    # ... (Aynı, sadece print'ler print_system_message olabilir) ...
    global outgoing_message_counter_to_server
    current_sess_key = session_key
    if not current_sess_key: print_system_message("Oturum anahtarı yok.", "error"); return False
    current_counter = outgoing_message_counter_to_server; outgoing_message_counter_to_server += 1
    try:
        enc_payload = encrypt_aes_gcm(current_sess_key, json.dumps(payload_dict), current_counter)
        sock.sendall(f"{command_type}:{enc_payload}\n".encode('utf-8')); return True
    except Exception as e: print_system_message(f"Mesaj gönderirken hata: {e}", "error"); outgoing_message_counter_to_server = current_counter; return False

def perform_dh_key_exchange(sock):
    # ... (Aynı, sadece print'ler print_system_message olabilir) ...
    global session_key, outgoing_message_counter_to_server, expected_incoming_message_counter_from_server
    if not server_signing_public_key: print_system_message("Sunucu doğrulama anahtarı yüklenmedi.", "error"); return False
    try:
        dh_init_data = sock.recv(4096).strip(); parts = dh_init_data.split(b":")
        if len(parts) != 3 or parts[0] != b"DH_INIT_SERVER_PUBKEY": print_system_message("Geçersiz DH formatı.", "error"); return False
        serv_dh_pub_bytes = base64.b64decode(parts[1]); sig_bytes = base64.b64decode(parts[2])
        if not verify_signature(server_signing_public_key, sig_bytes, serv_dh_pub_bytes): print_system_message("Sunucu imzası GEÇERSİZ!", "error"); return False
        print_system_message("Sunucu imzası doğrulandı.", "success")
        cli_dh_priv, cli_dh_pub = generate_dh_keys(); cli_dh_pub_bytes = serialize_public_key(cli_dh_pub)
        sock.sendall(b"DH_CLIENT_PUBKEY:" + base64.b64encode(cli_dh_pub_bytes) + b"\n")
        print_system_message("İstemci DH genel anahtarı gönderildi.", "info")
        session_key = derive_shared_key(cli_dh_priv, serv_dh_pub_bytes); print_system_message(f"Sunucu ile oturum anahtarı türetildi.", "info")
        if sock.recv(1024).strip() == b"DH_SUCCESS":
            print_system_message("DH başarı onayı alındı.", "success")
            outgoing_message_counter_to_server = 0; expected_incoming_message_counter_from_server = 0
            return True
        else: print_system_message(f"DH onayı alınamadı.", "error"); session_key = None; return False
    except Exception as e: print_system_message(f"DH sırasında hata: {e}", "error"); traceback.print_exc(); session_key = None; return False

def handle_dm_command(recipient_username, message_content):
    # ... (Aynı, sadece print'ler print_system_message olabilir) ...
    global active_e2e_dm_sessions, received_e2e_public_keys_cache, e2e_pubkey_request_status
    if not my_e2e_private_key: print_system_message("Kişisel E2EE özel anahtarınız yüklenmemiş. DM gönderilemiyor.", "error"); return
    recipient_e2e_pubkey_pem = received_e2e_public_keys_cache.get(recipient_username)
    if not recipient_e2e_pubkey_pem:
        if e2e_pubkey_request_status.get(recipient_username) == "pending": print_system_message(f"'{recipient_username}' için genel anahtar bekleniyor. Sonra tekrar deneyin.", "info"); return
        elif e2e_pubkey_request_status.get(recipient_username) == "failed": print_system_message(f"'{recipient_username}' anahtar alınamadı. Tekrar isteniyor...", "warning"); request_e2e_public_key(recipient_username); return
        else: request_e2e_public_key(recipient_username); print_system_message(f"'{recipient_username}' anahtar isteği gönderildi. Sonra mesajı tekrar deneyin.", "info"); return
    try: recipient_e2e_public_key_obj = load_signing_public_key_from_pem(recipient_e2e_pubkey_pem)
    except Exception as e: print_system_message(f"'{recipient_username}' genel anahtarı yüklenemedi: {e}", "error"); return
    session_info = active_e2e_dm_sessions.get(recipient_username)
    if not session_info:
        print_system_message(f"'{recipient_username}' ile yeni E2EE oturumu başlatılıyor...", "info")
        temp_dm_key_bytes = generate_symmetric_key(); encrypted_temp_dm_key_bytes = encrypt_with_rsa_public_key(recipient_e2e_public_key_obj, temp_dm_key_bytes)
        e2e_send_counter = 0 ; encrypted_e2e_message_b64 = encrypt_aes_gcm(temp_dm_key_bytes, message_content, e2e_send_counter)
        e2e_init_payload = {"to": recipient_username, "encrypted_dm_key_b64": base64.b64encode(encrypted_temp_dm_key_bytes).decode('utf-8'), "encrypted_message_b64": encrypted_e2e_message_b64}
        if send_secure_command(client_socket, "E2E_DM_INIT", e2e_init_payload):
            active_e2e_dm_sessions[recipient_username] = {"key": temp_dm_key_bytes, "send_counter": e2e_send_counter + 1, "recv_counter": 0}
            print_system_message(f"'{recipient_username}' E2E DM başlatma isteği gönderildi.", "info")
        else: print_system_message(f"'{recipient_username}' E2E DM başlatma isteği gönderilemedi.", "error")
    else:
        current_e2e_send_counter = session_info["send_counter"]
        encrypted_e2e_message_b64 = encrypt_aes_gcm(session_info["key"], message_content, current_e2e_send_counter)
        session_info["send_counter"] = current_e2e_send_counter + 1
        e2e_message_payload = {"to": recipient_username, "e2e_encrypted_content_b64": encrypted_e2e_message_b64}
        if send_secure_command(client_socket, "E2E_DM_MESSAGE", e2e_message_payload):
            print_system_message(f"'{recipient_username}' E2EE mesaj gönderildi (sayaç: {current_e2e_send_counter}).", "info")
        else: print_system_message(f"'{recipient_username}' E2EE mesaj gönderilemedi.", "error")


def display_prompt():
    """Mevcut duruma göre komut istemini oluşturur ve yazdırır."""
    if is_authenticated and username_cache:
        # Kullanıcı adını renklendir, sonuna ':' ve boşluk ekle
        prompt_text = f"{color_text(username_cache, TermColors.OKCYAN)}{TermColors.BOLD}:{TermColors.ENDC} "
    else:
        prompt_text = "Giriş/Kayıt/Çıkış ('signin', 'signup', 'exit'): "
    
    # Kullanıcının yarım kalan girdisini silmekten kaçınmak için,
    # bu basit CLI'da prompt'u input() fonksiyonuna parametre olarak vermek en iyisi.
    # print(prompt_text, end="", flush=True) # Bu satır sorun yaratabilir.
    return prompt_text


def main():
    global client_socket, is_authenticated, username_cache, e2e_key_registered_this_session

    print_system_message("Güvenli Sohbet İstemcisi Başlatılıyor...", "header")
    if not load_server_verification_key(): print_system_message("İstemci başlatılamadı.", "error"); return
    if not load_or_generate_my_e2e_keys(): print_system_message("İstemci başlatılamadı.", "error"); return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT)); print_system_message(f"{HOST}:{PORT} adresine bağlanıldı.", "success")
        if not perform_dh_key_exchange(client_socket):
            print_system_message("Anahtar değişimi/Sunucu doğrulaması başarısız. Çıkılıyor.", "error"); client_socket.close(); return
        
        threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

        print_system_message("Kullanılabilir komutlar için 'help' yazabilirsiniz.", "info")

        while True:
            current_prompt = display_prompt() # Prompt'u al
            try:
                user_input = input(current_prompt).strip()
            except EOFError: # Ctrl+D gibi durumlarda
                print_system_message("EOF alındı, çıkılıyor...", "warning")
                break
            except KeyboardInterrupt: # Ctrl+C
                print_system_message("\nKeyboardInterrupt alındı, çıkılıyor...", "warning")
                break


            if not is_authenticated:
                action = user_input.lower()
                if action == "exit": break
                elif action == "signup":
                    uname=input(f"{color_text('? Kayıt - Kullanıcı Adı:', TermColors.OKBLUE)} "); passwd=getpass.getpass(f"{color_text('? Kayıt - Parola:', TermColors.OKBLUE)} "); cpasswd=getpass.getpass(f"{color_text('? Kayıt - Parola Tekrar:', TermColors.OKBLUE)} ")
                    if not uname or not passwd: print_system_message("Kullanıcı adı veya parola boş olamaz.", "error"); continue
                    if passwd != cpasswd: print_system_message("Parolalar eşleşmiyor.", "error"); continue
                    if send_secure_command(client_socket, "SECURE_SIGNUP", {"username":uname, "password":passwd}):
                        username_cache=uname; time.sleep(0.3); 
                elif action == "signin":
                    uname=input(f"{color_text('? Giriş - Kullanıcı Adı:', TermColors.OKBLUE)} "); passwd=getpass.getpass(f"{color_text('? Giriş - Parola:', TermColors.OKBLUE)} ")
                    if not uname or not passwd: print_system_message("Kullanıcı adı veya parola boş olamaz.", "error"); continue
                    if send_secure_command(client_socket, "SECURE_SIGNIN", {"username":uname, "password":passwd}):
                        username_cache=uname; time.sleep(0.3); 
                elif action == "help":
                    print_system_message("Kullanılabilir komutlar (giriş yapılmadı): 'signin', 'signup', 'exit'", "info")
                elif action: # Boş olmayan ama tanınmayan komut
                    print_system_message(f"Geçersiz komut: {action}. 'help' yazın.", "error")
            else: 
                if user_input.lower() == "exit": break
                if user_input.lower() == "logout": 
                    is_authenticated=False; username_cache=None; 
                    active_e2e_dm_sessions.clear(); received_e2e_public_keys_cache.clear()
                    e2e_key_registered_this_session = False; e2e_pubkey_request_status.clear()
                    print_system_message("Oturum kapatıldı.", "success"); continue
                
                parts = user_input.split(" ", 2); cmd = parts[0].lower()

                if cmd == "broadcast" and len(parts) >= 2: 
                    send_secure_command(client_socket, "BROADCAST", {"content": " ".join(parts[1:])})
                elif cmd == "dm" and len(parts) == 3:
                    recipient_username, message_content = parts[1], parts[2]
                    handle_dm_command(recipient_username, message_content)
                elif cmd == "help":
                    print_system_message("Kullanılabilir komutlar: 'broadcast <mesaj>', 'dm <kullanıcı> <mesaj>', 'logout', 'exit'", "info")
                elif user_input: # Boş olmayan ama tanınmayan komut
                    print_system_message(f"Geçersiz komut: {cmd}. 'help' yazın.", "error")

    except ConnectionRefusedError: print_system_message(f"{HOST}:{PORT} adresine bağlanılamadı. Sunucu çalışıyor mu?", "error")
    # KeyboardInterrupt artık input içinde yakalanıyor.
    except Exception as e: print_system_message(f"Ana istemci döngüsünde bir hata oluştu: {e}", "error"); traceback.print_exc()
    finally:
        if client_socket: 
            try: client_socket.close()
            except: pass
        e2e_key_registered_this_session = False
        print_system_message("İstemci sonlandırıldı.", "info")

if __name__ == "__main__":
    main()