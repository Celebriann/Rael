# -*- coding: utf-8 -*-
"""
Client de chat IRC-like — Version Tor + TLS + E2E + UI Textual
Usage : python client.py <adresse.onion> [port]
"""

import socket
import ssl
import threading
import sys
import os
import json
import glob
import base64
import time
import asyncio
from datetime import datetime

import socks
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, BestAvailableEncryption
)

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    import hashlib

from UI import ChatApp

# ─── Configuration ────────────────────────────────────────────────────────────

if len(sys.argv) < 2:
    print("Usage : python client.py <adresse> [port] [--no-tor]")
    sys.exit(1)

HOST         = sys.argv[1]
PORT         = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 5555
NO_TOR       = "--no-tor" in sys.argv
SERVER_CERT  = "server.crt"
TOR_HOST     = "127.0.0.1"
TOR_PORT     = 9050
MAX_MSG      = 32768
USER_FILE    = "user.json"

# ─── État global ──────────────────────────────────────────────────────────────

current_channel  = None
is_owner         = False
log_file         = None
main_sock        = None
user_data        = {}
_password_raw    = ""
rsa_private_key  = None
rsa_public_key   = None
aes_keys         = {}
app: ChatApp     = None   # Instance UI


# ─── Affichage via UI ─────────────────────────────────────────────────────────

def ui_print(msg: str):
    """Envoie un message à l'UI (thread-safe)."""
    if app:
        app.call_from_thread(app.push_message, msg)


def ui_set_channel(ch):
    if app:
        app.call_from_thread(app.set_channel, ch)


def ui_set_nick(nick):
    if app:
        app.call_from_thread(app.set_nick, nick)


# ─── Tor ──────────────────────────────────────────────────────────────────────

def create_tor_socket():
    s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    s.set_proxy(socks.SOCKS5, TOR_HOST, TOR_PORT, rdns=True)
    return s


def check_tor():
    try:
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t.settimeout(2)
        t.connect((TOR_HOST, TOR_PORT))
        t.close()
        return True
    except:
        return False


# ─── Hash mot de passe ────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash argon2 pour stockage local dans user.json (non deterministe)."""
    if ARGON2_AVAILABLE:
        ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
        return ph.hash(password)
    import hashlib
    salt = hashlib.sha256(password.encode()).digest()
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000)
    return "pbkdf2:" + base64.b64encode(dk).decode()


def hash_password_server(password: str) -> str:
    """Hash deterministe PBKDF2 pour authentification serveur (toujours identique)."""
    import hashlib
    salt = hashlib.sha256(password.encode()).digest()
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000)
    return "pbkdf2:" + base64.b64encode(dk).decode()


def verify_password(stored: str, password: str) -> bool:
    if stored.startswith("pbkdf2:"):
        import hashlib
        salt = hashlib.sha256(password.encode()).digest()
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000)
        return stored == "pbkdf2:" + base64.b64encode(dk).decode()
    if ARGON2_AVAILABLE:
        ph = PasswordHasher()
        try:
            return ph.verify(stored, password)
        except:
            return False
    return False


# ─── RSA ──────────────────────────────────────────────────────────────────────

def generate_rsa_keys():
    pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return pk, pk.public_key()

def private_key_to_encrypted_pem(pk, pwd):
    return pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8,
                            BestAvailableEncryption(pwd.encode())).decode()

def load_private_key_from_pem(pem, pwd):
    return serialization.load_pem_private_key(pem.encode(), password=pwd.encode())

def public_key_to_b64(pk) -> str:
    return base64.b64encode(pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)).decode()

def b64_to_public_key(b64):
    return serialization.load_pem_public_key(base64.b64decode(b64))

def rsa_encrypt(pk, data: bytes) -> str:
    return base64.b64encode(pk.encrypt(data, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode()

def rsa_decrypt(pk, b64: str) -> bytes:
    return pk.decrypt(base64.b64decode(b64), padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))


# ─── AES ──────────────────────────────────────────────────────────────────────

def generate_aes_key(): return os.urandom(32)

def aes_encrypt(key, plaintext):
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce).decode() + ":" + base64.b64encode(ct).decode()

def aes_decrypt(key, enc):
    n, c = enc.split(":", 1)
    return AESGCM(key).decrypt(base64.b64decode(n), base64.b64decode(c), None).decode()


# ─── Profil ───────────────────────────────────────────────────────────────────

def load_user_from_file(nick: str, pwd: str, bio: str = None):
    """
    Charge ou crée le profil utilisateur.
    Retourne (data, error_msg). error_msg est None si succès.
    """
    global rsa_private_key, rsa_public_key, _password_raw

    _password_raw = pwd

    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Vérifier que le pseudo correspond au profil local
        if data.get('nick', '') != nick:
            return None, f"Ce profil appartient à '{data.get('nick', '?')}'. Utilisez le bon pseudo."

        # Vérifier le mot de passe
        if not verify_password(data.get('password_hash', ''), pwd):
            return None, "Mot de passe incorrect."

        # Charger clé RSA
        if 'rsa_private_key' in data:
            try:
                rsa_private_key = load_private_key_from_pem(data['rsa_private_key'], pwd)
                rsa_public_key  = rsa_private_key.public_key()
            except:
                return None, "Impossible de déchiffrer la clé RSA."
        else:
            rsa_private_key, rsa_public_key = generate_rsa_keys()
            data['rsa_private_key'] = private_key_to_encrypted_pem(rsa_private_key, pwd)
            save_user(data)

        data['password_hash_send'] = hash_password_server(pwd)
        return data, None

    else:
        # Nouveau compte
        if bio is None:
            return None, "Compte introuvable. Utilisez 'Créer un compte'."

        rsa_private_key, rsa_public_key = generate_rsa_keys()
        pw_hash      = hash_password(pwd)         # argon2 pour user.json local
        pw_hash_send = hash_password_server(pwd)  # pbkdf2 deterministe pour le serveur
        data = {
            "nick": nick,
            "password_hash": pw_hash,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "bio": bio,
            "rsa_private_key": private_key_to_encrypted_pem(rsa_private_key, pwd)
        }
        save_user(data)
        data['password_hash_send'] = pw_hash_send
        return data, None


def save_user(data):
    to_save = {k: v for k, v in data.items() if k != 'password_hash_send'}
    with open(USER_FILE, "w", encoding="utf-8") as f:
        json.dump(to_save, f, ensure_ascii=False, indent=2)


# ─── Clés AES ─────────────────────────────────────────────────────────────────

def save_aes_keys():
    user_data['aes_keys'] = {ch: rsa_encrypt(rsa_public_key, k) for ch, k in aes_keys.items()}
    save_user(user_data)

def load_aes_keys():
    for ch, enc in user_data.get('aes_keys', {}).items():
        try:
            aes_keys[ch] = rsa_decrypt(rsa_private_key, enc)
        except:
            pass


# ─── Logs salon ───────────────────────────────────────────────────────────────

def open_log(channel):
    global log_file
    close_log()
    log_file = open(f"{channel}.txt", "a", encoding="utf-8")
    log_file.write(f"\n--- Session du {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
    log_file.flush()

def close_log():
    global log_file
    if log_file:
        try: log_file.close()
        except: pass
        log_file = None

def write_log(msg):
    if log_file:
        try:
            log_file.write(msg + "\n")
            log_file.flush()
        except: pass

def save_key(channel, key):
    fn = f"{channel}.txt"
    existing = open(fn).read() if os.path.exists(fn) else ""
    lines = [l for l in existing.splitlines() if not l.startswith("__KEY__:")]
    with open(fn, "w", encoding="utf-8") as f:
        f.write(f"__KEY__:{key}\n")
        f.write("\n".join(lines))

def read_key(fn):
    try:
        with open(fn) as f:
            for line in f:
                if line.strip().startswith("__KEY__:"):
                    return line.strip()[8:]
    except: pass
    return None

def read_users(channel):
    try:
        with open(f"{channel}.txt") as f:
            for line in f:
                if line.strip().startswith("__USERS__:"):
                    return set(u for u in line.strip()[10:].split(",") if u)
    except: pass
    return set()

def save_users(channel, users):
    fn = f"{channel}.txt"
    if not os.path.exists(fn): return
    with open(fn) as f: lines = f.readlines()
    lines = [l for l in lines if not l.strip().startswith("__USERS__:")]
    pos = 1 if lines and lines[0].startswith("__KEY__:") else 0
    lines.insert(pos, f"__USERS__:{','.join(sorted(users))}\n")
    with open(fn, "w") as f: f.writelines(lines)

def add_user_to_salon(channel, nick):
    users = read_users(channel)
    if nick not in users:
        users.add(nick)
        save_users(channel, users)

def read_history(channel):
    lines = []
    try:
        with open(f"{channel}.txt") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith(("__KEY__:", "__USERS__:", "---")):
                    lines.append(s)
    except: pass
    return lines

def send_history_to_server(sock, channel):
    for line in read_history(channel):
        sock.sendall(f"__HISTORY__{channel}:{line}\n".encode())
    sock.sendall(f"__HISTORY_END__{channel}\n".encode())
    users = read_users(channel)
    if users:
        sock.sendall(f"__USERS__{channel}:{','.join(users)}\n".encode())

def sync_salons(sock):
    for fp in glob.glob("*.txt"):
        ch = os.path.splitext(fp)[0]
        key = read_key(fp)
        if key:
            sock.sendall(f"__SYNC__{ch}:{key}\n".encode())


# ─── Envoi depuis l'UI ────────────────────────────────────────────────────────

def on_send(message: str):
    """Appelé par l'UI quand l'utilisateur envoie un message."""
    global current_channel
    if not main_sock:
        ui_print("[!] Non connecté au serveur.")
        return

    if message.startswith("/"):
        main_sock.sendall((message + "\n").encode())
        if message.strip().lower() == "/quit":
            if app:
                app.stop_chat()
            app.exit()
    else:
        if current_channel and current_channel in aes_keys:
            encrypted = aes_encrypt(aes_keys[current_channel], message)
            nonce_b64, ct_b64 = encrypted.split(":", 1)
            payload = f"{nonce_b64}:{ct_b64}"
            if len(payload) > MAX_MSG:
                ui_print("[!] Message trop long.")
                return
            main_sock.sendall((payload + "\n").encode())
        elif current_channel:
            ui_print("[!] Clé manquante — attendez que le créateur soit en ligne.")
        else:
            ui_print("[!] Rejoignez un salon avec /join <salon>")


# ─── Thread de réception ──────────────────────────────────────────────────────

def receive_messages(sock):
    global current_channel, is_owner, user_data

    while True:
        try:
            data = sock.recv(MAX_MSG).decode('utf-8', errors='ignore')
            if not data:
                ui_print("[!] Connexion fermée par le serveur.")
                break

            for line in data.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue

                # Auth
                if line.startswith("__AUTH_OK__"):
                    nick = line[11:]
                    ui_print(f"[*] Connecté en tant que {nick}")
                    sock.sendall(f"__PUBKEY__{public_key_to_b64(rsa_public_key)}\n".encode())
                    continue

                if line.startswith("__AUTH_FAIL__"):
                    app.call_from_thread(app.auth_error, line[13:])
                    continue

                # Profil
                if line.startswith("__NICK_CHANGE__"):
                    new_nick = line[15:]
                    user_data['nick'] = new_nick
                    save_user(user_data)
                    ui_set_nick(new_nick)
                    continue

                if line.startswith("__BIO_UPDATE__"):
                    user_data['bio'] = line[14:]
                    save_user(user_data)
                    continue

                # Sync
                if line.startswith("__SYNC_OK__") or line.startswith("__SYNC_FAIL__"):
                    continue

                # Clé de salon
                if line.startswith("__KEY__"):
                    ch, key = line[7:].split(":", 1)
                    save_key(ch, key)
                    add_user_to_salon(ch, user_data.get('nick', ''))
                    continue

                # Générer clé AES nouveau salon
                if line.startswith("__GENERATE_AESKEY__"):
                    ch = line[19:]
                    aes_keys[ch] = generate_aes_key()
                    save_aes_keys()
                    continue

                # Rotation clé AES
                if line.startswith("__ROTATE_KEY__"):
                    payload = line[14:]
                    ch, targets_str = payload.split(":", 1)
                    aes_keys[ch] = generate_aes_key()
                    save_aes_keys()
                    if targets_str:
                        for entry in targets_str.split(";"):
                            if ":" in entry:
                                t_nick, t_pubkey = entry.split(":", 1)
                                if t_pubkey:
                                    try:
                                        enc = rsa_encrypt(b64_to_public_key(t_pubkey), aes_keys[ch])
                                        sock.sendall(f"__AESKEY__{ch}:{t_nick}:{enc}\n".encode())
                                    except: pass
                    ui_print(f"[*] Clé renouvelée pour #{ch}")
                    continue

                # Envoyer clé AES à nouveau membre
                if line.startswith("__SEND_AESKEY__"):
                    parts = line[15:].split(":", 2)
                    if len(parts) == 3:
                        ch, t_nick, pubkey_b64 = parts
                        if ch in aes_keys and pubkey_b64:
                            try:
                                enc = rsa_encrypt(b64_to_public_key(pubkey_b64), aes_keys[ch])
                                sock.sendall(f"__AESKEY__{ch}:{t_nick}:{enc}\n".encode())
                            except: pass
                    continue

                # Réception clé AES
                if line.startswith("__AESKEY__"):
                    parts = line[10:].split(":", 2)
                    if len(parts) == 3:
                        ch, _, enc_aes = parts
                        try:
                            aes_keys[ch] = rsa_decrypt(rsa_private_key, enc_aes)
                            save_aes_keys()
                            ui_print(f"[*] Clé reçue pour #{ch}")
                        except: pass
                    continue

                # Message privé — envoi
                if line.startswith("__PM_PUBKEY__"):
                    parts = line[13:].split(":", 2)
                    if len(parts) == 3:
                        t_nick, pubkey_b64, msg_text = parts
                        if pubkey_b64:
                            try:
                                enc = rsa_encrypt(b64_to_public_key(pubkey_b64), msg_text.encode())
                                sock.sendall(f"__PM__{t_nick}:{enc}\n".encode())
                            except: pass
                    continue

                # Message privé — réception
                if line.startswith("__PM__"):
                    parts = line[6:].split(":", 1)
                    if len(parts) == 2:
                        sender, enc = parts
                        try:
                            plaintext = rsa_decrypt(rsa_private_key, enc).decode()
                            ui_print(f"[MP de {sender}] {plaintext}")
                        except:
                            ui_print(f"[MP de {sender}] [déchiffrement impossible]")
                    continue

                # Historique
                if line.startswith("__SEND_HISTORY__"):
                    send_history_to_server(sock, line[16:])
                    continue

                if line.startswith("__ADD_USER__"):
                    ch, u = line[12:].split(":", 1)
                    add_user_to_salon(ch, u)
                    continue

                if line.startswith("__LOG__"):
                    write_log(line[7:])
                    continue

                # Message chiffré du salon
                if line.startswith("__MSG__"):
                    parts = line[7:].split(":", 3)
                    if len(parts) == 4:
                        ch, sender, nonce_b64, ct_b64 = parts
                        if ch in aes_keys:
                            try:
                                plaintext = aes_decrypt(aes_keys[ch], nonce_b64 + ":" + ct_b64)
                                display = f"[#{ch}] {sender}: {plaintext}"
                                if is_owner and current_channel == ch:
                                    write_log(display)
                                ui_print(display)
                            except:
                                ui_print(f"[#{ch}] {sender}: [déchiffrement échoué]")
                        else:
                            ui_print(f"[#{ch}] {sender}: [clé manquante]")
                    continue

                # Ignorer séparateurs d'historique
                if line.startswith("--- Historique") or line.startswith("--- Fin de l'historique"):
                    continue

                # Détection changements de salon
                if "Vous avez cree et rejoint #" in line:
                    current_channel = line.split("#", 1)[1].strip()
                    is_owner = True
                    open_log(current_channel)
                    ui_set_channel(current_channel)
                elif "Vous avez reactive votre salon #" in line:
                    current_channel = line.split("#", 1)[1].strip()
                    is_owner = True
                    open_log(current_channel)
                    ui_set_channel(current_channel)
                elif "Vous avez rejoint #" in line:
                    current_channel = line.split("#", 1)[1].strip()
                    is_owner = False
                    close_log()
                    ui_set_channel(current_channel)
                elif any(x in line for x in ["quitte le salon", "salon est ferme"]):
                    if is_owner:
                        close_log()
                    current_channel = None
                    is_owner = False
                    ui_set_channel(None)

                ui_print(line)

        except Exception:
            break

    close_log()


# ─── Connexion réseau ─────────────────────────────────────────────────────────

def connect_and_start(nick: str, pwd: str, bio=None):
    """
    Appelé depuis l'UI après soumission du formulaire d'auth.
    Tourne dans un thread séparé pour ne pas bloquer l'UI.
    """
    global main_sock, user_data, current_channel, is_owner, aes_keys

    # Remettre à zéro l'état de la session précédente
    current_channel = None
    is_owner        = False
    aes_keys        = {}
    if main_sock:
        try:
            main_sock.close()
        except Exception:
            pass
        main_sock = None
    close_log()

    # Charger le profil
    data, err = load_user_from_file(nick, pwd, bio)
    if err:
        app.call_from_thread(app.auth_error, err)
        return

    user_data = data
    load_aes_keys()

    # Connexion — Tor ou directe
    if NO_TOR:
        tor_active = False
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        tor_active = check_tor()
        if not tor_active:
            app.call_from_thread(app.auth_error,
                "Tor inaccessible sur le port 9050. Démarrez Tor d'abord.")
            return
        raw_sock = create_tor_socket()

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_ctx.check_hostname = False
    if os.path.exists(SERVER_CERT):
        ssl_ctx.load_verify_locations(SERVER_CERT)
        ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ssl_ctx.verify_mode = ssl.CERT_NONE

    try:
        raw_sock.connect((HOST, PORT))
        main_sock = ssl_ctx.wrap_socket(raw_sock, server_hostname="chat-server")
    except Exception as e:
        app.call_from_thread(app.auth_error, f"Connexion impossible : {e}")
        return

    # Passer à l'écran de chat
    app.call_from_thread(app.start_chat, data['nick'], on_send, tor_active)

    # Lancer la réception
    recv_thread = threading.Thread(target=receive_messages, args=(main_sock,), daemon=True)
    recv_thread.start()

    # Authentification
    time.sleep(0.3)
    # Separateur | pour eviter conflit avec les : dans le hash
    auth_msg = (
        f"__AUTH__{data['nick']}|{data['password_hash_send']}|"
        f"{data.get('created_at', '')}|{data.get('bio', '')}"
    )
    main_sock.sendall((auth_msg + "\n").encode())

    time.sleep(0.5)
    sync_salons(main_sock)

    if not ARGON2_AVAILABLE:
        ui_print("[!] argon2-cffi absent — hash PBKDF2 utilisé")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    global app

    def on_auth(nick, pwd, bio):
        """Callback de l'UI quand le formulaire est soumis."""
        t = threading.Thread(target=connect_and_start, args=(nick, pwd, bio), daemon=True)
        t.start()

    app = ChatApp(on_auth=on_auth)
    app.run()


if __name__ == "__main__":
    main()
