# -*- coding: utf-8 -*-
"""
Client de chat IRC-like — Version Tor + TLS + E2E
- Toutes les connexions passent par Tor (SOCKS5 sur 127.0.0.1:9050)
- Connexion vers une adresse .onion
- TLS 1.3 dans le tunnel Tor
- Chiffrement E2E RSA+AES
- Argon2id pour le mot de passe
- Cle privee RSA protegee par mot de passe
- Rotation de cle AES
- Messages prives chiffres E2E
- Anti-replay

Usage : python client.py <adresse.onion> [port]
Exemple : python client.py abc123xyz.onion 5555
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
import getpass
from datetime import datetime

# Tor SOCKS5
import socks  # pip install pysocks

# Cryptographie
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat,
    BestAvailableEncryption
)

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    import hashlib

# ─── Configuration ────────────────────────────────────────────────────────────

if len(sys.argv) < 2:
    print("Usage : python client.py <adresse.onion> [port]")
    print("Exemple : python client.py abc123.onion 5555")
    sys.exit(1)

HOST = sys.argv[1]   # Adresse .onion du serveur
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5555
SERVER_CERT = "server.crt"

TOR_PROXY_HOST = "127.0.0.1"
TOR_PROXY_PORT = 9050
MAX_MSG = 32768
USER_FILE = "user.json"

current_channel = None
is_owner = False
log_file = None
main_sock = None
user_data = {}
_password_raw = ""

rsa_private_key = None
rsa_public_key = None
aes_keys = {}


# ─── Tor ─────────────────────────────────────────────────────────────────────

def create_tor_socket():
    """Cree un socket qui route via Tor (SOCKS5)."""
    s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    s.set_proxy(socks.SOCKS5, TOR_PROXY_HOST, TOR_PROXY_PORT, rdns=True)
    return s


def check_tor():
    """Verifie que Tor tourne bien sur le port 9050."""
    try:
        test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test.settimeout(2)
        test.connect((TOR_PROXY_HOST, TOR_PROXY_PORT))
        test.close()
        return True
    except:
        return False


# ─── Hash mot de passe ────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    if ARGON2_AVAILABLE:
        print("[DEBUG] argon2 utilise")
        ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
        return ph.hash(password)
    else:
        print("[DEBUG] PBKDF2 utilise")
        import hashlib
        salt = hashlib.sha256(password.encode()).digest()
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000)
        return "pbkdf2:" + base64.b64encode(dk).decode()


def verify_password(stored_hash: str, password: str) -> bool:
    if stored_hash.startswith("pbkdf2:"):
        import hashlib
        salt = hashlib.sha256(password.encode()).digest()
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000)
        return stored_hash == "pbkdf2:" + base64.b64encode(dk).decode()
    if ARGON2_AVAILABLE:
        ph = PasswordHasher()
        try:
            return ph.verify(stored_hash, password)
        except:
            return False
    return False


# ─── RSA ─────────────────────────────────────────────────────────────────────

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def private_key_to_encrypted_pem(private_key, password: str) -> str:
    pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(password.encode('utf-8'))
    )
    return pem.decode('utf-8')


def load_private_key_from_pem(pem: str, password: str):
    return serialization.load_pem_private_key(pem.encode('utf-8'), password=password.encode('utf-8'))


def public_key_to_b64(public_key) -> str:
    pem = public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(pem).decode('utf-8')


def b64_to_public_key(b64: str):
    return serialization.load_pem_public_key(base64.b64decode(b64))


def rsa_encrypt(public_key, data: bytes) -> str:
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted).decode('utf-8')


def rsa_decrypt(private_key, b64_data: str) -> bytes:
    return private_key.decrypt(
        base64.b64decode(b64_data),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


# ─── AES ─────────────────────────────────────────────────────────────────────

def generate_aes_key() -> bytes:
    return os.urandom(32)


def aes_encrypt(key: bytes, plaintext: str) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return base64.b64encode(nonce).decode() + ":" + base64.b64encode(ct).decode()


def aes_decrypt(key: bytes, encrypted: str) -> str:
    nonce_b64, ct_b64 = encrypted.split(":", 1)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(base64.b64decode(nonce_b64), base64.b64decode(ct_b64), None).decode('utf-8')


# ─── Profil utilisateur ───────────────────────────────────────────────────────

def load_user():
    global rsa_private_key, rsa_public_key, _password_raw

    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(f"[*] Profil charge : {data['nick']}")
        _password_raw = getpass.getpass("Mot de passe : ")

        if not verify_password(data.get('password_hash', ''), _password_raw):
            print("[!] Mot de passe incorrect.")
            sys.exit(1)

        if 'rsa_private_key' in data:
            try:
                rsa_private_key = load_private_key_from_pem(data['rsa_private_key'], _password_raw)
                rsa_public_key = rsa_private_key.public_key()
                print("[*] Cles RSA chargees")
            except:
                print("[!] Impossible de dechiffrer la cle RSA.")
                sys.exit(1)
        else:
            rsa_private_key, rsa_public_key = generate_rsa_keys()
            data['rsa_private_key'] = private_key_to_encrypted_pem(rsa_private_key, _password_raw)
            save_user(data)

        data['password_hash_send'] = hash_password(_password_raw)
        return data
    else:
        print("=== Premiere connexion : creation de votre profil ===")
        nick = input("Pseudo : ").strip()
        while not nick:
            nick = input("Pseudo (obligatoire) : ").strip()
        _password_raw = getpass.getpass("Mot de passe : ")
        while not _password_raw:
            _password_raw = getpass.getpass("Mot de passe (obligatoire) : ")
        bio = input("Bio (optionnel) : ").strip()
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        rsa_private_key, rsa_public_key = generate_rsa_keys()
        pw_hash = hash_password(_password_raw)

        data = {
            "nick": nick,
            "password_hash": pw_hash,
            "created_at": created_at,
            "bio": bio,
            "rsa_private_key": private_key_to_encrypted_pem(rsa_private_key, _password_raw)
        }
        save_user(data)
        data['password_hash_send'] = pw_hash
        print(f"[*] Profil cree pour {nick}")
        return data


def save_user(data):
    to_save = {k: v for k, v in data.items() if k != 'password_hash_send'}
    with open(USER_FILE, "w", encoding="utf-8") as f:
        json.dump(to_save, f, ensure_ascii=False, indent=2)


# ─── Cles AES ────────────────────────────────────────────────────────────────

def save_aes_keys():
    encrypted_keys = {ch: rsa_encrypt(rsa_public_key, key) for ch, key in aes_keys.items()}
    user_data['aes_keys'] = encrypted_keys
    save_user(user_data)


def load_aes_keys():
    for channel, enc_key in user_data.get('aes_keys', {}).items():
        try:
            aes_keys[channel] = rsa_decrypt(rsa_private_key, enc_key)
        except:
            pass


# ─── Fichiers de salon ────────────────────────────────────────────────────────

def open_log(channel):
    global log_file
    close_log()
    log_file = open(f"{channel}.txt", "a", encoding="utf-8")
    log_file.write(f"\n--- Session du {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
    log_file.flush()


def close_log():
    global log_file
    if log_file:
        try:
            log_file.close()
        except:
            pass
        log_file = None


def write_log(message):
    if log_file:
        try:
            log_file.write(message + "\n")
            log_file.flush()
        except:
            pass


def save_key(channel, key):
    filename = f"{channel}.txt"
    existing = open(filename).read() if os.path.exists(filename) else ""
    lines = [l for l in existing.splitlines() if not l.startswith("__KEY__:")]
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"__KEY__:{key}\n")
        f.write("\n".join(lines))


def read_key(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("__KEY__:"):
                    return line.strip()[8:]
    except:
        pass
    return None


def read_users(channel):
    try:
        with open(f"{channel}.txt", "r", encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("__USERS__:"):
                    return set(u for u in line.strip()[10:].split(",") if u)
    except:
        pass
    return set()


def save_users(channel, users):
    filename = f"{channel}.txt"
    if not os.path.exists(filename):
        return
    with open(filename, "r", encoding="utf-8") as f:
        lines = f.readlines()
    new_lines = [l for l in lines if not l.strip().startswith("__USERS__:")]
    pos = 1 if new_lines and new_lines[0].startswith("__KEY__:") else 0
    new_lines.insert(pos, f"__USERS__:{','.join(sorted(users))}\n")
    with open(filename, "w", encoding="utf-8") as f:
        f.writelines(new_lines)


def add_user_to_salon(channel, nick):
    users = read_users(channel)
    if nick not in users:
        users.add(nick)
        save_users(channel, users)


def read_history(channel):
    lines = []
    try:
        with open(f"{channel}.txt", "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith(("__KEY__:", "__USERS__:", "---")):
                    lines.append(s)
    except:
        pass
    return lines


def send_history_to_server(sock, channel):
    lines = read_history(channel)
    for line in lines:
        sock.sendall(f"__HISTORY__{channel}:{line}\n".encode('utf-8'))
    sock.sendall(f"__HISTORY_END__{channel}\n".encode('utf-8'))
    users = read_users(channel)
    if users:
        sock.sendall(f"__USERS__{channel}:{','.join(users)}\n".encode('utf-8'))
    if lines:
        print(f"[*] Historique #{channel} envoye ({len(lines)} messages)")


def sync_salons(sock):
    synced = 0
    for filepath in glob.glob("*.txt"):
        channel = os.path.splitext(filepath)[0]
        key = read_key(filepath)
        if key:
            sock.sendall(f"__SYNC__{channel}:{key}\n".encode('utf-8'))
            synced += 1
    if synced:
        print(f"[*] Synchronisation de {synced} salon(s)...")


# ─── Thread de reception ──────────────────────────────────────────────────────

def receive_messages(sock):
    global current_channel, is_owner, user_data

    while True:
        try:
            data = sock.recv(MAX_MSG).decode('utf-8', errors='ignore')
            if not data:
                print("\n[!] Connexion fermee.")
                break

            for line in data.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue

                if line.startswith("__AUTH_OK__"):
                    print(f"\r[*] Connecte en tant que {line[11:]}")
                    sock.sendall(f"__PUBKEY__{public_key_to_b64(rsa_public_key)}\n".encode('utf-8'))
                    print("> ", end="", flush=True)
                    continue

                if line.startswith("__AUTH_FAIL__"):
                    print(f"\r[!] Echec auth : {line[13:]}")
                    os._exit(1)

                if line.startswith("__NICK_CHANGE__"):
                    user_data['nick'] = line[15:]
                    save_user(user_data)
                    continue

                if line.startswith("__BIO_UPDATE__"):
                    user_data['bio'] = line[14:]
                    save_user(user_data)
                    continue

                if line.startswith("__SYNC_OK__"):
                    print(f"\r[*] #{line[11:]} synchronise")
                    print("> ", end="", flush=True)
                    continue

                if line.startswith("__SYNC_FAIL__"):
                    continue

                if line.startswith("__KEY__"):
                    ch, key = line[7:].split(":", 1)
                    save_key(ch, key)
                    add_user_to_salon(ch, user_data.get('nick', ''))
                    continue

                if line.startswith("__GENERATE_AESKEY__"):
                    ch = line[19:]
                    new_key = generate_aes_key()
                    aes_keys[ch] = new_key
                    save_aes_keys()
                    print(f"\r[*] Cle AES generee pour #{ch}")
                    print("> ", end="", flush=True)
                    continue

                if line.startswith("__ROTATE_KEY__"):
                    payload = line[14:]
                    ch, targets_str = payload.split(":", 1)
                    new_key = generate_aes_key()
                    aes_keys[ch] = new_key
                    save_aes_keys()
                    if targets_str:
                        for entry in targets_str.split(";"):
                            if ":" in entry:
                                t_nick, t_pubkey = entry.split(":", 1)
                                if t_pubkey:
                                    try:
                                        t_key = b64_to_public_key(t_pubkey)
                                        enc = rsa_encrypt(t_key, new_key)
                                        sock.sendall(f"__AESKEY__{ch}:{t_nick}:{enc}\n".encode('utf-8'))
                                    except:
                                        pass
                    print(f"\r[*] Rotation de cle pour #{ch} effectuee")
                    print("> ", end="", flush=True)
                    continue

                if line.startswith("__SEND_AESKEY__"):
                    parts = line[15:].split(":", 2)
                    if len(parts) == 3:
                        ch, t_nick, pubkey_b64 = parts
                        if ch in aes_keys and pubkey_b64:
                            try:
                                t_key = b64_to_public_key(pubkey_b64)
                                enc = rsa_encrypt(t_key, aes_keys[ch])
                                sock.sendall(f"__AESKEY__{ch}:{t_nick}:{enc}\n".encode('utf-8'))
                            except:
                                pass
                    continue

                if line.startswith("__AESKEY__"):
                    parts = line[10:].split(":", 2)
                    if len(parts) == 3:
                        ch, sender, enc_aes = parts
                        try:
                            aes_keys[ch] = rsa_decrypt(rsa_private_key, enc_aes)
                            save_aes_keys()
                            print(f"\r[*] Cle recue pour #{ch}")
                            print("> ", end="", flush=True)
                        except:
                            pass
                    continue

                if line.startswith("__PM_PUBKEY__"):
                    parts = line[13:].split(":", 2)
                    if len(parts) == 3:
                        t_nick, pubkey_b64, msg_text = parts
                        if pubkey_b64:
                            try:
                                t_pubkey = b64_to_public_key(pubkey_b64)
                                enc = rsa_encrypt(t_pubkey, msg_text.encode('utf-8'))
                                sock.sendall(f"__PM__{t_nick}:{enc}\n".encode('utf-8'))
                            except:
                                pass
                    continue

                if line.startswith("__PM__"):
                    parts = line[6:].split(":", 1)
                    if len(parts) == 2:
                        sender, enc = parts
                        try:
                            plaintext = rsa_decrypt(rsa_private_key, enc).decode('utf-8')
                            print(f"\r[MP de {sender}] {plaintext}")
                            print("> ", end="", flush=True)
                        except:
                            print(f"\r[MP de {sender}] [dechiffrement impossible]")
                            print("> ", end="", flush=True)
                    continue

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

                if line.startswith("__MSG__"):
                    parts = line[7:].split(":", 3)
                    if len(parts) == 4:
                        ch, sender, nonce_b64, ct_b64 = parts
                        # Messages de l'historique (envoyes avant de rejoindre) : stocker sans afficher
                        is_history = (ch == current_channel and not is_owner) or ch != current_channel
                        if ch in aes_keys:
                            try:
                                plaintext = aes_decrypt(aes_keys[ch], nonce_b64 + ":" + ct_b64)
                                display = f"[#{ch}] {sender}: {plaintext}"
                                # Toujours logger si createur
                                if is_owner and current_channel == ch:
                                    write_log(display)
                                # Afficher uniquement les nouveaux messages (pas le replay d'historique)
                                print(f"\r{display}")
                                print("> ", end="", flush=True)
                            except:
                                print(f"\r[#{ch}] {sender}: [dechiffrement echoue]")
                                print("> ", end="", flush=True)
                        else:
                            print(f"\r[#{ch}] {sender}: [cle manquante]")
                            print("> ", end="", flush=True)
                    continue

                # Ignorer les separateurs d'historique (ne pas afficher)
                if line.startswith("--- Historique") or line.startswith("--- Fin de l'historique"):
                    continue

                if "Vous avez cree et rejoint #" in line:
                    current_channel = line.split("#", 1)[1].strip()
                    is_owner = True
                    open_log(current_channel)
                elif "Vous avez reactive votre salon #" in line:
                    current_channel = line.split("#", 1)[1].strip()
                    is_owner = True
                    open_log(current_channel)
                elif "Vous avez rejoint #" in line:
                    current_channel = line.split("#", 1)[1].strip()
                    is_owner = False
                    close_log()
                elif any(x in line for x in ["quitte le salon", "salon est ferme", "ferme par son createur"]):
                    if is_owner:
                        close_log()
                    current_channel = None
                    is_owner = False

                print(f"\r{line}")
                print("> ", end="", flush=True)

        except Exception as e:
            break

    close_log()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    global main_sock, user_data

    # Verifier Tor
    if not check_tor():
        print(f"[!] Tor n'est pas accessible sur {TOR_PROXY_HOST}:{TOR_PROXY_PORT}")
        print(f"[!] Verifiez que Tor est demarre : sudo systemctl start tor")
        sys.exit(1)
    print(f"[*] Tor detecte sur le port {TOR_PROXY_PORT}")

    user_data = load_user()
    load_aes_keys()

    # Creer le socket via Tor
    raw_sock = create_tor_socket()

    # Envelopper avec TLS
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_ctx.check_hostname = False

    if os.path.exists(SERVER_CERT):
        ssl_ctx.load_verify_locations(SERVER_CERT)
        ssl_ctx.verify_mode = ssl.CERT_REQUIRED
        print(f"[*] Verification du certificat serveur activee")
    else:
        ssl_ctx.verify_mode = ssl.CERT_NONE
        print(f"[!] server.crt absent — connexion sans verification MITM")

    print(f"[*] Connexion a {HOST}:{PORT} via Tor...")
    print(f"[*] (La connexion peut prendre quelques secondes)")

    try:
        raw_sock.connect((HOST, PORT))
        main_sock = ssl_ctx.wrap_socket(raw_sock, server_hostname="chat-server")
    except Exception as e:
        print(f"[!] Impossible de se connecter : {e}")
        sys.exit(1)

    print(f"[*] Connecte via Tor + TLS 1.3")
    if not ARGON2_AVAILABLE:
        print("[!] argon2-cffi non fonctionnel — hash PBKDF2 utilise")
        print("[!] Pour corriger : pip install argon2-cffi --break-system-packages")

    recv_thread = threading.Thread(target=receive_messages, args=(main_sock,), daemon=True)
    recv_thread.start()

    time.sleep(0.3)
    auth_msg = (
        f"__AUTH__{user_data['nick']}:"
        f"{user_data['password_hash_send']}:"
        f"{user_data.get('created_at', '')}:"
        f"{user_data.get('bio', '')}"
    )
    main_sock.sendall((auth_msg + "\n").encode('utf-8'))

    time.sleep(0.5)
    sync_salons(main_sock)

    try:
        while True:
            print("> ", end="", flush=True)
            message = input()
            if not message.strip():
                continue

            if message.startswith("/"):
                main_sock.sendall((message + "\n").encode('utf-8'))
                if message.strip().lower() == "/quit":
                    break
            else:
                if current_channel and current_channel in aes_keys:
                    encrypted = aes_encrypt(aes_keys[current_channel], message)
                    nonce_b64, ct_b64 = encrypted.split(":", 1)
                    payload = f"{nonce_b64}:{ct_b64}"
                    if len(payload) > MAX_MSG:
                        print("[!] Message trop long.")
                        continue
                    main_sock.sendall((payload + "\n").encode('utf-8'))
                elif current_channel:
                    print("[!] Cle manquante — attendez que le createur soit en ligne.")
                else:
                    print("[!] Rejoignez un salon avec /join <salon>")

    except (KeyboardInterrupt, EOFError):
        print("\n[*] Deconnexion...")
        try:
            main_sock.sendall(("/quit\n").encode('utf-8'))
        except:
            pass
    finally:
        close_log()
        try:
            main_sock.close()
        except:
            pass


if __name__ == "__main__":
    main()
