# -*- coding: utf-8 -*-
"""
Serveur de chat IRC-like — Version Tor + TLS + E2E
- Lance Tor automatiquement au demarrage
- Genere et affiche l'adresse .onion
- Ecoute uniquement sur 127.0.0.1
- TLS 1.3 + chiffrement E2E RSA+AES
- Pseudos uniques permanents
- Rotation de cle AES, anti-replay

Usage : python server.py
Pour changer l'adresse .onion : python server.py --reset-tor
"""

import socket
import ssl
import threading
import uuid
import base64
import os
import subprocess
import sys
import time
import shutil
import signal

HOST = '127.0.0.1'
PORT = 5555
MAX_MSG_SIZE = 65536

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
TOR_DATA_DIR    = os.path.join(BASE_DIR, "tor_data")
TOR_SERVICE_DIR = os.path.join(TOR_DATA_DIR, "chat_service")
TOR_TORRC       = os.path.join(TOR_DATA_DIR, "torrc")
TOR_PID_FILE    = os.path.join(TOR_DATA_DIR, "tor.pid")
TOR_LOG_FILE    = os.path.join(TOR_DATA_DIR, "tor.log")
TOR_HOSTNAME    = os.path.join(TOR_SERVICE_DIR, "hostname")

tor_process = None

clients = {}
channels = {}
salon_keys = {}
offline_salons = {}
user_profiles = {}
registered_nicks = {}
public_keys = {}
session_nonces = {}
lock = threading.Lock()


# ─── Tor ─────────────────────────────────────────────────────────────────────

def check_tor_installed():
    if shutil.which("tor") is None:
        print("[!] Tor n'est pas installe.")
        print("[!]   Arch  : sudo pacman -S tor")
        print("[!]   Debian: sudo apt install tor")
        return False
    return True


def write_torrc():
    os.makedirs(TOR_DATA_DIR, exist_ok=True)
    os.makedirs(TOR_SERVICE_DIR, exist_ok=True)
    os.chmod(TOR_DATA_DIR, 0o700)
    os.chmod(TOR_SERVICE_DIR, 0o700)

    with open(TOR_TORRC, "w") as f:
        f.write(f"""# torrc genere automatiquement par server.py
DataDirectory {TOR_DATA_DIR}
PidFile {TOR_PID_FILE}
Log notice file {TOR_LOG_FILE}
SocksPort 0

HiddenServiceDir {TOR_SERVICE_DIR}
HiddenServicePort {PORT} 127.0.0.1:{PORT}
""")
    os.chmod(TOR_TORRC, 0o600)


def start_tor():
    global tor_process

    if not check_tor_installed():
        return False

    write_torrc()
    print("[*] Demarrage de Tor...")

    tor_process = subprocess.Popen(
        ["tor", "-f", TOR_TORRC],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    print("[*] Attente de la generation de l'adresse .onion...")
    for i in range(60):
        if os.path.exists(TOR_HOSTNAME):
            onion = read_onion_address()
            if onion:
                print(f"[*] Tor demarre")
                return True
        time.sleep(1)
        if i > 0 and i % 10 == 0:
            print(f"[*] Toujours en attente... ({i}s)")

    print(f"[!] Timeout — consultez {TOR_LOG_FILE}")
    return False


def stop_tor():
    global tor_process
    if tor_process:
        print("[*] Arret de Tor...")
        tor_process.terminate()
        try:
            tor_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tor_process.kill()
        tor_process = None


def read_onion_address():
    try:
        with open(TOR_HOSTNAME, "r") as f:
            return f.read().strip()
    except:
        return None


def reset_tor_identity():
    """Supprime les cles Tor pour generer une nouvelle adresse .onion."""
    stop_tor()
    if os.path.exists(TOR_SERVICE_DIR):
        shutil.rmtree(TOR_SERVICE_DIR)
    print("[*] Ancienne identite Tor supprimee.")
    print("[*] Une nouvelle adresse .onion sera generee au prochain demarrage.")


# ─── TLS ─────────────────────────────────────────────────────────────────────

def generate_tls_cert():
    if os.path.exists("server.crt") and os.path.exists("server.key"):
        return
    print("[*] Generation du certificat TLS...")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", "server.key", "-out", "server.crt",
        "-days", "3650", "-nodes", "-subj", "/CN=chat-server"
    ], check=True, capture_output=True)
    os.chmod("server.key", 0o600)
    os.chmod("server.crt", 0o644)
    print("[*] Certificat TLS genere")


def create_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("server.crt", "server.key")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


# ─── Utilitaires ─────────────────────────────────────────────────────────────

def send(sock, message):
    try:
        sock.sendall((message + "\n").encode('utf-8'))
    except:
        pass


def broadcast_channel(channel, message, exclude=None):
    with lock:
        members = channels.get(channel, {}).get('members', set()).copy()
    for member in members:
        if member != exclude:
            send(member, message)


def get_nick(sock):
    return clients[sock]['nick']


def get_channel(sock):
    return clients[sock]['channel']


def is_authenticated(sock):
    return clients[sock].get('authenticated', False)


def send_history(sock, channel):
    with lock:
        history = channels.get(channel, {}).get('history', []).copy()
    if not history:
        return
    send(sock, f"--- Historique de #{channel} ---")
    for line in history:
        send(sock, line)
    send(sock, "--- Fin de l'historique ---")


def notify_key_rotation(channel):
    with lock:
        owner_sock = channels.get(channel, {}).get('owner')
        members = channels.get(channel, {}).get('members', set()).copy()
        member_keys = {
            clients[s]['nick']: clients[s].get('public_key', '')
            for s in members if s != owner_sock
        }
    if owner_sock:
        targets = ";".join(f"{n}:{k}" for n, k in member_keys.items())
        send(owner_sock, f"__ROTATE_KEY__{channel}:{targets}")


# ─── Gestion des clients ──────────────────────────────────────────────────────

def handle_client(sock, addr):
    print(f"[+] Connexion de {addr}")
    with lock:
        clients[sock] = {'nick': None, 'channel': None, 'authenticated': False, 'public_key': None}
        session_nonces[sock] = set()
    send(sock, "=== Bienvenue sur le serveur de chat (Tor + TLS) ===")

    try:
        buffer = ""
        while True:
            data = sock.recv(MAX_MSG_SIZE).decode('utf-8', errors='ignore')
            if not data:
                break
            buffer += data
            if len(buffer) > MAX_MSG_SIZE * 4:
                buffer = buffer[-MAX_MSG_SIZE:]
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if line:
                    handle_message(sock, line)
    except:
        pass
    finally:
        disconnect(sock)


def leave_channel(sock):
    nick = get_nick(sock)
    channel = get_channel(sock)
    if not channel:
        return

    with lock:
        is_owner = channels.get(channel, {}).get('owner') == sock

    if is_owner:
        with lock:
            members = channels.get(channel, {}).get('members', set()).copy()
        for member in members:
            if member != sock:
                send(member, f"[!] Le createur a quitte #{channel}, le salon est ferme.")
                with lock:
                    if member in clients:
                        clients[member]['channel'] = None
        with lock:
            history = channels.get(channel, {}).get('history', [])
            users = channels.get(channel, {}).get('users', set())
            offline_salons[channel] = nick
            salon_keys[channel + '__history'] = history
            salon_keys[channel + '__users'] = users
            channels.pop(channel, None)
        print(f"[*] Salon #{channel} hors ligne")
    else:
        with lock:
            channels[channel]['members'].discard(sock)
        broadcast_channel(channel, f"[*] {nick} a quitte #{channel}")
        notify_key_rotation(channel)

    with lock:
        if sock in clients:
            clients[sock]['channel'] = None


def handle_message(sock, message):
    nick = get_nick(sock)
    channel = get_channel(sock)

    # Anti-replay
    if message.startswith("__MSG__") or message.startswith("__PM__"):
        parts = message.split(":")
        if len(parts) >= 2:
            msg_nonce = parts[-1][:32]
            with lock:
                seen = session_nonces.get(sock, set())
                if msg_nonce in seen:
                    return
                seen.add(msg_nonce)
                if len(seen) > 10000:
                    session_nonces[sock] = set(list(seen)[-5000:])

    if message.startswith("__PUBKEY__"):
        pubkey_b64 = message[10:]
        with lock:
            if nick:
                public_keys[nick] = pubkey_b64
                clients[sock]['public_key'] = pubkey_b64
        return

    if message.startswith("__SYNC__"):
        try:
            salon_name, key = message[8:].split(":", 1)
            with lock:
                stored_key = salon_keys.get(salon_name)
            if stored_key and stored_key == key:
                with lock:
                    offline_salons[salon_name] = nick
                send(sock, f"__SYNC_OK__{salon_name}")
            else:
                send(sock, f"__SYNC_FAIL__{salon_name}")
        except:
            pass
        return

    if message.startswith("__HISTORY__"):
        try:
            salon_name, history_line = message[11:].split(":", 1)
            with lock:
                if salon_name in channels:
                    channels[salon_name]['history'].append(history_line)
        except:
            pass
        return

    if message.startswith("__HISTORY_END__"):
        return

    if message.startswith("__USERS__"):
        try:
            salon_name, users_str = message[9:].split(":", 1)
            users = set(u for u in users_str.split(",") if u)
            with lock:
                if salon_name in channels:
                    channels[salon_name]['users'].update(users)
        except:
            pass
        return

    if message.startswith("__AESKEY__"):
        try:
            parts = message[10:].split(":", 2)
            salon_name, target_nick, encrypted_key = parts[0], parts[1], parts[2]
            with lock:
                target_sock = next(
                    (s for s, c in clients.items() if c['nick'] == target_nick), None
                )
            if target_sock:
                send(target_sock, f"__AESKEY__{salon_name}:{nick}:{encrypted_key}")
        except:
            pass
        return

    if message.startswith("__PM__"):
        try:
            target_nick, encrypted = message[6:].split(":", 1)
            with lock:
                target_sock = next(
                    (s for s, c in clients.items() if c['nick'] == target_nick), None
                )
            if target_sock:
                send(target_sock, f"__PM__{nick}:{encrypted}")
            else:
                send(sock, f"[!] Utilisateur '{target_nick}' introuvable.")
        except:
            pass
        return

    if message.startswith("__AUTH__"):
        try:
            parts = message[8:].split(":", 3)
            a_nick = parts[0]
            a_hash = parts[1]
            a_created = parts[2]
            a_bio = parts[3] if len(parts) > 3 else ""

            with lock:
                already_connected = any(
                    c['nick'] == a_nick and c['authenticated']
                    for s, c in clients.items() if s != sock
                )
                if already_connected:
                    send(sock, "__AUTH_FAIL__Ce pseudo est deja connecte.")
                    return

                if a_nick in registered_nicks:
                    if registered_nicks[a_nick] != a_hash:
                        send(sock, "__AUTH_FAIL__Mot de passe incorrect.")
                        return
                    if a_nick in user_profiles:
                        user_profiles[a_nick]['bio'] = a_bio
                else:
                    registered_nicks[a_nick] = a_hash
                    user_profiles[a_nick] = {
                        'password_hash': a_hash,
                        'created_at': a_created,
                        'bio': a_bio,
                        'salons_crees': []
                    }

                clients[sock]['nick'] = a_nick
                clients[sock]['authenticated'] = True

            send(sock, f"__AUTH_OK__{a_nick}")
            print(f"[*] {a_nick} authentifie")
        except:
            send(sock, "__AUTH_FAIL__Erreur d'authentification.")
        return

    if not is_authenticated(sock):
        send(sock, "[!] Vous devez vous authentifier d'abord.")
        return

    if message.startswith("/"):
        parts = message.split(" ", 2)
        command = parts[0].lower()

        if command == "/help":
            send(sock, "--- Commandes disponibles ---")
            send(sock, "/nick <pseudo>           : Changer votre pseudo")
            send(sock, "/join <salon>            : Rejoindre/creer un salon")
            send(sock, "/leave                   : Quitter le salon actuel")
            send(sock, "/list                    : Lister les salons")
            send(sock, "/who                     : Voir les membres du salon")
            send(sock, "/msg <pseudo> <msg>      : Message prive chiffre E2E")
            send(sock, "/profil                  : Voir votre profil")
            send(sock, "/profil <pseudo>         : Voir le profil de quelqu'un")
            send(sock, "/bio <texte>             : Modifier votre bio")
            send(sock, "/setbio <texte>          : Modifier votre bio (alias /bio)")
            send(sock, "/quit                    : Se deconnecter")

        elif command == "/nick":
            if len(parts) < 2 or not parts[1].strip():
                send(sock, "[!] Usage : /nick <pseudo>")
                return
            new_nick = parts[1].strip()
            with lock:
                if new_nick in registered_nicks:
                    send(sock, f"[!] Le pseudo '{new_nick}' est deja pris.")
                    return
                old_nick = nick
                registered_nicks[new_nick] = registered_nicks.pop(old_nick, "")
                if old_nick in user_profiles:
                    user_profiles[new_nick] = user_profiles.pop(old_nick)
                if old_nick in public_keys:
                    public_keys[new_nick] = public_keys.pop(old_nick)
                clients[sock]['nick'] = new_nick
            send(sock, f"[*] Pseudo change : {old_nick} -> {new_nick}")
            send(sock, f"__NICK_CHANGE__{new_nick}")
            if channel:
                broadcast_channel(channel, f"[*] {old_nick} s'appelle maintenant {new_nick}", exclude=sock)

        elif command == "/join":
            if len(parts) < 2 or not parts[1].strip():
                send(sock, "[!] Usage : /join <salon>")
                return
            new_channel = parts[1].strip().lstrip("#")

            if channel:
                leave_channel(sock)

            with lock:
                already_exists = new_channel in channels
                is_offline = new_channel in offline_salons
                is_returning_owner = is_offline and offline_salons.get(new_channel) == nick

            if already_exists:
                with lock:
                    channels[new_channel]['members'].add(sock)
                    channels[new_channel]['users'].add(nick)
                    clients[sock]['channel'] = new_channel
                    owner_sock = channels[new_channel].get('owner')
                    joiner_pubkey = public_keys.get(nick, "")
                send(sock, f"[*] Vous avez rejoint #{new_channel}")
                broadcast_channel(new_channel, f"[*] {nick} a rejoint #{new_channel}", exclude=sock)
                if owner_sock and owner_sock != sock:
                    send(owner_sock, f"__SEND_AESKEY__{new_channel}:{nick}:{joiner_pubkey}")
                    send(owner_sock, f"__ADD_USER__{new_channel}:{nick}")
                send_history(sock, new_channel)

            elif is_returning_owner:
                with lock:
                    saved_history = salon_keys.pop(new_channel + '__history', [])
                    saved_users = salon_keys.pop(new_channel + '__users', set())
                    saved_users.add(nick)
                    channels[new_channel] = {
                        'members': {sock},
                        'owner': sock,
                        'history': saved_history,
                        'users': saved_users
                    }
                    clients[sock]['channel'] = new_channel
                    offline_salons.pop(new_channel, None)
                send(sock, f"[*] Vous avez reactive votre salon #{new_channel}")
                send(sock, f"[*] Vous etes le createur : le salon sera ferme si vous partez.")
                send(sock, f"__SEND_HISTORY__{new_channel}")
                send_history(sock, new_channel)

            elif is_offline:
                send(sock, f"[!] Le salon #{new_channel} est hors ligne, en attente de son createur.")

            else:
                new_key = str(uuid.uuid4())
                with lock:
                    channels[new_channel] = {
                        'members': {sock},
                        'owner': sock,
                        'history': [],
                        'users': {nick}
                    }
                    clients[sock]['channel'] = new_channel
                    salon_keys[new_channel] = new_key
                    if nick in user_profiles:
                        user_profiles[nick].setdefault('salons_crees', []).append(new_channel)
                send(sock, f"[*] Vous avez cree et rejoint #{new_channel}")
                send(sock, f"[*] Vous etes le createur : le salon sera ferme si vous partez.")
                send(sock, f"[*] L'historique est enregisté dans le dossier txt")
                send(sock, f"__KEY__{new_channel}:{new_key}")
                send(sock, f"__GENERATE_AESKEY__{new_channel}")

        elif command == "/leave":
            if not channel:
                send(sock, "[!] Vous n'etes dans aucun salon.")
                return
            leave_channel(sock)
            send(sock, "[*] Vous avez quitte le salon.")

        elif command == "/list":
            with lock:
                active = {ch: len(info['members']) for ch, info in channels.items() if info['members']}
                offline = dict(offline_salons)
            if not active and not offline:
                send(sock, "[*] Aucun salon disponible.")
            else:
                send(sock, "--- Salons disponibles ---")
                for ch, count in active.items():
                    send(sock, f"  [EN LIGNE]   #{ch} ({count} membre{'s' if count > 1 else ''})")
                for ch, owner_nick in offline.items():
                    send(sock, f"  [HORS LIGNE] #{ch} (createur: {owner_nick})")

        elif command == "/who":
            if not channel:
                send(sock, "[!] Vous n'etes dans aucun salon.")
                return
            with lock:
                members_now = [clients[s]['nick'] for s in channels.get(channel, {}).get('members', set())]
                all_users = channels.get(channel, {}).get('users', set())
                owner_sock = channels.get(channel, {}).get('owner')
                owner_nick = clients[owner_sock]['nick'] if owner_sock in clients else "?"
            send(sock, f"--- Membres de #{channel} (createur: {owner_nick}) ---")
            send(sock, f"  En ligne       : {', '.join(members_now)}")
            past = [u for u in all_users if u not in members_now]
            if past:
                send(sock, f"  Passes par ici : {', '.join(past)}")

        elif command == "/profil":
            target = parts[1].strip() if len(parts) > 1 else nick
            with lock:
                profile = user_profiles.get(target)
            if not profile:
                send(sock, f"[!] Utilisateur '{target}' inconnu.")
                return
            send(sock, f"--- Profil de {target} ---")
            send(sock, f"  Pseudo        : {target}")
            send(sock, f"  Membre depuis : {profile.get('created_at', '?')}")
            send(sock, f"  Bio           : {profile.get('bio', '') or '(aucune)'}")
            crees = profile.get('salons_crees', [])
            send(sock, f"  Salons crees  : {', '.join(['#' + s for s in crees]) if crees else '(aucun)'}")

        elif command == "/setbio":
            if len(parts) < 2:
                send(sock, "[!] Usage : /setbio <texte>")
                return
            new_bio = message[8:].strip()
            with lock:
                if nick in user_profiles:
                    user_profiles[nick]['bio'] = new_bio
            send(sock, "[*] Bio mise a jour.")
            send(sock, f"__BIO_UPDATE__{new_bio}")

        elif command == "/msg":
            if len(parts) < 3:
                send(sock, "[!] Usage : /msg <pseudo> <message>")
                return
            target_nick = parts[1].strip()
            with lock:
                target_pubkey = public_keys.get(target_nick, "")
                target_online = any(
                    c['nick'] == target_nick and c['authenticated']
                    for c in clients.values()
                )
            if not target_online:
                send(sock, f"[!] Utilisateur '{target_nick}' introuvable.")
                return
            send(sock, f"__PM_PUBKEY__{target_nick}:{target_pubkey}:{parts[2]}")

        elif command == "/quit":
            send(sock, "[*] Au revoir !")
            sock.close()

        else:
            send(sock, f"[!] Commande inconnue : {command}. Tapez /help.")

    else:
        if not channel:
            send(sock, "[!] Rejoignez un salon d'abord avec /join <salon>")
            return
        formatted = f"__MSG__{channel}:{nick}:{message}"
        with lock:
            if channel in channels:
                channels[channel]['history'].append(formatted)
        broadcast_channel(channel, formatted, exclude=sock)
        send(sock, formatted)
        with lock:
            owner_sock = channels.get(channel, {}).get('owner')
        if owner_sock and owner_sock != sock:
            send(owner_sock, f"__LOG__{formatted}")


def disconnect(sock):
    nick = get_nick(sock) if sock in clients else "?"
    channel = get_channel(sock) if sock in clients else None
    print(f"[-] Deconnexion de {nick}")
    if channel:
        leave_channel(sock)
    with lock:
        clients.pop(sock, None)
        session_nonces.pop(sock, None)
    try:
        sock.close()
    except:
        pass


def main():
    # Gestion de --reset-tor
    if "--reset-tor" in sys.argv:
        reset_tor_identity()
        print("[*] Relancez server.py pour demarrer avec une nouvelle adresse.")
        sys.exit(0)

    # Gestion propre de Ctrl+C
    def signal_handler(sig, frame):
        print("\n[*] Arret du serveur...")
        stop_tor()
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # TLS
    generate_tls_cert()
    ssl_ctx = create_ssl_context()

    # Tor
    tor_ok = start_tor()
    onion = read_onion_address() if tor_ok else None

    # Socket serveur
    raw_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_server.bind((HOST, PORT))
    raw_server.listen()

    print(f"\n{'='*50}")
    print(f"[*] Serveur demarre sur {HOST}:{PORT}")
    print(f"[*] TLS 1.3 + E2E actifs")
    if onion:
        print(f"[*] Adresse .onion : {onion}")
        print(f"[*] Commande client : python client.py {onion} {PORT}")
    else:
        print(f"[!] Tor non disponible — serveur accessible en local uniquement")
    print(f"{'='*50}\n")
    print(f"[*] Pour changer l'adresse .onion : python server.py --reset-tor")

    try:
        while True:
            raw_sock, addr = raw_server.accept()
            try:
                tls_sock = ssl_ctx.wrap_socket(raw_sock, server_side=True)
                thread = threading.Thread(target=handle_client, args=(tls_sock, addr), daemon=True)
                thread.start()
            except ssl.SSLError as e:
                print(f"[!] Erreur TLS : {e}")
                raw_sock.close()
    except KeyboardInterrupt:
        pass
    finally:
        raw_server.close()
        stop_tor()


if __name__ == "__main__":
    main()
