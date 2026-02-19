"""
Serveur de chat IRC-like en Python
Commandes supportées : /nick, /join, /leave, /list, /msg, /quit, /help
"""

import socket
import threading

HOST = '::'
PORT = 5555

clients = {}   # socket -> {nick, channel}
channels = {}  # channel_name -> set of sockets
lock = threading.Lock()


def send(sock, message):
    try:
        sock.sendall((message + "\n").encode('utf-8'))
    except:
        pass


def broadcast_channel(channel, message, exclude=None):
    with lock:
        members = channels.get(channel, set()).copy()
    for member in members:
        if member != exclude:
            send(member, message)


def get_nick(sock):
    return clients[sock]['nick']


def get_channel(sock):
    return clients[sock]['channel']


def handle_client(sock, addr):
    print(f"[+] Connexion de {addr}")

    with lock:
        clients[sock] = {'nick': f"user_{addr[1]}", 'channel': None}

    send(sock, "=== Bienvenue sur le serveur de chat ===")
    send(sock, f"Votre pseudo par défaut : {get_nick(sock)}")
    send(sock, "Tapez /help pour voir les commandes disponibles.")

    try:
        buffer = ""
        while True:
            data = sock.recv(1024).decode('utf-8', errors='ignore')
            if not data:
                break

            buffer += data
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if line:
                    handle_message(sock, line)
    except:
        pass
    finally:
        disconnect(sock)


def handle_message(sock, message):
    nick = get_nick(sock)
    channel = get_channel(sock)

    if message.startswith("/"):
        parts = message.split(" ", 2)
        command = parts[0].lower()

        # /help
        if command == "/help":
            send(sock, "--- Commandes disponibles ---")
            send(sock, "/nick <pseudo>       : Changer votre pseudo")
            send(sock, "/join <salon>        : Rejoindre un salon")
            send(sock, "/leave               : Quitter le salon actuel")
            send(sock, "/list                : Lister les salons actifs")
            send(sock, "/who                 : Voir les membres du salon actuel")
            send(sock, "/msg <pseudo> <msg>  : Message privé")
            send(sock, "/quit                : Se déconnecter")

        # /nick <pseudo>
        elif command == "/nick":
            if len(parts) < 2 or not parts[1].strip():
                send(sock, "[!] Usage : /nick <pseudo>")
                return
            new_nick = parts[1].strip()
            # Vérifier unicité
            with lock:
                taken = any(
                    c['nick'] == new_nick
                    for s, c in clients.items() if s != sock
                )
            if taken:
                send(sock, f"[!] Le pseudo '{new_nick}' est déjà utilisé.")
                return
            old_nick = nick
            with lock:
                clients[sock]['nick'] = new_nick
            send(sock, f"[*] Pseudo changé : {old_nick} -> {new_nick}")
            if channel:
                broadcast_channel(channel, f"[*] {old_nick} s'appelle maintenant {new_nick}", exclude=sock)

        # /join <salon>
        elif command == "/join":
            if len(parts) < 2 or not parts[1].strip():
                send(sock, "[!] Usage : /join <salon>")
                return
            new_channel = parts[1].strip().lstrip("#")
            # Quitter l'ancien salon
            if channel:
                leave_channel(sock)
            # Rejoindre le nouveau
            with lock:
                if new_channel not in channels:
                    channels[new_channel] = set()
                channels[new_channel].add(sock)
                clients[sock]['channel'] = new_channel
            send(sock, f"[*] Vous avez rejoint #{new_channel}")
            broadcast_channel(new_channel, f"[*] {get_nick(sock)} a rejoint #{new_channel}", exclude=sock)

        # /leave
        elif command == "/leave":
            if not channel:
                send(sock, "[!] Vous n'êtes dans aucun salon.")
                return
            leave_channel(sock)
            send(sock, "[*] Vous avez quitté le salon.")

        # /list
        elif command == "/list":
            with lock:
                active = {ch: len(members) for ch, members in channels.items() if members}
            if not active:
                send(sock, "[*] Aucun salon actif pour le moment.")
            else:
                send(sock, "--- Salons actifs ---")
                for ch, count in active.items():
                    send(sock, f"  #{ch} ({count} membre{'s' if count > 1 else ''})")

        # /who
        elif command == "/who":
            if not channel:
                send(sock, "[!] Vous n'êtes dans aucun salon.")
                return
            with lock:
                members = [clients[s]['nick'] for s in channels.get(channel, set())]
            send(sock, f"--- Membres de #{channel} ---")
            send(sock, "  " + ", ".join(members))

        # /msg <pseudo> <message>
        elif command == "/msg":
            if len(parts) < 3:
                send(sock, "[!] Usage : /msg <pseudo> <message>")
                return
            target_nick = parts[1].strip()
            private_msg = parts[2]
            target_sock = None
            with lock:
                for s, info in clients.items():
                    if info['nick'] == target_nick:
                        target_sock = s
                        break
            if not target_sock:
                send(sock, f"[!] Utilisateur '{target_nick}' introuvable.")
                return
            send(target_sock, f"[MP de {nick}] {private_msg}")
            send(sock, f"[MP à {target_nick}] {private_msg}")

        # /quit
        elif command == "/quit":
            send(sock, "[*] Au revoir !")
            sock.close()

        else:
            send(sock, f"[!] Commande inconnue : {command}. Tapez /help.")

    else:
        # Message normal dans le salon
        if not channel:
            send(sock, "[!] Rejoignez un salon d'abord avec /join <salon>")
            return
        broadcast_channel(channel, f"[#{channel}] {nick}: {message}", exclude=sock)
        send(sock, f"[#{channel}] {nick}: {message}")


def leave_channel(sock):
    nick = get_nick(sock)
    channel = get_channel(sock)
    if not channel:
        return
    with lock:
        channels[channel].discard(sock)
        if not channels[channel]:
            del channels[channel]
        clients[sock]['channel'] = None
    broadcast_channel(channel, f"[*] {nick} a quitté #{channel}")


def disconnect(sock):
    nick = get_nick(sock) if sock in clients else "?"
    channel = get_channel(sock) if sock in clients else None
    print(f"[-] Déconnexion de {nick}")
    if channel:
        leave_channel(sock)
    with lock:
        clients.pop(sock, None)
    try:
        sock.close()
    except:
        pass


def main():
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[*] Serveur démarré sur {HOST}:{PORT}")

    try:
        while True:
            sock, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(sock, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\n[*] Arrêt du serveur.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
