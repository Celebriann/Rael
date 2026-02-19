"""
Client de chat IRC-like en Python
Usage : python client.py [host] [port]
"""

import socket
import threading
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else '::1'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5555


def receive_messages(sock):
    """Thread qui écoute en continu les messages du serveur."""
    while True:
        try:
            data = sock.recv(1024).decode('utf-8', errors='ignore')
            if not data:
                print("\n[!] Connexion fermée par le serveur.")
                break
            # Afficher proprement sans casser la saisie en cours
            print(f"\r{data.strip()}")
            print("> ", end="", flush=True)
        except:
            break


def main():
    info = socket.getaddrinfo(HOST, PORT, socket.AF_UNSPEC, socket.SOCK_STREAM)
    family, socktype, proto,canonname, sockaddr = info[0]
    sock = socket.socket(family, socktype)

    try:
        sock.connect(sockaddr)
    except ConnectionRefusedError:
        print(f"[!] Impossible de se connecter à {HOST}:{PORT}")
        print("    Vérifiez que le serveur est bien démarré.")
        sys.exit(1)

    print(f"[*] Connecté au serveur {HOST}:{PORT}")

    # Lancer le thread d'écoute
    recv_thread = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    recv_thread.start()

    try:
        while True:
            print("> ", end="", flush=True)
            message = input()
            if not message.strip():
                continue
            sock.sendall((message + "\n").encode('utf-8'))
            if message.strip().lower() == "/quit":
                break
    except (KeyboardInterrupt, EOFError):
        print("\n[*] Déconnexion...")
        try:
            sock.sendall(("/quit\n").encode('utf-8'))
        except:
            pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()
