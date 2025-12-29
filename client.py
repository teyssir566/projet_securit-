"""
Client normal avec hash d'intégrité
P2-C1 : Détection MITM
"""
import socket
import time
import hashlib

class NormalClient:
    def __init__(self, server_host='127.0.0.1', server_port=9999):
        self.server_host = server_host
        self.server_port = server_port

    def calculate_hash(self, message):
        """Calcule le hash du message"""
        return hashlib.sha256(message.encode()).hexdigest()[:16]

    def send_message(self, message, via_mitm=False):
        port = 8888 if via_mitm else self.server_port
        label = "VIA MITM" if via_mitm else "DIRECT"

        msg_hash = self.calculate_hash(message)
        payload = f"{message}|{msg_hash}"

        print(f"\n📤 ENVOI {label}")
        print(f"Message      : {message}")
        print(f"Hash envoyé  : {msg_hash}")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            start = time.time()
            sock.connect((self.server_host, port))
            sock.send(payload.encode('utf-8'))

            response = sock.recv(4096).decode('utf-8')
            duration = time.time() - start

            print(f"\n📨 RÉPONSE SERVEUR ({duration:.3f}s)")
            print(response)

            sock.close()
            return response

        except Exception as e:
            print(f"❌ Erreur client : {e}")
            return None

    def interactive_mode(self):
        print("\n💻 CLIENT AVEC HASH - MODE INTERACTIF")
        use_mitm = False

        while True:
            msg = input("\nMessage > ").strip()

            if msg.lower() == "quit":
                break
            elif msg.lower() == "mitm":
                use_mitm = not use_mitm
                print("MITM", "ACTIVÉ" if use_mitm else "DÉSACTIVÉ")
                continue
            elif not msg:
                continue

            self.send_message(msg, via_mitm=use_mitm)

if __name__ == "__main__":
    NormalClient().interactive_mode()
