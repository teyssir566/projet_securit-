"""
Serveur de détection MITM avec vérification d'intégrité par hash
P2-C1 : Détection Man-in-the-Middle
"""
import socket
import threading
import time
import hashlib
from datetime import datetime

class DetectionServer:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.running = True

        self.seen_hashes = {}   # anti-replay
        self.client_stats = {}
        self.REPLAY_WINDOW = 30
        self.MAX_MSG_PER_MIN = 10
        self.READ_TIMEOUT = 10

    # ---------- HASH ----------
    def calculate_hash(self, message):
        return hashlib.sha256(message.encode()).hexdigest()[:16]

    def check_integrity(self, message, received_hash):
        expected = self.calculate_hash(message)
        if expected != received_hash:
            return {
                "type": "INTEGRITY",
                "severity": "HIGH",
                "message": "Hash différent → message modifié (MITM probable)"
            }
        return None

    # ---------- REPLAY ----------
    def detect_replay(self, msg_hash):
        now = time.time()
        if msg_hash in self.seen_hashes:
            if now - self.seen_hashes[msg_hash] < self.REPLAY_WINDOW:
                return {
                    "type": "REPLAY",
                    "severity": "HIGH",
                    "message": "Message rejoué détecté"
                }
        self.seen_hashes[msg_hash] = now
        return None

    # ---------- FLOOD ----------
    def detect_flood(self, ip):
        now = time.time()
        self.client_stats.setdefault(ip, [])
        self.client_stats[ip].append(now)
        self.client_stats[ip] = [t for t in self.client_stats[ip] if now - t < 60]

        if len(self.client_stats[ip]) > self.MAX_MSG_PER_MIN:
            return {
                "type": "FLOOD",
                "severity": "HIGH",
                "message": "Trop de messages envoyés"
            }
        return None

    # ---------- ANALYSE ----------
    def analyze(self, message, msg_hash, ip):
        alerts = []

        checks = [
            self.check_integrity(message, msg_hash),
            self.detect_replay(msg_hash),
            self.detect_flood(ip)
        ]

        for c in checks:
            if c:
                alerts.append(c)

        return alerts

    # ---------- CLIENT ----------
    def handle_client(self, sock, addr):
        ip = addr[0]
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Connexion de {ip}")

        try:
            sock.settimeout(self.READ_TIMEOUT)
            data = sock.recv(4096).decode().strip()

            if "|" not in data:
                sock.send(b"ERREUR: format invalide")
                return

            message, msg_hash = data.rsplit("|", 1)
            message, received_hash = data.rsplit("|", 1)
            calculated_hash = self.calculate_hash(message)

            print(f"Message reçu       : {message}")
            print(f"Hash reçu          : {received_hash}")
            print(f"Hash recalculé     : {calculated_hash}")

            

            alerts = self.analyze(message, msg_hash, ip)

            if alerts:
                response = "ALERTES: " + " | ".join(
                    f"{a['type']}:{a['message']}" for a in alerts
                )
                print("⚠️  ALERTES détectées")
            else:
                response = "OK: message intègre et valide"
                print("✅ Message valide")

            sock.send(response.encode())

        except Exception as e:
            print("❌ Erreur:", e)
        finally:
            sock.close()

    # ---------- SERVEUR ----------
    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(5)

        print("🚀 Serveur de détection MITM lancé")
        print(f"📡 {self.host}:{self.port}")

        try:
            while True:
                client, addr = s.accept()
                threading.Thread(
                    target=self.handle_client,
                    args=(client, addr),
                    daemon=True
                ).start()
        except KeyboardInterrupt:
            print("\nArrêt serveur")
        finally:
            s.close()

if __name__ == "__main__":
    DetectionServer().start()
