"""
Serveur de détection MITM avec vérification d'intégrité par hash
P2-C1 : Détection Man-in-the-Middle

Ce serveur analyse les messages reçus afin de détecter :
- Modification du message (attaque MITM)
- Rejeu de messages (replay attack)
- Inondation de messages (flood)
"""
import socket              # Gestion des sockets réseau
import threading           # Gestion du multi-thread (plusieurs clients)
import time                # Gestion du temps (timestamps)
import hashlib             # Calcul de hash (SHA-256)
from datetime import datetime  # Date et heure pour logs


class DetectionServer:
    def __init__(self, host='127.0.0.1', port=9999):
        # Adresse IP et port du serveur
        self.host = host
        self.port = port

        # État du serveur
        self.running = True

        # Dictionnaire pour stocker les hash déjà vus (anti-replay)
        # Format : {hash : timestamp}
        self.seen_hashes = {}

        # Statistiques par client (anti-flood)
        # Format : {ip : [timestamps]}
        self.client_stats = {}

        # Fenêtre de temps pour détecter le rejeu (en secondes)
        self.REPLAY_WINDOW = 30

        # Nombre maximum de messages par minute par client
        self.MAX_MSG_PER_MIN = 10

        # Timeout de lecture du socket client
        self.READ_TIMEOUT = 10

    # ---------- HASH ----------
    def calculate_hash(self, message):
        """
        Calcule le hash SHA-256 du message
        et retourne uniquement les 16 premiers caractères
        (suffisant pour la détection dans ce TP)
        """
        return hashlib.sha256(message.encode()).hexdigest()[:16]

    def check_integrity(self, message, received_hash):
        """
        Vérifie l'intégrité du message :
        - Recalcule le hash du message reçu
        - Compare avec le hash envoyé par le client
        """
        expected = self.calculate_hash(message)

        # Si les hash sont différents → message modifié
        if expected != received_hash:
            return {
                "type": "INTEGRITY",
                "severity": "HIGH",
                "message": "Hash différent → message modifié (MITM probable)"
            }
        return None

    # ---------- REPLAY ----------
    def detect_replay(self, msg_hash):
        """
        Détecte une attaque par rejeu :
        - Vérifie si le hash a déjà été vu récemment
        """
        now = time.time()

        # Si le hash existe déjà
        if msg_hash in self.seen_hashes:
            # Et s'il est reçu dans la fenêtre de temps définie
            if now - self.seen_hashes[msg_hash] < self.REPLAY_WINDOW:
                return {
                    "type": "REPLAY",
                    "severity": "HIGH",
                    "message": "Message rejoué détecté"
                }

        # Enregistre le hash avec le timestamp actuel
        self.seen_hashes[msg_hash] = now
        return None

    # ---------- FLOOD ----------
    def detect_flood(self, ip):
        """
        Détecte une attaque par flooding :
        - Compte le nombre de messages envoyés par IP
        - Sur une période d'une minute
        """
        now = time.time()

        # Initialise la liste si l'IP est nouvelle
        self.client_stats.setdefault(ip, [])

        # Ajoute le timestamp actuel
        self.client_stats[ip].append(now)

        # Garde uniquement les messages des 60 dernières secondes
        self.client_stats[ip] = [
            t for t in self.client_stats[ip] if now - t < 60
        ]

        # Si le seuil est dépassé → flood détecté
        if len(self.client_stats[ip]) > self.MAX_MSG_PER_MIN:
            return {
                "type": "FLOOD",
                "severity": "HIGH",
                "message": "Trop de messages envoyés"
            }
        return None

    # ---------- ANALYSE ----------
    def analyze(self, message, msg_hash, ip):
        """
        Analyse complète du message :
        - Intégrité
        - Rejeu
        - Flood
        """
        alerts = []

        # Liste des vérifications de sécurité
        checks = [
            self.check_integrity(message, msg_hash),
            self.detect_replay(msg_hash),
            self.detect_flood(ip)
        ]

        # Ajoute toutes les alertes détectées
        for c in checks:
            if c:
                alerts.append(c)

        return alerts

    # ---------- CLIENT ----------
    def handle_client(self, sock, addr):
        """
        Gère un client connecté :
        - Réception du message
        - Analyse
        - Réponse
        """
        ip = addr[0]

        # Log de connexion
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Connexion de {ip}")

        try:
            # Timeout pour éviter un client bloquant
            sock.settimeout(self.READ_TIMEOUT)

            # Réception des données
            data = sock.recv(4096).decode().strip()

            # Vérification du format attendu : message|hash
            if "|" not in data:
                sock.send(b"ERREUR: format invalide")
                return

            # Séparation du message et du hash reçu
            message, msg_hash = data.rsplit("|", 1)
            message, received_hash = data.rsplit("|", 1)

            # Recalcul du hash localement
            calculated_hash = self.calculate_hash(message)

            # Affichage pour débogage et démonstration
            print(f"Message reçu       : {message}")
            print(f"Hash reçu          : {received_hash}")
            print(f"Hash recalculé     : {calculated_hash}")

            # Analyse de sécurité
            alerts = self.analyze(message, msg_hash, ip)

            # Construction de la réponse serveur
            if alerts:
                response = "ALERTES: " + " | ".join(
                    f"{a['type']}:{a['message']}" for a in alerts
                )
                print("⚠️  ALERTES détectées")
            else:
                response = "OK: message intègre et valide"
                print("✅ Message valide")

            # Envoi de la réponse au client
            sock.send(response.encode())

        except Exception as e:
            # Gestion des erreurs
            print("❌ Erreur:", e)
        finally:
            # Fermeture de la connexion client
            sock.close()

    # ---------- SERVEUR ----------
    def start(self):
        """
        Démarre le serveur :
        - Écoute les connexions entrantes
        - Lance un thread par client
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Réutilisation de l'adresse pour éviter les blocages
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Liaison IP/port
        s.bind((self.host, self.port))

        # Mise en écoute
        s.listen(5)

        print("🚀 Serveur de détection MITM lancé")
        print(f"📡 {self.host}:{self.port}")

        try:
            while True:
                # Acceptation d'un nouveau client
                client, addr = s.accept()

                # Lancement d'un thread pour le client
                threading.Thread(
                    target=self.handle_client,
                    args=(client, addr),
                    daemon=True
                ).start()

        except KeyboardInterrupt:
            # Arrêt propre du serveur
            print("\nArrêt serveur")
        finally:
            s.close()


# Point d'entrée du programme
if __name__ == "__main__":
    DetectionServer().start()
