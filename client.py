"""
Client normal avec hash d'intégrité
P2-C1 : Détection MITM

Ce client :
- Calcule un hash d'intégrité pour chaque message
- Envoie le message + hash au serveur
- Peut envoyer directement ou via un MITM (simulation)
"""
import socket     # Communication réseau
import time       # Mesure du temps (latence)
import hashlib    # Calcul du hash SHA-256


class NormalClient:
    def __init__(self, server_host='127.0.0.1', server_port=9999):
        # Adresse IP du serveur
        self.server_host = server_host

        # Port du serveur de détection
        self.server_port = server_port

    def calculate_hash(self, message):
        """
        Calcule le hash SHA-256 du message
        et retourne uniquement les 16 premiers caractères
        pour correspondre au serveur
        """
        return hashlib.sha256(message.encode()).hexdigest()[:16]

    def send_message(self, message, via_mitm=False):
        """
        Envoie un message au serveur :
        - Directement (port normal)
        - Ou via un MITM simulé (autre port)
        """
        # Si MITM activé → envoi vers le port 8888
        port = 8888 if via_mitm else self.server_port

        # Étiquette d'affichage
        label = "VIA MITM" if via_mitm else "DIRECT"

        # Calcul du hash d'intégrité
        msg_hash = self.calculate_hash(message)

        # Construction du message final : message|hash
        payload = f"{message}|{msg_hash}"

        # Affichage des informations d'envoi
        print(f"\n📤 ENVOI {label}")
        print(f"Message      : {message}")
        print(f"Hash envoyé  : {msg_hash}")

        try:
            # Création du socket TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Timeout pour éviter un blocage
            sock.settimeout(5)

            # Début du chronométrage (latence)
            start = time.time()

            # Connexion au serveur
            sock.connect((self.server_host, port))

            # Envoi du message
            sock.send(payload.encode('utf-8'))

            # Réception de la réponse serveur
            response = sock.recv(4096).decode('utf-8')

            # Calcul du temps de réponse
            duration = time.time() - start

            # Affichage de la réponse
            print(f"\n📨 RÉPONSE SERVEUR ({duration:.3f}s)")
            print(response)

            # Fermeture de la connexion
            sock.close()
            return response

        except Exception as e:
            # Gestion des erreurs client
            print(f"❌ Erreur client : {e}")
            return None

    def interactive_mode(self):
        """
        Mode interactif :
        - Saisie des messages via le clavier
        - Activation/désactivation du MITM
        """
        print("\n💻 CLIENT AVEC HASH - MODE INTERACTIF")

        # Indique si le MITM est actif
        use_mitm = False

        while True:
            # Lecture du message utilisateur
            msg = input("\nMessage > ").strip()

            # Quitter le programme
            if msg.lower() == "quit":
                break

            # Activer / désactiver le MITM
            elif msg.lower() == "mitm":
                use_mitm = not use_mitm
                print("MITM", "ACTIVÉ" if use_mitm else "DÉSACTIVÉ")
                continue

            # Ignorer les messages vides
            elif not msg:
                continue

            # Envoi du message
            self.send_message(msg, via_mitm=use_mitm)


# Point d'entrée du programme
if __name__ == "__main__":
    NormalClient().interactive_mode()
