"""
MITM Proxy pédagogique
Intercepte et modifie les messages
"""
import socket
import hashlib

LISTEN_PORT = 8888
SERVER_PORT = 9999
HOST = "127.0.0.1"
#calcule de hash du message
def compute_hash(msg):
    return hashlib.sha256(msg.encode()).hexdigest()[:16]

def start_mitm():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, LISTEN_PORT))
    s.listen(5)

    print(" MITM Proxy actif sur le port 8888")

    while True:
        client, addr = s.accept()
        data = client.recv(4096).decode()

        print("\n Message intercepté :", data)

        # Séparer message et hash
        if "|" in data:
            message, h = data.rsplit("|", 1)

            #  MODIFICATION MALVEILLANTE
            modified_msg = message + " [MITM]"
            fake_hash = compute_hash(message)  # ancien hash → incohérent

            new_payload = f"{modified_msg}|{fake_hash}"
            print("✏️ Message modifié :", new_payload)
        else:
            new_payload = data

        # Envoi vers le vrai serveur
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((HOST, SERVER_PORT))
        server.send(new_payload.encode())

        response = server.recv(4096)
        client.send(response)

        client.close()
        server.close()

if __name__ == "__main__":
    start_mitm()
