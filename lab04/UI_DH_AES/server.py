from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket
import threading
import hashlib

# List of connected clients (client_socket, aes_key)
clients = []

# Function to encrypt message (matching the style of AES-RSA)
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

# Function to decrypt message (matching the style of AES-RSA)
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    return parameters

def generate_server_key_pair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def handle_client(client_socket, client_address, server_private_key, server_public_key):
    print(f"Connected with {client_address}")
    try:
        # 1. Send server's DH public key to client
        server_pub_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.send(server_pub_bytes)
        
        # 2. Receive client's DH public key
        client_pub_bytes = client_socket.recv(2048)
        if not client_pub_bytes:
            raise Exception("Client disconnected before DH exchange completed.")
            
        client_public_key = serialization.load_pem_public_key(client_pub_bytes)
        
        # 3. Derive DH shared secret and AES key
        shared_secret = server_private_key.exchange(client_public_key)
        aes_key = hashlib.sha256(shared_secret).digest()[:16] # 16 bytes for AES-128
        
        # Add client to the list
        clients.append((client_socket, aes_key))
        
        while True:
            encrypted_message = client_socket.recv(2048)
            if not encrypted_message:
                break
            decrypted_message = decrypt_message(aes_key, encrypted_message)
            print(f"Received from {client_address}: {decrypted_message}")
            
            # Send received message to all other clients
            for client, key in clients:
                if client != client_socket:
                    try:
                        encrypted = encrypt_message(key, decrypted_message)
                        client.send(encrypted)
                    except Exception as send_err:
                        print(f"Failed to forward message: {send_err}")
                    
            if decrypted_message == "exit":
                break
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        # Clean up client
        for client, key in list(clients):
            if client == client_socket:
                clients.remove((client, key))
                break
        client_socket.close()
        print(f"Connection with {client_address} closed")

def main():
    parameters = generate_dh_parameters()
    private_key, public_key = generate_server_key_pair(parameters)
    
    with open("server_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Initialize server socket for DH-AES secure chat
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12346)) # Port 12346 for DH-AES
    server_socket.listen(5)
    print("Diffie-Hellman AES Socket Server listening on port 12346...")
    
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client, 
                args=(client_socket, client_address, private_key, public_key)
            )
            client_thread.start()
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()