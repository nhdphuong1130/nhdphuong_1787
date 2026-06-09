from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import socket
import hashlib
import time

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

def test_aes_rsa():
    print("=== Testing AES-RSA Socket Server (Port 12345) ===")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('localhost', 12345))
        print("[1] Connected to AES-RSA server.")
        
        # Recv server key
        server_pub_raw = s.recv(2048)
        print(f"[2] Received Server RSA Public Key (length: {len(server_pub_raw)})")
        
        # Gen client key
        client_key = RSA.generate(2048)
        print("[3] Generated Client RSA 2048-bit keys.")
        
        # Send client key
        s.send(client_key.publickey().export_key(format='PEM'))
        print("[4] Sent Client RSA Public Key.")
        
        # Recv encrypted AES key
        enc_aes_key = s.recv(2048)
        print(f"[5] Received Encrypted AES Key (length: {len(enc_aes_key)})")
        
        # Decrypt AES key
        cipher_rsa = PKCS1_OAEP.new(client_key)
        aes_key = cipher_rsa.decrypt(enc_aes_key)
        print(f"[6] Decrypted AES Session Key: {aes_key.hex()}")
        
        # Send encrypted test message
        test_msg = "Client_Test: Hello from automated test!"
        encrypted = encrypt_message(aes_key, test_msg)
        s.send(encrypted)
        print(f"[7] Encrypted and sent message: {test_msg}")
        
        s.close()
        print("AES-RSA server test PASSED!\n")
        return True
    except Exception as e:
        print(f"AES-RSA server test FAILED: {e}\n")
        return False

def test_dh_aes():
    print("=== Testing DH-AES Socket Server (Port 12346) ===")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('localhost', 12346))
        print("[1] Connected to DH-AES server.")
        
        # Recv server DH public key
        server_pub_raw = s.recv(2048)
        print(f"[2] Received Server DH Public Key (length: {len(server_pub_raw)})")
        
        # Load server DH public key
        server_public_key = serialization.load_pem_public_key(server_pub_raw)
        
        # Extract parameters and generate client DH keypair
        parameters = server_public_key.parameters()
        client_private_key = parameters.generate_private_key()
        client_public_key = client_private_key.public_key()
        print("[3] Loaded DH parameters and generated Client DH keypair.")
        
        # Derive shared secret and AES key
        shared_secret = client_private_key.exchange(server_public_key)
        aes_key = hashlib.sha256(shared_secret).digest()[:16]
        print(f"[4] Derived shared secret. Derived AES Key: {aes_key.hex()}")
        
        # Send client public key
        client_pub_bytes = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        s.send(client_pub_bytes)
        print("[5] Sent Client DH Public Key.")
        
        # Send encrypted test message
        test_msg = "Client_DH_Test: Hello from DH automated test!"
        encrypted = encrypt_message(aes_key, test_msg)
        s.send(encrypted)
        print(f"[6] Encrypted and sent message: {test_msg}")
        
        s.close()
        print("DH-AES server test PASSED!\n")
        return True
    except Exception as e:
        print(f"DH-AES server test FAILED: {e}\n")
        return False

if __name__ == "__main__":
    time.sleep(1) # wait for servers to settle
    rsa_ok = test_aes_rsa()
    dh_ok = test_dh_aes()
    if rsa_ok and dh_ok:
        print("All server checks passed successfully!")
    else:
        print("Some server checks failed!")
