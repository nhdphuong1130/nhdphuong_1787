from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket
import threading
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dh_aes_secure_chat_key_2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Per-client session storage
sessions = {}

# Function to encrypt message (matching server.py template)
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

# Function to decrypt message (matching server.py template)
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

def client_receive_loop(sid, sock, aes_key):
    """Background thread: receive messages from socket server, relay to browser"""
    while sessions.get(sid, {}).get('running', False):
        try:
            data = sock.recv(2048)
            if not data:
                break
            msg = decrypt_message(aes_key, data)
            socketio.emit('log', {'category': 'SECURE', 'message': f'Received cipher: {data.hex()[:32]}...'}, room=sid)
            if ': ' in msg:
                sender, content = msg.split(': ', 1)
            else:
                sender, content = 'System', msg
            if msg == 'exit':
                break
            socketio.emit('message', {'sender': sender, 'content': content}, room=sid)
        except Exception as e:
            socketio.emit('log', {'category': 'ERROR', 'message': f'Receive error: {str(e)}'}, room=sid)
            break
    socketio.emit('status', {'status': 'DISCONNECTED'}, room=sid)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def on_connect():
    pass

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    if sid in sessions:
        sessions[sid]['running'] = False
        try:
            sock = sessions[sid].get('socket')
            aes_key = sessions[sid].get('aes_key')
            if sock and aes_key:
                sock.send(encrypt_message(aes_key, 'exit'))
            if sock:
                sock.close()
        except:
            pass
        del sessions[sid]

@socketio.on('connect_chat')
def on_connect_chat(data):
    sid = request.sid
    host = data.get('host', 'localhost')
    port = int(data.get('port', 12346))
    username = data.get('username', 'Anonymous')

    emit('status', {'status': 'CONNECTING'})
    emit('log', {'category': 'SYSTEM', 'message': f'Connecting to {host}:{port}...'})

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        emit('log', {'category': 'SYSTEM', 'message': 'Socket connected. Starting Diffie-Hellman Handshake...'})

        # 1. Receive server DH public key
        emit('log', {'category': 'HANDSHAKE', 'message': 'Receiving server DH public key...'})
        server_pub_raw = sock.recv(2048)
        if not server_pub_raw:
            raise Exception("Server disconnected immediately.")
        server_pub_pem = server_pub_raw.decode('utf-8', errors='ignore').strip()
        server_public_key = serialization.load_pem_public_key(server_pub_raw)
        emit('log', {'category': 'HANDSHAKE', 'message': f'Server DH key received. MD5: {hashlib.md5(server_pub_raw).hexdigest()}'})

        # 2. Extract DH parameters & generate client keypair
        emit('log', {'category': 'HANDSHAKE', 'message': 'Extracting DH parameters & generating client keypair...'})
        parameters = server_public_key.parameters()
        client_private_key = parameters.generate_private_key()
        client_public_key = client_private_key.public_key()

        client_pub_bytes = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_pub_pem = client_pub_bytes.decode('utf-8').strip()

        # Get client private key description
        priv_numbers = client_private_key.private_numbers()
        client_priv_desc = f"Private Value (x): {str(priv_numbers.x)[:48]}..."
        emit('log', {'category': 'HANDSHAKE', 'message': 'Client DH keypair generated successfully.'})

        # 3. Derive shared secret and AES key
        emit('log', {'category': 'HANDSHAKE', 'message': 'Deriving Diffie-Hellman shared secret...'})
        shared_secret = client_private_key.exchange(server_public_key)
        shared_secret_hex = shared_secret.hex()
        emit('log', {'category': 'HANDSHAKE', 'message': f'Shared Secret derived (first 32 hex): {shared_secret_hex[:32]}...'})

        emit('log', {'category': 'HANDSHAKE', 'message': 'Hashing shared secret with SHA-256 → AES-128 key...'})
        aes_key = hashlib.sha256(shared_secret).digest()[:16]
        emit('log', {'category': 'HANDSHAKE', 'message': f'Derived AES Key: {aes_key.hex()}'})

        # 4. Send client public key
        sock.send(client_pub_bytes)
        emit('log', {'category': 'HANDSHAKE', 'message': 'Sent client DH public key to server. Handshake complete!'})

        emit('handshake_done', {
            'aes_key': aes_key.hex().upper(),
            'server_pub': server_pub_pem,
            'client_pub': client_pub_pem,
            'shared_secret': shared_secret_hex.upper(),
            'client_priv': client_priv_desc
        })
        emit('status', {'status': 'CONNECTED'})

        sessions[sid] = {
            'socket': sock,
            'aes_key': aes_key,
            'username': username,
            'running': True
        }

        # Start background receive thread
        t = threading.Thread(target=client_receive_loop, args=(sid, sock, aes_key), daemon=True)
        t.start()
        sessions[sid]['thread'] = t

    except Exception as e:
        emit('log', {'category': 'ERROR', 'message': f'Connection failed: {str(e)}'})
        emit('status', {'status': 'DISCONNECTED'})

@socketio.on('send_message')
def on_send_message(data):
    sid = request.sid
    session = sessions.get(sid)
    if not session or not session.get('running'):
        emit('log', {'category': 'ERROR', 'message': 'Not connected to server.'})
        return
    msg = data.get('message', '').strip()
    if not msg:
        return
    username = session['username']
    full_msg = f'{username}: {msg}'
    try:
        encrypted = encrypt_message(session['aes_key'], full_msg)
        session['socket'].send(encrypted)
        emit('log', {'category': 'SECURE', 'message': f'Encrypted & sent: {encrypted.hex()[:32]}...'})
    except Exception as e:
        emit('log', {'category': 'ERROR', 'message': f'Send failed: {str(e)}'})

@socketio.on('disconnect_chat')
def on_disconnect_chat():
    sid = request.sid
    if sid in sessions:
        sessions[sid]['running'] = False
        try:
            sock = sessions[sid]['socket']
            aes_key = sessions[sid].get('aes_key')
            if sock and aes_key:
                sock.send(encrypt_message(aes_key, 'exit'))
            sock.close()
        except:
            pass
        del sessions[sid]
    emit('status', {'status': 'DISCONNECTED'})

if __name__ == '__main__':
    print("Starting DH-AES Secure Chat Web App on http://localhost:5002")
    socketio.run(app, host='0.0.0.0', port=5002, debug=False, allow_unsafe_werkzeug=True)
