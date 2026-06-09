from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket
import sys
import os
import hashlib
from PyQt5 import QtCore, QtGui, QtWidgets

# AES Encryption & Decryption Helper functions matching template
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

class ClientSocketThread(QtCore.QThread):
    connection_status = QtCore.pyqtSignal(str) # CONNECTED, DISCONNECTED, CONNECTING
    message_received = QtCore.pyqtSignal(str, str) # sender, content
    handshake_done = QtCore.pyqtSignal(bytes, str, str, str, str) # aes_key, server_pub_pem, client_pub_pem, shared_secret_hex, client_priv_desc
    log_event = QtCore.pyqtSignal(str, str) # category, message
    error_occurred = QtCore.pyqtSignal(str)

    def __init__(self, host, port, username):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.socket = None
        self.aes_key = None
        self.running = True

    def run(self):
        self.connection_status.emit("CONNECTING")
        self.log_event.emit("SYSTEM", f"Starting connection to {self.host}:{self.port}...")
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.log_event.emit("SYSTEM", "Socket connected. Starting Diffie-Hellman Key Exchange...")

            # 1. Receive server's DH public key
            self.log_event.emit("HANDSHAKE", "Receiving server DH public key...")
            server_pub_raw = self.socket.recv(2048)
            if not server_pub_raw:
                raise Exception("Server disconnected before sending public key.")
            server_pub_pem = server_pub_raw.decode('utf-8', errors='ignore').strip()
            
            # Load server DH public key
            server_public_key = serialization.load_pem_public_key(server_pub_raw)
            self.log_event.emit("HANDSHAKE", f"Loaded Server DH Public Key (2048-bit). MD5: {hashlib.md5(server_pub_raw).hexdigest()}")

            # 2. Extract DH parameters & generate client DH keypair
            self.log_event.emit("HANDSHAKE", "Extracting DH parameters from server public key...")
            parameters = server_public_key.parameters()
            self.log_event.emit("HANDSHAKE", "Generating client DH keypair...")
            client_private_key = parameters.generate_private_key()
            client_public_key = client_private_key.public_key()
            
            client_pub_bytes = client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_pub_pem = client_pub_bytes.decode('utf-8').strip()
            
            # Create a description of client's private key (DH private values are too long, display size/type)
            priv_numbers = client_private_key.private_numbers()
            client_priv_desc = f"DH Private Key (2048-bit). Private Value: {str(priv_numbers.x)[:32]}..."
            self.log_event.emit("HANDSHAKE", "Client DH keypair generated successfully.")

            # 3. Derive Shared Secret and AES key
            self.log_event.emit("HANDSHAKE", "Exchanging keys and deriving Shared Secret...")
            shared_secret = client_private_key.exchange(server_public_key)
            shared_secret_hex = shared_secret.hex()
            self.log_event.emit("HANDSHAKE", f"Derived Shared Secret (first 32 bytes): {shared_secret_hex[:64]}...")
            
            self.log_event.emit("HANDSHAKE", "Hashing Shared Secret with SHA-256 to derive AES-128 key...")
            self.aes_key = hashlib.sha256(shared_secret).digest()[:16]
            self.log_event.emit("HANDSHAKE", f"Derived AES Key: {self.aes_key.hex()}")

            # 4. Send client's DH public key to server
            self.log_event.emit("HANDSHAKE", "Sending client DH public key to server...")
            self.socket.send(client_pub_bytes)
            self.log_event.emit("HANDSHAKE", "Sent client DH public key.")

            self.handshake_done.emit(self.aes_key, server_pub_pem, client_pub_pem, shared_secret_hex, client_priv_desc)
            self.connection_status.emit("CONNECTED")
            self.log_event.emit("SYSTEM", "Secure channel established. Ready for chat.")

            # 5. Keep receiving encrypted messages
            while self.running:
                encrypted_message = self.socket.recv(2048)
                if not encrypted_message:
                    break
                self.log_event.emit("SECURE", f"Received cipher: {encrypted_message.hex()[:48]}...")
                try:
                    decrypted_message = decrypt_message(self.aes_key, encrypted_message)
                    self.log_event.emit("SECURE", f"Decrypted message: '{decrypted_message}'")
                    
                    # Split sender from content
                    if ": " in decrypted_message:
                        sender, content = decrypted_message.split(": ", 1)
                    else:
                        sender, content = "System", decrypted_message
                    
                    self.message_received.emit(sender, content)
                except Exception as dec_err:
                    self.log_event.emit("ERROR", f"Failed to decrypt message: {str(dec_err)}")

        except Exception as e:
            self.error_occurred.emit(str(e))
            self.log_event.emit("ERROR", f"Connection error: {str(e)}")
        finally:
            self.disconnect_socket()

    def send_message(self, message):
        if self.socket and self.aes_key:
            try:
                full_message = f"{self.username}: {message}"
                encrypted_message = encrypt_message(self.aes_key, full_message)
                self.socket.send(encrypted_message)
                self.log_event.emit("SECURE", f"Encrypted and sent: {encrypted_message.hex()[:48]}...")
                return True
            except Exception as e:
                self.log_event.emit("ERROR", f"Failed to send message: {str(e)}")
        return False

    def disconnect_socket(self):
        self.running = False
        if self.socket:
            try:
                if self.aes_key:
                    exit_payload = encrypt_message(self.aes_key, "exit")
                    self.socket.send(exit_payload)
            except:
                pass
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        self.aes_key = None
        self.connection_status.emit("DISCONNECTED")


class ModernSecureChatApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.socket_thread = None
        self.aes_key = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Secure Chat Client - Diffie-Hellman & AES Protocol")
        self.resize(1000, 700)
        
        # Premium Dark Theme Stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0b0f19;
            }
            QWidget {
                color: #e2e8f0;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 13px;
            }
            QLabel {
                font-weight: 500;
            }
            QLineEdit {
                background-color: #111827;
                border: 1px solid #374151;
                border-radius: 6px;
                padding: 6px 10px;
                color: #f9fafb;
            }
            QLineEdit:focus {
                border: 1px solid #10b981;
            }
            QPushButton {
                background-color: #10b981;
                border: none;
                border-radius: 6px;
                padding: 7px 14px;
                color: #0b0f19;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #34d399;
            }
            QPushButton:pressed {
                background-color: #059669;
            }
            QPushButton:disabled {
                background-color: #374151;
                color: #6b7280;
            }
            QTextBrowser {
                background-color: #111827;
                border: 1px solid #1f2937;
                border-radius: 8px;
                padding: 10px;
            }
            QGroupBox {
                border: 1px solid #1f2937;
                border-radius: 8px;
                margin-top: 10px;
                padding: 10px;
                font-weight: bold;
                color: #10b981;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px 0 3px;
            }
            QSplitter::handle {
                background-color: #1f2937;
            }
        """)

        # Central Widget & Main Layout
        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QtWidgets.QHBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        # Splitter to divide Left (Chat & Logs) and Right (Key Details & Handshake Parameters)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        main_layout.addWidget(splitter)

        # LEFT CONTAINER
        left_widget = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)
        
        # 1. Connection Panel
        conn_group = QtWidgets.QGroupBox("1. Setup Connection (DH-AES)")
        conn_layout = QtWidgets.QHBoxLayout(conn_group)
        
        self.txt_username = QtWidgets.QLineEdit("Client_DH")
        self.txt_username.setPlaceholderText("Username")
        self.txt_host = QtWidgets.QLineEdit("localhost")
        self.txt_host.setFixedWidth(120)
        self.txt_port = QtWidgets.QLineEdit("12346")
        self.txt_port.setFixedWidth(60)
        
        self.btn_connect = QtWidgets.QPushButton("Connect")
        self.btn_connect.clicked.connect(self.toggle_connection)
        
        self.btn_toggle_info = QtWidgets.QPushButton("Key Info")
        self.btn_toggle_info.setCheckable(True)
        self.btn_toggle_info.toggled.connect(self.toggle_crypto_panel)
        
        conn_layout.addWidget(QLabelCustom("Username:"))
        conn_layout.addWidget(self.txt_username)
        conn_layout.addWidget(QLabelCustom("Host:"))
        conn_layout.addWidget(self.txt_host)
        conn_layout.addWidget(QLabelCustom("Port:"))
        conn_layout.addWidget(self.txt_port)
        conn_layout.addWidget(self.btn_connect)
        conn_layout.addWidget(self.btn_toggle_info)
        
        left_layout.addWidget(conn_group)

        # 2. Chat History & Input area
        chat_group = QtWidgets.QGroupBox("2. Secure Room Chat")
        chat_layout = QtWidgets.QVBoxLayout(chat_group)
        
        self.txt_chat_history = QtWidgets.QTextBrowser()
        self.txt_chat_history.setOpenExternalLinks(False)
        chat_layout.addWidget(self.txt_chat_history)
        
        input_row = QtWidgets.QHBoxLayout()
        self.txt_msg_input = QtWidgets.QLineEdit()
        self.txt_msg_input.setPlaceholderText("Type secure message here... Press Enter or click Send")
        self.txt_msg_input.returnPressed.connect(self.send_chat)
        self.txt_msg_input.setEnabled(False)
        
        self.btn_send = QtWidgets.QPushButton("Send")
        self.btn_send.clicked.connect(self.send_chat)
        self.btn_send.setEnabled(False)
        
        input_row.addWidget(self.txt_msg_input)
        input_row.addWidget(self.btn_send)
        chat_layout.addLayout(input_row)
        
        left_layout.addWidget(chat_group)

        # 3. Security Event Logs
        self.log_group = QtWidgets.QGroupBox("3. Security Event Logs (Diffie-Hellman Handshake)")
        log_layout = QtWidgets.QVBoxLayout(self.log_group)
        self.txt_logs = QtWidgets.QTextBrowser()
        self.txt_logs.setFixedHeight(150)
        log_layout.addWidget(self.txt_logs)
        
        left_layout.addWidget(self.log_group)
        splitter.addWidget(left_widget)

        # RIGHT CONTAINER (DH Key Inspector)
        right_widget = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)
        
        # Client Key Inspector
        client_key_group = QtWidgets.QGroupBox("Client DH Parameters")
        client_key_layout = QtWidgets.QVBoxLayout(client_key_group)
        
        self.txt_client_priv = QtWidgets.QLineEdit()
        self.txt_client_priv.setReadOnly(True)
        self.txt_client_priv.setPlaceholderText("Client DH Private key details...")
        
        self.txt_client_pub = QtWidgets.QTextBrowser()
        self.txt_client_pub.setPlaceholderText("Client DH Public Key PEM will load...")
        
        client_key_layout.addWidget(QLabelCustom("Client DH Private Key Value:"))
        client_key_layout.addWidget(self.txt_client_priv)
        client_key_layout.addWidget(QLabelCustom("Client DH Public Key (PEM):"))
        client_key_layout.addWidget(self.txt_client_pub)
        
        right_layout.addWidget(client_key_group)

        # Server Public key & Derived Secrets
        secret_group = QtWidgets.QGroupBox("Derived Keys & Secrets")
        secret_layout = QtWidgets.QVBoxLayout(secret_group)
        
        self.txt_server_pub = QtWidgets.QTextBrowser()
        self.txt_server_pub.setPlaceholderText("Server DH Public Key PEM will load...")
        
        self.txt_shared_secret = QtWidgets.QTextBrowser()
        self.txt_shared_secret.setPlaceholderText("DH Shared Secret will derive here...")
        
        self.txt_aes_key = QtWidgets.QLineEdit()
        self.txt_aes_key.setReadOnly(True)
        self.txt_aes_key.setPlaceholderText("AES Key Derived from Shared Secret...")
        
        secret_layout.addWidget(QLabelCustom("Server DH Public Key (PEM):"))
        secret_layout.addWidget(self.txt_server_pub)
        secret_layout.addWidget(QLabelCustom("DH Shared Secret (g^ab mod p - Hex):"))
        secret_layout.addWidget(self.txt_shared_secret)
        secret_layout.addWidget(QLabelCustom("Derived AES-128 Session Key (SHA-256 Digest):"))
        secret_layout.addWidget(self.txt_aes_key)
        
        right_layout.addWidget(secret_group)
        splitter.addWidget(right_widget)

        # Store right_widget and hide it initially
        self.right_widget = right_widget
        self.right_widget.setVisible(False)
        self.log_group.setVisible(False)

        # Adjust initial sizes of splitter panels
        splitter.setSizes([580, 420])
        self.resize(600, 450)
        
        self.add_log("SYSTEM", "Client DH GUI initialized. Please input parameters and connect.")

    def toggle_crypto_panel(self, checked):
        self.right_widget.setVisible(checked)
        self.log_group.setVisible(checked)
        if checked:
            self.resize(1000, 700)
        else:
            self.resize(600, 450)

    def toggle_connection(self):
        if self.socket_thread and self.socket_thread.isRunning():
            self.add_log("SYSTEM", "Disconnecting...")
            self.socket_thread.disconnect_socket()
        else:
            host = self.txt_host.text().strip()
            port = int(self.txt_port.text().strip())
            username = self.txt_username.text().strip()
            
            if not username:
                QMessageBox.warning(self, "Validation Error", "Username cannot be empty.")
                return

            self.socket_thread = ClientSocketThread(host, port, username)
            self.socket_thread.connection_status.connect(self.on_connection_status)
            self.socket_thread.message_received.connect(self.on_message_received)
            self.socket_thread.handshake_done.connect(self.on_handshake_done)
            self.socket_thread.log_event.connect(self.add_log)
            self.socket_thread.error_occurred.connect(self.on_error)
            
            self.socket_thread.start()

    def on_connection_status(self, status):
        if status == "CONNECTING":
            self.btn_connect.setText("Connecting...")
            self.btn_connect.setEnabled(False)
            self.txt_username.setEnabled(False)
            self.txt_host.setEnabled(False)
            self.txt_port.setEnabled(False)
        elif status == "CONNECTED":
            self.btn_connect.setText("Disconnect")
            self.btn_connect.setEnabled(True)
            self.txt_msg_input.setEnabled(True)
            self.btn_send.setEnabled(True)
            self.txt_msg_input.setFocus()
        elif status == "DISCONNECTED":
            self.btn_connect.setText("Connect")
            self.btn_connect.setEnabled(True)
            self.txt_username.setEnabled(True)
            self.txt_host.setEnabled(True)
            self.txt_port.setEnabled(True)
            self.txt_msg_input.setEnabled(False)
            self.btn_send.setEnabled(False)
            self.txt_aes_key.clear()
            self.txt_client_pub.clear()
            self.txt_client_priv.clear()
            self.txt_server_pub.clear()
            self.txt_shared_secret.clear()
            self.socket_thread = None

    def on_message_received(self, sender, content):
        # Format beautiful bubbles in chat window
        is_self = sender == self.txt_username.text().strip()
        
        align = "right" if is_self else "left"
        bg_color = "#10b981" if is_self else "#1f2937"
        text_color = "#0b0f19" if is_self else "#f9fafb"
        label_color = "#111827" if is_self else "#9ca3af"
        
        bubble_html = f"""
        <div style='margin: 5px; text-align: {align};'>
            <div style='display: inline-block; background-color: {bg_color}; color: {text_color}; 
                        padding: 8px 12px; border-radius: 12px; max-width: 70%; text-align: left;'>
                <b style='font-size: 11px; color: {label_color};'>{sender}</b><br/>
                {content}
            </div>
        </div>
        """
        self.txt_chat_history.append(bubble_html)

    def on_handshake_done(self, aes_key, server_pub_pem, client_pub_pem, shared_secret_hex, client_priv_desc):
        self.aes_key = aes_key
        self.txt_aes_key.setText(aes_key.hex().upper())
        self.txt_server_pub.setText(server_pub_pem)
        self.txt_client_pub.setText(client_pub_pem)
        self.txt_shared_secret.setText(shared_secret_hex.upper())
        self.txt_client_priv.setText(client_priv_desc)

    def send_chat(self):
        msg = self.txt_msg_input.text().strip()
        if not msg:
            return
        
        if self.socket_thread and self.socket_thread.isRunning():
            success = self.socket_thread.send_message(msg)
            if success:
                self.on_message_received(self.txt_username.text().strip(), msg)
                self.txt_msg_input.clear()
            else:
                self.add_log("ERROR", "Message could not be encrypted & sent. Session lost.")
        else:
            self.add_log("ERROR", "Not connected to the secure server.")

    def on_error(self, err_msg):
        QtWidgets.QMessageBox.critical(self, "Network Error", f"An error occurred: {err_msg}")

    def add_log(self, category, message):
        color_map = {
            "SYSTEM": "#cbd5e1",    # Muted white
            "HANDSHAKE": "#f59e0b", # Amber
            "SECURE": "#10b981",    # Emerald
            "ERROR": "#ef4444"      # Red
        }
        color = color_map.get(category, "#ffffff")
        log_html = f"<span style='color: {color};'><b>[{category}]</b> {message}</span>"
        self.txt_logs.append(log_html)
        self.txt_logs.moveCursor(QtGui.QTextCursor.End)

    def closeEvent(self, event):
        if self.socket_thread and self.socket_thread.isRunning():
            self.socket_thread.disconnect_socket()
            self.socket_thread.wait()
        event.accept()

class QLabelCustom(QtWidgets.QLabel):
    def __init__(self, text):
        super().__init__(text)
        self.setStyleSheet("color: #6b7280; font-weight: 600; margin-bottom: 2px;")

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    win = ModernSecureChatApp()
    win.show()
    sys.exit(app.exec_())
