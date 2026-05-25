import os
import sys
from flask import Flask, request, render_template

# Add ex01 to sys.path to allow imports from cipher module
sys.path.append(os.path.join(os.path.dirname(__file__), 'ex01'))

# pyrefly: ignore [missing-import]
from cipher.caesar import CaesarCipher

app = Flask(__name__)
caesar_cipher = CaesarCipher()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/caesar')
def caesar():
    return render_template('caesar.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    plain_text = request.form.get('inputPlainText', '')
    key_str = request.form.get('inputKeyPlain', '0')
    try:
        key = int(key_str)
    except ValueError:
        key = 0
    
    # Use Caesar cipher to encrypt and handle any potential ValueError (due to non-alphabetic chars)
    error_message = None
    encrypted_text = ""
    try:
        encrypted_text = caesar_cipher.encrypt_text(plain_text, key)
    except ValueError:
        error_message = "LỖI: Bản rõ chỉ được chứa các ký tự A-Z (không chứa khoảng trắng hay ký tự đặc biệt)."

    # Read templates/caesar.html to dynamically inject value attributes and show result
    template_path = os.path.join(app.root_path, 'templates', 'caesar.html')
    if os.path.exists(template_path):
        with open(template_path, 'r', encoding='utf-8') as f:
            html = f.read()
        
        # Inject values back into inputs to persist form state
        html = html.replace(
            'name="inputPlainText"',
            f'name="inputPlainText" value="{plain_text}"'
        )
        html = html.replace(
            'name="inputKeyPlain"',
            f'name="inputKeyPlain" value="{key}"'
        )
        
        # Determine what to write into the Cipher Text box
        display_cipher = error_message if error_message else encrypted_text
        html = html.replace(
            'name="inputCipherText"',
            f'name="inputCipherText" value="{display_cipher}"'
        )
        html = html.replace(
            'name="inputKeyCipher"',
            f'name="inputKeyCipher" value="{key}"'
        )
        return html
    
    return display_cipher

@app.route('/decrypt', methods=['POST'])
def decrypt():
    cipher_text = request.form.get('inputCipherText', '')
    key_str = request.form.get('inputKeyCipher', '0')
    try:
        key = int(key_str)
    except ValueError:
        key = 0
    
    # Use Caesar cipher to decrypt and handle any potential ValueError
    error_message = None
    decrypted_text = ""
    try:
        decrypted_text = caesar_cipher.decrypt_text(cipher_text, key)
    except ValueError:
        error_message = "LỖI: Bản mã chỉ được chứa các ký tự A-Z (không chứa khoảng trắng hay ký tự đặc biệt)."

    # Read templates/caesar.html to dynamically inject value attributes and show result
    template_path = os.path.join(app.root_path, 'templates', 'caesar.html')
    if os.path.exists(template_path):
        with open(template_path, 'r', encoding='utf-8') as f:
            html = f.read()
        
        # Inject values back into inputs to persist form state
        html = html.replace(
            'name="inputCipherText"',
            f'name="inputCipherText" value="{cipher_text}"'
        )
        html = html.replace(
            'name="inputKeyCipher"',
            f'name="inputKeyCipher" value="{key}"'
        )
        
        # Determine what to write into the Plain Text box
        display_plain = error_message if error_message else decrypted_text
        html = html.replace(
            'name="inputPlainText"',
            f'name="inputPlainText" value="{display_plain}"'
        )
        html = html.replace(
            'name="inputKeyPlain"',
            f'name="inputKeyPlain" value="{key}"'
        )
        return html
    
    return display_plain

@app.route('/rsa')
def rsa():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>RSA Cipher</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css" rel="stylesheet" />
    </head>
    <body>
        <div class="container mt-5">
            <a href="/" class="btn btn-secondary mb-3">Quay lại trang chủ</a>
            <div class="card">
                <div class="card-header bg-dark text-white">
                    <h3>Mã hóa RSA (Placeholder)</h3>
                </div>
                <div class="card-body">
                    <p class="card-text">Trang mô phỏng thuật toán mã hóa RSA sẽ được cập nhật trong tương lai!</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
