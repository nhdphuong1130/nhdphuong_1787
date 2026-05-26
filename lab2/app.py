import os
import sys

from flask import Flask, render_template, request, json

sys.path.append(os.path.join(os.path.dirname(__file__), 'ex01'))

from cipher.caesar import CaesarCipher
from cipher.vigenere import VigenereCipher
from cipher.railfence import RailFenceCipher
from cipher.playfair import PlayFairCipher
from cipher.transposition import TranspositionCipher

app = Flask(__name__)

#router routes for home page
@app.route("/")
def home():
    return render_template('index.html')

#router routes for caesar cypher
@app.route("/caesar")
def caesar():
    return render_template('caesar.html')


@app.route("/vigenere")
def vigenere():
    return render_template('vigenere.html')


@app.route("/railfence")
def railfence():
    return render_template('railfence.html')


@app.route("/playfair")
def playfair():
    return render_template('playfair.html')


@app.route("/transposition")
def transposition():
    return render_template('transposition.html')


@app.route("/rsa")
def rsa():
    return "RSA Cipher page is updating..."


@app.route("/encrypt", methods=['POST'])
def caesar_encrypt():
    text = request.form['inputPlainText']
    key = int(request.form['inputKeyPlain'])
    Caesar = CaesarCipher()

    encrypted_text = Caesar.encrypt_text(text, key)
    return render_template(
        'caesar.html',
        inputPlainText=text,
        inputKeyPlain=key,
        inputCipherText=encrypted_text,
        inputKeyCipher=key,
        encrypted_text=encrypted_text
    )


@app.route("/decrypt", methods=['POST'])
def caesar_decrypt():
    text = request.form['inputCipherText']
    key = int(request.form['inputKeyCipher'])
    Caesar = CaesarCipher()

    decrypted_text = Caesar.decrypt_text(text, key)
    return render_template(
        'caesar.html',
        inputCipherText=text,
        inputKeyCipher=key,
        inputPlainText=decrypted_text,
        inputKeyPlain=key,
        decrypted_text=decrypted_text
    )


@app.route("/vigenere_encrypt", methods=['POST'])
def vigenere_encrypt():
    text = request.form['inputPlainText']
    key = request.form['inputKeyPlain']
    Vigenere = VigenereCipher()

    encrypted_text = Vigenere.vigenere_encrypt(text, key)
    return render_template(
        'vigenere.html',
        inputPlainText=text,
        inputKeyPlain=key,
        inputCipherText=encrypted_text,
        inputKeyCipher=key,
        encrypted_text=encrypted_text
    )


@app.route("/vigenere_decrypt", methods=['POST'])
def vigenere_decrypt():
    text = request.form['inputCipherText']
    key = request.form['inputKeyCipher']
    Vigenere = VigenereCipher()

    decrypted_text = Vigenere.vigenere_decrypt(text, key)
    return render_template(
        'vigenere.html',
        inputCipherText=text,
        inputKeyCipher=key,
        inputPlainText=decrypted_text,
        inputKeyPlain=key,
        decrypted_text=decrypted_text
    )


@app.route("/railfence_encrypt", methods=['POST'])
def railfence_encrypt():
    text = request.form['inputPlainText']
    key = int(request.form['inputKeyPlain'])
    RailFence = RailFenceCipher()

    encrypted_text = RailFence.rail_fence_encrypt(text, key)
    return render_template(
        'railfence.html',
        inputPlainText=text,
        inputKeyPlain=key,
        inputCipherText=encrypted_text,
        inputKeyCipher=key,
        encrypted_text=encrypted_text
    )


@app.route("/railfence_decrypt", methods=['POST'])
def railfence_decrypt():
    text = request.form['inputCipherText']
    key = int(request.form['inputKeyCipher'])
    RailFence = RailFenceCipher()

    decrypted_text = RailFence.rail_fence_decrypt(text, key)
    return render_template(
        'railfence.html',
        inputCipherText=text,
        inputKeyCipher=key,
        inputPlainText=decrypted_text,
        inputKeyPlain=key,
        decrypted_text=decrypted_text
    )


@app.route("/playfair_encrypt", methods=['POST'])
def playfair_encrypt():
    text = request.form['inputPlainText']
    key = request.form['inputKeyPlain'].upper()
    PlayFair = PlayFairCipher()

    matrix = PlayFair.create_playfair_matrix(key)
    encrypted_text = PlayFair.playfair_encrypt(text, matrix)
    return render_template(
        'playfair.html',
        inputPlainText=text,
        inputKeyPlain=key,
        inputCipherText=encrypted_text,
        inputKeyCipher=key,
        encrypted_text=encrypted_text
    )


@app.route("/playfair_decrypt", methods=['POST'])
def playfair_decrypt():
    text = request.form['inputCipherText']
    key = request.form['inputKeyCipher'].upper()
    PlayFair = PlayFairCipher()

    matrix = PlayFair.create_playfair_matrix(key)
    decrypted_text = PlayFair.playfair_decrypt(text, matrix)
    return render_template(
        'playfair.html',
        inputCipherText=text,
        inputKeyCipher=key,
        inputPlainText=decrypted_text,
        inputKeyPlain=key,
        decrypted_text=decrypted_text
    )


@app.route("/transposition_encrypt", methods=['POST'])
def transposition_encrypt():
    text = request.form['inputPlainText']
    key = int(request.form['inputKeyPlain'])
    Transposition = TranspositionCipher()

    encrypted_text = Transposition.encrypt(text, key)
    return render_template(
        'transposition.html',
        inputPlainText=text,
        inputKeyPlain=key,
        inputCipherText=encrypted_text,
        inputKeyCipher=key,
        encrypted_text=encrypted_text
    )


@app.route("/transposition_decrypt", methods=['POST'])
def transposition_decrypt():
    text = request.form['inputCipherText']
    key = int(request.form['inputKeyCipher'])
    Transposition = TranspositionCipher()

    decrypted_text = Transposition.decrypt(text, key)
    return render_template(
        'transposition.html',
        inputCipherText=text,
        inputKeyCipher=key,
        inputPlainText=decrypted_text,
        inputKeyPlain=key,
        decrypted_text=decrypted_text
    )


#main function
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5050, debug=True)
