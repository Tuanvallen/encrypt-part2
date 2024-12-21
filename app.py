from flask import Flask, render_template, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import base64

app = Flask(__name__)

# RSA Key Pair Generation
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# AES Key and IV
aes_key = get_random_bytes(16)
iv = get_random_bytes(16)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/rsa', methods=['GET', 'POST'])
def rsa():
    if request.method == 'POST':
        action = request.form['action']
        message = request.form['message']
        if action == 'encrypt':
            recipient_key = RSA.import_key(public_key)
            cipher_rsa = PKCS1_OAEP.new(recipient_key)
            encrypted_message = cipher_rsa.encrypt(message.encode())
            return render_template('rsa.html', encrypted=base64.b64encode(encrypted_message).decode())
        elif action == 'decrypt':
            encrypted_message = base64.b64decode(request.form['encrypted_message'])
            private_rsa_key = RSA.import_key(private_key)
            cipher_rsa = PKCS1_OAEP.new(private_rsa_key)
            decrypted_message = cipher_rsa.decrypt(encrypted_message).decode()
            return render_template('rsa.html', decrypted=decrypted_message)
    return render_template('rsa.html')

@app.route('/aes', methods=['GET', 'POST'])
def aes():
    if request.method == 'POST':
        action = request.form['action']
        message = request.form['message']
        if action == 'encrypt':
            cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv)
            encrypted_message = cipher_aes.encrypt(message.encode())
            return render_template('aes.html', encrypted=base64.b64encode(encrypted_message).decode(),
                                   iv=base64.b64encode(iv).decode())
        elif action == 'decrypt':
            encrypted_message = base64.b64decode(request.form['encrypted_message'])
            iv_received = base64.b64decode(request.form['iv'])
            cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv_received)
            decrypted_message = cipher_aes.decrypt(encrypted_message).decode()
            return render_template('aes.html', decrypted=decrypted_message)
    return render_template('aes.html')

@app.route('/sha256', methods=['GET', 'POST'])
def sha256():
    if request.method == 'POST':
        message = request.form['message']
        hasher = SHA256.new()
        hasher.update(message.encode())
        hashed_message = hasher.hexdigest()
        return render_template('sha256.html', hashed=hashed_message)
    return render_template('sha256.html')

if __name__ == '__main__':
    app.run(debug=True)
