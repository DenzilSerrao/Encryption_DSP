from flask import Flask, render_template, request, jsonify
import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)

# Generate RSA keys for the hybrid encryption (in production, store these securely)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sha256', methods=['POST'])
def sha256_hash():
    data = request.json.get('text', '')
    
    # Generate SHA256 hash
    hash_object = hashlib.sha256(data.encode('utf-8'))
    hash_hex = hash_object.hexdigest()
    
    return jsonify({
        'hash': hash_hex,
        'length': len(hash_hex)
    })

@app.route('/hmac', methods=['POST'])
def hmac_generate():
    data = request.json.get('text', '')
    key = request.json.get('key', '')
    
    if not key:
        key = secrets.token_hex(32)  # Generate random key if not provided
    
    # Generate HMAC
    hmac_object = hmac.new(
        key.encode('utf-8'),
        data.encode('utf-8'),
        hashlib.sha256
    )
    hmac_hex = hmac_object.hexdigest()
    
    return jsonify({
        'hmac': hmac_hex,
        'key': key,
        'key_generated': not request.json.get('key')
    })

@app.route('/hmac/verify', methods=['POST'])
def hmac_verify():
    data = request.json.get('text', '')
    key = request.json.get('key', '')
    provided_hmac = request.json.get('hmac', '')
    
    if not key or not provided_hmac:
        return jsonify({
            'error': 'Both key and HMAC are required for verification',
            'valid': False
        }), 400
    
    # Generate HMAC with provided key
    hmac_object = hmac.new(
        key.encode('utf-8'),
        data.encode('utf-8'),
        hashlib.sha256
    )
    calculated_hmac = hmac_object.hexdigest()
    
    # Compare HMACs (timing-safe comparison)
    is_valid = hmac.compare_digest(calculated_hmac, provided_hmac)
    
    return jsonify({
        'valid': is_valid,
        'calculated_hmac': calculated_hmac,
        'message': 'HMAC is valid! Message is authentic.' if is_valid else 'HMAC is invalid! Message may be tampered or key is incorrect.'
    })

@app.route('/sha256/verify', methods=['POST'])
def sha256_verify():
    data = request.json.get('text', '')
    provided_hash = request.json.get('hash', '')
    
    if not provided_hash:
        return jsonify({
            'error': 'Hash is required for verification',
            'valid': False
        }), 400
    
    # Generate SHA256 hash
    hash_object = hashlib.sha256(data.encode('utf-8'))
    calculated_hash = hash_object.hexdigest()
    
    # Compare hashes
    is_valid = calculated_hash.lower() == provided_hash.lower()
    
    return jsonify({
        'valid': is_valid,
        'calculated_hash': calculated_hash,
        'message': 'Hash matches! Data integrity verified.' if is_valid else 'Hash does not match! Data may be corrupted or modified.'
    })

@app.route('/hybrid', methods=['POST'])
def hybrid_encrypt():
    data = request.json.get('text', '')
    
    # Generate random AES key (256-bit)
    aes_key = secrets.token_bytes(32)
    
    # Generate random IV for AES
    iv = secrets.token_bytes(16)
    
    # Encrypt data with AES
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Pad the data to be multiple of 16 bytes (AES block size)
    padding_length = 16 - (len(data.encode('utf-8')) % 16)
    padded_data = data.encode('utf-8') + bytes([padding_length] * padding_length)
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Create HMAC for authentication (Encrypt-then-MAC)
    # HMAC key derived from AES key
    hmac_key = hashlib.sha256(aes_key + b'hmac-key').digest()
    auth_tag = hmac.new(
        hmac_key,
        iv + encrypted_data,
        hashlib.sha256
    ).digest()
    
    # Encrypt AES key with RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Encode everything to base64 for transmission
    return jsonify({
        'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
        'encrypted_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'auth_tag': base64.b64encode(auth_tag).decode('utf-8'),
        'original_length': len(data)
    })

@app.route('/hybrid/decrypt', methods=['POST'])
def hybrid_decrypt():
    try:
        encrypted_data = base64.b64decode(request.json.get('encrypted_data'))
        encrypted_aes_key = base64.b64decode(request.json.get('encrypted_key'))
        iv = base64.b64decode(request.json.get('iv'))
        provided_auth_tag = base64.b64decode(request.json.get('auth_tag', ''))
        
        # Decrypt AES key with RSA
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Verify HMAC authentication tag before decrypting
        hmac_key = hashlib.sha256(aes_key + b'hmac-key').digest()
        calculated_auth_tag = hmac.new(
            hmac_key,
            iv + encrypted_data,
            hashlib.sha256
        ).digest()
        
        # Timing-safe comparison
        if not hmac.compare_digest(calculated_auth_tag, provided_auth_tag):
            return jsonify({
                'error': 'Authentication failed! Data has been tampered with or corrupted.',
                'success': False,
                'tampered': True
            }), 400
        
        # Decrypt data with AES (only if authentication passed)
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        padding_length = decrypted_padded[-1]
        decrypted_data = decrypted_padded[:-padding_length].decode('utf-8')
        
        return jsonify({
            'decrypted_text': decrypted_data,
            'success': True,
            'authenticated': True
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 400

if __name__ == '__main__':
    app.run(debug=True)
