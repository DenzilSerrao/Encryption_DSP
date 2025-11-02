# 🔐 Cryptography Methods Demo

A beautiful, educational Flask web application that demonstrates three essential cryptographic methods: SHA256 hashing, HMAC generation, and Hybrid RSA+AES encryption.

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![Flask](https://img.shields.io/badge/flask-2.0+-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## ✨ Features

### 1. SHA256 Hashing
- **One-way cryptographic hash function**
- Produces fixed 256-bit (64 hex characters) output
- Ideal for password storage and data integrity verification
- Demonstrates deterministic hashing and avalanche effect

### 2. HMAC Generation
- **Hash-based Message Authentication Code**
- Combines secret key with SHA256 for authentication
- Auto-generates secure random keys if none provided
- Perfect for API authentication and message verification

### 3. Hybrid RSA + AES Encryption
- **Best of both worlds encryption**
- RSA (2048-bit) for secure key exchange
- AES-256 (CBC mode) for fast data encryption
- Full encrypt/decrypt cycle demonstration
- Shows all cryptographic components (encrypted data, key, IV)

## 🚀 Quick Start

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Installation

1. **Clone or download this repository**
```bash
git clone <repository-url>
cd cryptography-demo
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the application**
```bash
python app.py
```

4. **Open in browser**
```
http://127.0.0.1:5000
```

## 📁 Project Structure

```
cryptography-demo/
│
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
│
└── templates/
    └── index.html        # Frontend UI
```

## 🎯 Usage

### SHA256 Hashing
1. Enter any text in the input field
2. Click "Generate SHA256 Hash"
3. View the resulting 64-character hash
4. Try modifying a single character to see how the hash changes completely

### HMAC Generation
1. Enter the message text
2. Optionally provide your own secret key (or leave blank for auto-generation)
3. Click "Generate HMAC"
4. Save the secret key if you need to verify the message later
5. The same message + key will always produce the same HMAC

### Hybrid Encryption
1. Enter text to encrypt
2. Click "Encrypt with Hybrid Method"
3. View the encrypted data, encrypted AES key, and initialization vector
4. Click "Decrypt" to recover the original text
5. Notice how RSA secures the AES key, and AES encrypts your data

## 🔒 Security Notes

### For Educational Use
This application is designed for **educational and demonstration purposes**. For production use, consider:

- **Key Management**: Store RSA keys securely (not in code)
- **Key Rotation**: Implement regular key rotation policies
- **HTTPS**: Always use HTTPS in production
- **Session Management**: Add proper session handling
- **Input Validation**: Implement comprehensive input sanitization
- **Rate Limiting**: Add rate limiting to prevent abuse
- **Logging**: Implement secure logging practices

### Cryptographic Best Practices Demonstrated
✅ Uses industry-standard algorithms (SHA256, HMAC-SHA256, RSA-2048, AES-256)  
✅ Proper padding (PKCS7 for AES, OAEP for RSA)  
✅ Random IV generation for each encryption  
✅ Secure key generation using `secrets` module  
✅ CBC mode with proper initialization vectors  

## 🛠️ Technical Details

### Technologies Used
- **Backend**: Flask 3.0.0
- **Cryptography**: cryptography library 41.0.0
- **Frontend**: Vanilla JavaScript, CSS3, HTML5
- **Styling**: Custom CSS with gradient themes

### Cryptographic Specifications
- **SHA256**: 256-bit output, one-way hash
- **HMAC**: SHA256-based, with custom or random key
- **RSA**: 2048-bit key size, OAEP padding with SHA256
- **AES**: 256-bit key, CBC mode, PKCS7 padding

## 📚 Educational Resources

### What You'll Learn
- Difference between hashing and encryption
- When to use symmetric vs asymmetric encryption
- How hybrid encryption combines the best of both
- Practical applications of each method
- Real-world use cases (SSL/TLS, JWT, blockchain)

### Common Use Cases
- **SHA256**: Password storage, blockchain, file integrity, digital signatures
- **HMAC**: API authentication, JWT tokens, webhook verification, cookie signing
- **Hybrid Encryption**: SSL/TLS, PGP/GPG, secure file transfer, encrypted email

## 🐛 Troubleshooting

### Import Error: No module named 'cryptography'
```bash
pip install --upgrade cryptography
```

### Flask not found
```bash
pip install --upgrade flask
```

### Template not found
Ensure your directory structure matches:
```
app.py
templates/
  └── index.html
```

### Port already in use
Change the port in `app.py`:
```python
app.run(debug=True, port=5001)
```

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new features
- Improve documentation
- Add more cryptographic methods

## 📄 License

This project is licensed under the MIT License - feel free to use it for learning and teaching!

## ⚠️ Disclaimer

This application is for **educational purposes only**. While it implements cryptographic standards correctly, it should not be used as-is for production security-critical applications without proper security auditing, key management, and additional security measures.

## 🎓 Learn More

- [Cryptography Library Docs](https://cryptography.io/)
- [OWASP Cryptographic Guidelines](https://owasp.org/www-project-cryptographic-storage-cheat-sheet/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/)

---

**Built with ❤️ for learning cryptography**