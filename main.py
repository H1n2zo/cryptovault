from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import mysql.connector
import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "encryption_db"
}

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

def derive_key(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode()).digest()

def encrypt_aes(text: str, passphrase: str) -> str:
    key = derive_key(passphrase)
    iv = os.urandom(16)
    
    padder = padding.PKCS7(128).padder()
    padded = padder.update(text.encode()) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    
    return base64.b64encode(iv + ct).decode()

def decrypt_aes(token: str, passphrase: str) -> str:
    key = derive_key(passphrase)
    token = ''.join(token.split())  # strip whitespace
    raw = base64.b64decode(token)
    iv, ct = raw[:16], raw[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

class EncryptRequest(BaseModel):
    text: str
    passphrase: str

class DecryptRequest(BaseModel):
    cipher_text: str
    passphrase: str

@app.post("/encrypt")
def encrypt_and_store(req: EncryptRequest):
    encrypted = encrypt_aes(req.text, req.passphrase)
    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO entries (cipher_text) VALUES (%s)", (encrypted,))
    db.commit()
    db.close()
    return {"cipher_text": encrypted}

@app.post("/decrypt")
def decrypt_entry(req: DecryptRequest):
    try:
        plain = decrypt_aes(req.cipher_text.strip(), req.passphrase)
        return {"text": plain}
    except Exception:
        raise HTTPException(status_code=400, detail="Wrong passphrase or corrupted data")
