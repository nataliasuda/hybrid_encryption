from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import base64
import os
import threading
import time

from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    load_der_public_key,
)
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = FastAPI(title="Hybrid Encryption Service")

lock = threading.Lock()

client_public_key_bytes: Optional[bytes] = None
aes_key: Optional[bytes] = None

class RegisterKeyRequest(BaseModel):
    public_key: str  

@app.post("/register-key")
async def register_key(req: RegisterKeyRequest):
    global client_public_key_bytes

    try:
        raw = base64.b64decode(req.public_key)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64: {e}")
    try:
        _ = load_pem_public_key(raw)
        with lock:
            client_public_key_bytes = raw[:]  
        return {"status": "ok", "format": "PEM"}
    except Exception:
        pass

    try:
        _ = load_der_public_key(raw)
        with lock:
            client_public_key_bytes = raw[:]
        return {"status": "ok", "format": "DER"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Unable to parse public key: {e}")

@app.get("/get-secret")
async def get_secret():
    global client_public_key_bytes, aes_key

    with lock:
        if client_public_key_bytes is None:
            raise HTTPException(status_code=404, detail="No public key registered")
        if aes_key is None:
            aes_key = os.urandom(32)  

        raw_key = client_public_key_bytes[:]

    try:
        public_key = load_pem_public_key(raw_key)
    except Exception:
        try:
            public_key = load_der_public_key(raw_key)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid stored public key: {e}")

    encrypted = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return {"encrypted_secret": base64.b64encode(encrypted).decode()}

@app.get("/get-message")
async def get_message():
    global aes_key
    with lock:
        if aes_key is None:
            raise HTTPException(status_code=404, detail="AES key not established yet")
        key = aes_key[:]


    ts = int(time.time())
    plaintext = f"Pozdrowienia z serwera, czas: {ts}".encode("utf-8")

    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(iv, plaintext, None)

    composed = iv + ciphertext_and_tag

    return {"ciphertext": base64.b64encode(composed).decode()}