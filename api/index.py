from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
import json
import base64
import hashlib
import hmac
import time
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = FastAPI(
    title="GetContact API Serverless",
    description="Modern Vercel-deployed wrapper for GetContact CLI backend",
    version="8.4.0"
)

GTC_BASE = "https://pbssrv-centralevents.com"
HMAC_KEY = "31426764382a642f3a6665497235466f3d236d5d785b722b4c657457442a495b494524324866782a2364292478587a78662d7a7b7578593f71703e2b7e365762"

class SearchRequest(BaseModel):
    phone: str
    token: str
    final_key: str
    client_device_id: str
    source: str = "profile"

def _sig(ts: str, message: str, key_hex: str) -> str:
    mac = hmac.new(bytes.fromhex(key_hex), f"{ts}-{message}".encode(), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()

def _pad(b: bytes) -> bytes:
    n = 16 - len(b) % 16
    return b + bytes([n]) * n

def encrypt(data: str, key_hex: str) -> str:
    enc = Cipher(algorithms.AES(bytes.fromhex(key_hex)), modes.ECB()).encryptor()
    return base64.b64encode(enc.update(_pad(data.encode())) + enc.finalize()).decode()

def decrypt(data: str, key_hex: str) -> str:
    dec = Cipher(algorithms.AES(bytes.fromhex(key_hex)), modes.ECB()).decryptor()
    out = dec.update(base64.b64decode(data)) + dec.finalize()
    return out[: -out[-1]].decode()

@app.get("/")
def home():
    return {
        "status": "online",
        "service": "GetContact Vercel Serverless API",
        "version": "8.4.0",
        "author": "MFajarb & Upgraded for Vercel"
    }

@app.post("/api/search")
def api_search(req: SearchRequest):
    endpoint = "/v2.8/number-detail" if req.source == "tags" else "/v2.8/search"
    payload = {
        "countryCode": "id",
        "phoneNumber": req.phone,
        "source": "profile" if req.source == "tags" else "search",
        "token": req.token,
    }
    
    raw = json.dumps(payload, ensure_ascii=False)
    ts = str(int(time.time() * 1000))
    headers = {
        "Content-Type": "application/json",
        "x-os": "android 9",
        "x-app-version": "8.4.0",
        "x-client-device-id": req.client_device_id,
        "x-lang": "en_US",
        "x-req-timestamp": ts,
        "x-country-code": "id",
        "x-encrypted": "1",
        "x-req-signature": _sig(ts, raw, HMAC_KEY),
        "x-token": req.token
    }
    
    body = json.dumps({"data": encrypt(raw, req.final_key)})
    r = requests.post(GTC_BASE + endpoint, data=body, headers=headers, timeout=25)
    
    try:
        parsed = r.json()
    except ValueError:
        raise HTTPException(status_code=502, detail="Non-JSON response from upstream provider")
        
    if "data" in parsed:
        parsed = json.loads(decrypt(parsed["data"], req.final_key))
        
    return {"http_code": r.status_code, "data": parsed}
