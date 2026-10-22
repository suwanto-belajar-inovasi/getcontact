from __future__ import annotations
import base64
import hashlib
import hmac
import json
import time
import requests
from flask import Flask, render_template_string, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

# Konfigurasi GetContact API Constants[cite: 1]
GTC_BASE = "https://pbssrv-centralevents.com"
HMAC_KEY = "31426764382a642f3a6665497235466f3d236d5d785b722b4c657457442a495b494524324866782a2364292478587a78662d7a7b7578593f71703e2b7e365762"
ANDROID_OS = "android 9"
APP_VERSION = "8.4.0"
LANG = "en_US"
COUNTRY = "id"

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

def _ts() -> str:
    return str(int(time.time() * 1000))

def gtc_call(endpoint: str, payload: dict, token: str, final_key: str, device_id: str) -> tuple[int, dict]:
    raw = json.dumps(payload, ensure_ascii=False)
    ts = _ts()
    headers = {
        "Content-Type": "application/json",
        "x-os": ANDROID_OS,
        "x-app-version": APP_VERSION,
        "x-client-device-id": device_id or "default_device_id",
        "x-lang": LANG,
        "x-req-timestamp": ts,
        "x-country-code": COUNTRY,
        "x-encrypted": "1",
        "x-req-signature": _sig(ts, raw, HMAC_KEY),
    }
    if token:
        headers["x-token"] = token
    body = json.dumps({"data": encrypt(raw, final_key)})
    r = requests.post(GTC_BASE + endpoint, data=body, headers=headers, timeout=25)
    try:
        parsed = r.json()
    except ValueError:
        return r.status_code, {"meta": {"errorMessage": "Non-JSON response from server"}}
    if "data" in parsed:
        try:
            parsed = json.loads(decrypt(parsed["data"], final_key))
        except Exception:
            pass
    return r.status_code, parsed

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="id" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GetContact Web Nexus</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style> body { font-family: 'Plus Jakarta Sans', sans-serif; } </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col">
    <header class="border-b border-slate-800/80 bg-slate-900/50 backdrop-blur-xl sticky top-0 z-50">
        <div class="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
            <h1 class="font-bold text-lg tracking-tight text-white">GetContact Web Nexus</h1>
            <span class="px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Online</span>
        </div>
    </header>
    <main class="flex-grow max-w-5xl w-full mx-auto px-4 py-8 space-y-6" x-data="getcontactApp()">
        <div class="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-6 shadow-xl">
            <h2 class="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center justify-between">
                <span>🔐 Autentikasi Akun (Credential)</span>
                <button @click="showCred = !showCred" class="text-xs text-emerald-400 hover:underline" x-text="showCred ? 'Sembunyikan' : 'Ubah Kredensial'"></button>
            </h2>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4" x-show="showCred">
                <div>
                    <label class="block text-xs text-slate-400 mb-1">Token</label>
                    <input type="text" x-model="token" placeholder="Token..." class="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">Final Key (Hex)</label>
                    <input type="text" x-model="finalKey" placeholder="Final Key..." class="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">Device ID</label>
                    <input type="text" x-model="deviceId" placeholder="Device ID..." class="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200">
                </div>
            </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div class="space-y-6">
                <div class="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-6 space-y-4">
                    <h3 class="font-semibold text-slate-200 text-sm">🔍 Pencarian Nomor</h3>
                    <input type="text" x-model="phone" placeholder="+628xxxxxxxxxx" class="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-sm text-slate-200">
                    <select x-model="searchType" class="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-sm text-slate-200">
                        <option value="profile">Profil Pemilik</option>
                        <option value="tags">Tag / Nama Tersimpan</option>
                    </select>
                    <button @click="performSearch" class="w-full bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold py-2.5 rounded-xl transition">Cari Sekarang</button>
                </div>
            </div>
            <div class="md:col-span-2">
                <div class="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-6 min-h-[300px]">
                    <h3 class="font-semibold text-slate-200 text-sm mb-4">📋 Hasil Data</h3>
                    <pre class="text-xs text-emerald-300 font-mono overflow-x-auto" x-text="JSON.stringify(searchResult, null, 2)"></pre>
                </div>
            </div>
        </div>
    </main>
    <script>
        function getcontactApp() {
            return {
                token: localStorage.getItem('gtc_token') || '',
                finalKey: localStorage.getItem('gtc_finalKey') || '',
                deviceId: localStorage.getItem('gtc_deviceId') || '',
                phone: '', searchType: 'profile', showCred: false, searchResult: null,
                init() {
                    this.$watch('token', val => localStorage.setItem('gtc_token', val));
                    this.$watch('finalKey', val => localStorage.setItem('gtc_finalKey', val));
                    this.$watch('deviceId', val => localStorage.setItem('gtc_deviceId', val));
                },
                async performSearch() {
                    let res = await fetch('/api/search', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token: this.token, finalKey: this.finalKey, deviceId: this.deviceId, phone: this.phone, type: this.searchType })
                    });
                    this.searchResult = await res.json();
                }
            }
        }
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/search", methods=["POST"])
def api_search_endpoint():
    data = request.json or {}
    token, final_key, device_id = data.get("token"), data.get("finalKey"), data.get("deviceId")
    phone = data.get("phone", "").strip()
    if phone.startswith("0"): phone = "+62" + phone[1:]
    elif phone.startswith("62"): phone = "+" + phone
    source = data.get("type", "profile")
    endpoint = "/v2.8/number-detail" if source == "tags" else "/v2.8/search"
    payload = {"countryCode": COUNTRY, "phoneNumber": phone, "source": "profile" if source == "tags" else "search", "token": token}
    code, body = gtc_call(endpoint, payload, token, final_key, device_id)
    return jsonify(body), code
