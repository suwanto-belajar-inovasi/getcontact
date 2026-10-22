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
    dec = Cipher(algorithms.AES(bytes.fromhex(key_hex)), modes.ECB()).encryptor()
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

def dig(obj, path, default=None):
    for k in path.split("."):
        if not isinstance(obj, dict) or k not in obj:
            return default
        obj = obj[k]
    return obj

# Frontend HTML Template dengan Cyber-Dark & Glassmorphism yang Elegan serta Penampil Tag Interaktif
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="id" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GetContact Web Nexus | Professional Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; }
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col selection:bg-emerald-500 selection:text-white">
    <!-- Header -->
    <header class="border-b border-slate-800/80 bg-slate-900/50 backdrop-blur-xl sticky top-0 z-50">
        <div class="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <div class="h-10 w-10 rounded-xl bg-gradient-to-tr from-emerald-500 to-teal-400 flex items-center justify-center shadow-lg shadow-emerald-500/20 font-bold text-slate-950 text-xl">
                    G
                </div>
                <div>
                    <h1 class="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">GetContact Web Nexus</h1>
                    <p class="text-xs text-slate-400">Powered by Flask & Vercel Serverless</p>
                </div>
            </div>
            <div class="flex items-center space-x-2">
                <span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse mr-1.5"></span> Online
                </span>
            </div>
        </div>
    </header>

    <!-- Main Container -->
    <main class="flex-grow max-w-5xl w-full mx-auto px-4 py-8 space-y-6" x-data="getcontactApp()">
        
        <!-- Credential Configuration Card -->
        <div class="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-2xl p-6 shadow-xl relative overflow-hidden">
            <div class="absolute -right-10 -top-10 w-40 h-40 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none"></div>
            <h2 class="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center justify-between">
                <span>🔐 Autentikasi Akun (Credential)</span>
                <button @click="showCred = !showCred" class="text-xs text-emerald-400 hover:underline focus:outline-none" x-text="showCred ? 'Sembunyikan' : 'Ubah Kredensial'"></button>
            </h2>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4" x-show="showCred" x-transition>
                <div>
                    <label class="block text-xs font-medium text-slate-400 mb-1">Token</label>
                    <input type="text" x-model="token" placeholder="Masukkan Token..." class="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500 transition">
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-400 mb-1">Final Key (Hex)</label>
                    <input type="text" x-model="finalKey" placeholder="Masukkan Final Key..." class="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500 transition">
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-400 mb-1">Client Device ID</label>
                    <input type="text" x-model="deviceId" placeholder="Device ID..." class="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500 transition">
                </div>
            </div>
            <div class="text-xs text-slate-500 mt-2" x-show="!showCred">
                Kredensial aktif tersimpan di sesi browser Anda. Klik "Ubah Kredensial" jika ingin mengganti token.
            </div>
        </div>

        <!-- Action Panel Tabs -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            <!-- Left Column: Search & Quota Controls -->
            <div class="md:col-span-1 space-y-6">
                <!-- Search Box -->
                <div class="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-2xl p-6 shadow-xl space-y-4">
                    <h3 class="font-semibold text-slate-200 text-sm">🔍 Pencarian Nomor</h3>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">Nomor Telepon (E.164 / Lokal)</label>
                        <input type="text" x-model="phone" placeholder="+628xxxxxxxxxx" class="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-emerald-500 transition">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">Tipe Pencarian</label>
                        <select x-model="searchType" class="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-emerald-500 transition">
                            <option value="profile">Profil Pemilik (Search)</option>
                            <option value="tags">Tag / Nama Tersimpan (Detail)</option>
                        </select>
                    </div>
                    <button @click="performSearch" :disabled="loading" class="w-full bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-600 hover:to-teal-600 text-slate-950 font-semibold py-2.5 rounded-xl shadow-lg shadow-emerald-500/20 transition disabled:opacity-50 flex items-center justify-center space-x-2">
                        <svg x-show="loading" class="animate-spin -ml-1 mr-2 h-4 w-4 text-slate-950" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                        <span x-text="loading ? 'Memproses...' : 'Cari Sekarang'"></span>
                    </button>
                </div>

                <!-- Quota Widget -->
                <div class="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-2xl p-6 shadow-xl space-y-3">
                    <div class="flex items-center justify-between">
                        <h3 class="font-semibold text-slate-200 text-sm">📊 Status Kuota</h3>
                        <button @click="fetchQuota" class="text-xs text-emerald-400 hover:underline">Refresh</button>
                    </div>
                    <div class="text-xs text-slate-400 space-y-1" x-html="quotaInfo">
                        Klik tombol refresh untuk memuat sisa kuota akun Anda.
                    </div>
                </div>
            </div>

            <!-- Right Column: Results Display -->
            <div class="md:col-span-2">
                <div class="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-2xl p-6 shadow-xl min-h-[420px] flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
                            <h3 class="font-semibold text-slate-200 text-sm">📋 Hasil Analisis & Data</h3>
                            <span class="text-xs text-slate-400" x-text="resultStatus"></span>
                        </div>

                        <!-- Result Content Container -->
                        <div class="space-y-4">
                            <template x-if="searchResult">
                                <div class="space-y-4">
                                    <!-- Profile Info Card -->
                                    <template x-if="searchResult.result && searchResult.result.profile">
                                        <div class="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 space-y-2">
                                            <div class="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Informasi Profil</div>
                                            <div class="grid grid-cols-2 gap-2 text-sm">
                                                <div><span class="text-slate-400 text-xs">Nama Tampil:</span> <div class="font-medium text-slate-200" x-text="searchResult.result.profile.displayName || '-'"></div></div>
                                                <div><span class="text-slate-400 text-xs">Nomor:</span> <div class="font-medium text-slate-200" x-text="searchResult.result.profile.phoneNumber || '-'"></div></div>
                                                <div><span class="text-slate-400 text-xs">Total Tag:</span> <div class="font-medium text-emerald-400" x-text="searchResult.result.profile.tagCount || '0'"></div></div>
                                            </div>
                                        </div>
                                    </template>

                                    <!-- Tags List Card (Detail View) -->
                                    <template x-if="searchResult.result && searchResult.result.tags">
                                        <div class="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 space-y-3">
                                            <div class="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Daftar Tag / Nama Tersimpan (<span x-text="searchResult.result.tags.length"></span>)</div>
                                            <div class="flex flex-wrap gap-2 max-h-64 overflow-y-auto pr-1">
                                                <template x-for="tag in searchResult.result.tags">
                                                    <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-slate-800 text-slate-200 border border-slate-700">
                                                        <span x-text="tag.tag"></span>
                                                        <span class="ml-1.5 px-1.5 py-0.2 bg-emerald-500/20 text-emerald-400 rounded-full text-[10px]" x-text="'x' + tag.count"></span>
                                                    </span>
                                                </template>
                                            </div>
                                        </div>
                                    </template>

                                    <!-- Raw JSON view fallback -->
                                    <div class="bg-slate-950/80 border border-slate-800/80 rounded-xl p-4">
                                        <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Raw JSON Response</div>
                                        <pre class="text-xs text-emerald-300 font-mono overflow-x-auto max-h-48" x-text="JSON.stringify(searchResult, null, 2)"></pre>
                                    </div>
                                </div>
                            </template>

                            <template x-if="!searchResult">
                                <div class="flex flex-col items-center justify-center py-20 text-center text-slate-500 space-y-2">
                                    <svg class="w-12 h-12 stroke-current opacity-40" fill="none" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                                    <p class="text-sm">Belum ada pencarian dilakukan.</p>
                                    <p class="text-xs text-slate-600">Masukkan nomor dan pilih tipe pencarian untuk memulai.</p>
                                </div>
                            </template>
                        </div>
                    </div>

                    <div class="border-t border-slate-800 pt-3 text-center text-xs text-slate-500">
                        GetContact Web Dashboard &bull; Handcrafted for Performance
                    </div>
                </div>
            </div>

        </div>
    </main>

    <!-- Alpine JS App Logic -->
    <script>
        function getcontactApp() {
            return {
                token: localStorage.getItem('gtc_token') || '',
                finalKey: localStorage.getItem('gtc_finalKey') || '',
                deviceId: localStorage.getItem('gtc_deviceId') || '',
                phone: '',
                searchType: 'profile',
                showCred: false,
                loading: false,
                searchResult: null,
                resultStatus: 'Menunggu input',
                quotaInfo: 'Belum dimuat.',

                init() {
                    this.$watch('token', val => localStorage.setItem('gtc_token', val));
                    this.$watch('finalKey', val => localStorage.setItem('gtc_finalKey', val));
                    this.$watch('deviceId', val => localStorage.setItem('gtc_deviceId', val));
                },

                async performSearch() {
                    if (!this.token || !this.finalKey) {
                        alert('Harap isi Token dan Final Key terlebih dahulu di menu Kredensial!');
                        this.showCred = true;
                        return;
                    }
                    if (!this.phone) {
                        alert('Masukkan nomor telepon yang ingin dicari.');
                        return;
                    }
                    this.loading = true;
                    this.resultStatus = 'Mengirim request ke server...';
                    try {
                        let res = await fetch('/api/search', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                token: this.token,
                                finalKey: this.finalKey,
                                deviceId: this.deviceId,
                                phone: this.phone,
                                type: this.searchType
                            })
                        });
                        let data = await res.json();
                        this.searchResult = data;
                        this.resultStatus = `Selesai (HTTP ${res.status})`;
                    } catch (err) {
                        alert('Terjadi kesalahan jaringan: ' + err);
                        this.resultStatus = 'Gagal';
                    } finally {
                        this.loading = false;
                    }
                },

                async fetchQuota() {
                    if (!this.token || !this.finalKey) {
                        alert('Harap isi Token dan Final Key terlebih dahulu!');
                        this.showCred = true;
                        return;
                    }
                    this.quotaInfo = 'Memuat kuota...';
                    try {
                        let res = await fetch('/api/quota', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                token: this.token,
                                finalKey: this.finalKey,
                                deviceId: this.deviceId
                            })
                        });
                        let data = await res.json();
                        let usage = data.result && data.result.subscriptionInfo ? data.result.subscriptionInfo.usage : null;
                        if (usage) {
                            let text = '';
                            for (let k in usage) {
                                text += `<div><b>${k}</b>: ${usage[k].remainingCount}/${usage[k].limit} tersisa</div>`;
                            }
                            this.quotaInfo = text;
                        } else {
                            this.quotaInfo = '<span class="text-red-400">Gagal memuat kuota atau token tidak valid.</span>';
                        }
                    } catch (err) {
                        this.quotaInfo = '<span class="text-red-400">Error koneksi server.</span>';
                    }
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
    token = data.get("token")
    final_key = data.get("finalKey")
    device_id = data.get("deviceId")
    phone_raw = data.get("phone", "")
    source = data.get("type", "profile")

    # Normalisasi nomor telepon
    phone = phone_raw.strip()
    if phone.startswith("0"):
        phone = "+62" + phone[1:]
    elif phone.startswith("62"):
        phone = "+" + phone

    # Endpoint otomatis dialihkan ke number-detail jika memilih tipe tags[cite: 1]
    endpoint = "/v2.8/number-detail" if source == "tags" else "/v2.8/search"
    payload = {
        "countryCode": COUNTRY,
        "phoneNumber": phone,
        "source": "profile" if source == "tags" else "search",
        "token": token,
    }

    code, body = gtc_call(endpoint, payload, token, final_key, device_id)
    return jsonify(body), code

@app.route("/api/quota", methods=["POST"])
def api_quota_endpoint():
    data = request.json or {}
    token = data.get("token")
    final_key = data.get("finalKey")
    device_id = data.get("deviceId")

    code, body = gtc_call("/v2.8/subscription", {"token": token}, token, final_key, device_id)
    return jsonify(body), code

if __name__ == "__main__":
    app.run(debug=True)
