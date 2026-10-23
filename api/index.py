from __future__ import annotations
import base64
import hashlib
import hmac
import json
import random
import re
import secrets
import time
import urllib.parse
import requests
from flask import Flask, render_template_string, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

# ==========================================
# KONFIGURASI GETCONTACT & VERIFYKIT CONSTANTS
# ==========================================
GTC_BASE = "https://pbssrv-centralevents.com"
VFK_BASE = "https://api.verifykit.com"

HMAC_KEY = "31426764382a642f3a6665497235466f3d236d5d785b722b4c657457442a495b494524324866782a2364292478587a78662d7a7b7578593f71703e2b7e365762"
VFK_HMAC_KEY = "3452235d713252604a35562d325f765238695738485863672a705e6841544d3c7e6e45463028266f372b544e596f3829236b392825262e534a7e774f37653932"
VFK_CLIENT_KEY = "bhvbd7ced119dc6ad6a0b35bd3cf836555d6f71930d9e5a405f32105c790d"
VFK_FINAL_KEY = "bd48d8c25293cfb537619cc93ae3d6e372eb2ddfffff4ab0eb000777144c7bfa"

APP_VERSION = "8.4.0"
ANDROID_OS = "android 9"
LANG = "en_US"
COUNTRY = "id"
DEVICE_NAME = "SM-G977N"
TIME_ZONE = "Asia/Bangkok"
BUNDLE_ID = "app.source.getcontact"
CARRIER = ("510", "Indosat Ooredoo", "01")

# Diffie-Hellman Parameters
DH_P = 900719898367
DH_G = 7

# Database HLR Operator Indonesia
ID_PREFIX_MAP = {
    "0811": ("Telkomsel", "KartuHalo (Pascabayar)"),
    "0812": ("Telkomsel", "SimPATI / Telkomsel PraBayar"),
    "0813": ("Telkomsel", "SimPATI / Telkomsel PraBayar"),
    "0821": ("Telkomsel", "SimPATI / Telkomsel PraBayar"),
    "0822": ("Telkomsel", "Kartu Loop / Telkomsel PraBayar"),
    "0823": ("Telkomsel", "Kartu As / Telkomsel PraBayar"),
    "0851": ("Telkomsel", "by.U / Kartu As"),
    "0852": ("Telkomsel", "Kartu As / Telkomsel PraBayar"),
    "0853": ("Telkomsel", "Kartu As / Telkomsel PraBayar"),
    "0814": ("Indosat Ooredoo Hutchison", "IM3 Indosat Broadband"),
    "0815": ("Indosat Ooredoo Hutchison", "Matrix / Mentari"),
    "0816": ("Indosat Ooredoo Hutchison", "Matrix / Mentari"),
    "0855": ("Indosat Ooredoo Hutchison", "Matrix Pascabayar / IM3"),
    "0856": ("Indosat Ooredoo Hutchison", "IM3"),
    "0857": ("Indosat Ooredoo Hutchison", "IM3"),
    "0858": ("Indosat Ooredoo Hutchison", "Mentari / IM3"),
    "0895": ("Indosat Ooredoo Hutchison", "Tri (3) Indonesia"),
    "0896": ("Indosat Ooredoo Hutchison", "Tri (3) Indonesia"),
    "0897": ("Indosat Ooredoo Hutchison", "Tri (3) Indonesia"),
    "0898": ("Indosat Ooredoo Hutchison", "Tri (3) Indonesia"),
    "0899": ("Indosat Ooredoo Hutchison", "Tri (3) Indonesia"),
    "0817": ("XL Axiata", "XL Prabayar / Prioritas"),
    "0818": ("XL Axiata", "XL Prabayar / Prioritas"),
    "0819": ("XL Axiata", "XL Prabayar / Prioritas"),
    "0859": ("XL Axiata", "XL / Live.On"),
    "0877": ("XL Axiata", "XL Prabayar"),
    "0878": ("XL Axiata", "XL Prabayar"),
    "0831": ("XL Axiata (AXIS)", "AXIS"),
    "0832": ("XL Axiata (AXIS)", "AXIS"),
    "0833": ("XL Axiata (AXIS)", "AXIS"),
    "0838": ("XL Axiata (AXIS)", "AXIS"),
    "0881": ("Smartfren", "Smartfren 4G/5G"),
    "0882": ("Smartfren", "Smartfren 4G/5G"),
    "0883": ("Smartfren", "Smartfren 4G/5G"),
    "0884": ("Smartfren", "Smartfren 4G/5G"),
    "0885": ("Smartfren", "Smartfren 4G/5G"),
    "0886": ("Smartfren", "Smartfren 4G/5G"),
    "0887": ("Smartfren", "Smartfren 4G/5G"),
    "0888": ("Smartfren", "Smartfren 4G/5G"),
    "0889": ("Smartfren", "Smartfren 4G/5G"),
}


# ==========================================
# FUNGSI KRIPTOGRAFI & UTILITAS
# ==========================================
def _sig(ts: str, message: str, key_hex: str) -> str:
    clean_key = key_hex.strip()
    mac = hmac.new(bytes.fromhex(clean_key), f"{ts}-{message}".encode(), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()


def _pad(b: bytes) -> bytes:
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def encrypt(data: str, key_hex: str) -> str:
    clean_key = key_hex.strip()
    enc = Cipher(algorithms.AES(bytes.fromhex(clean_key)), modes.ECB()).encryptor()
    return base64.b64encode(enc.update(_pad(data.encode())) + enc.finalize()).decode()


def decrypt(data: str, key_hex: str) -> str:
    clean_key = key_hex.strip()
    b_key = bytes.fromhex(clean_key)
    dec = Cipher(algorithms.AES(b_key), modes.ECB()).decryptor()
    decoded_bytes = base64.b64decode(data)
    out = dec.update(decoded_bytes) + dec.finalize()
    if not out:
        return ""
    pad_len = out[-1]
    unpadded = out if (pad_len > 16 or pad_len <= 0) else out[:-pad_len]
    return unpadded.decode("utf-8", errors="ignore").strip()


def dh_keypair() -> tuple[int, int]:
    priv = secrets.randbelow(10**8 - 10**6) + 10**6
    return priv, pow(DH_G, priv, DH_P)


def dh_final_key(priv: int, server_pub: int) -> str:
    return hashlib.sha256(str(pow(int(server_pub), priv, DH_P)).encode()).hexdigest()


def _ts() -> str:
    return str(int(time.time() * 1000))


def normalize_phone(raw: str) -> tuple[str, str]:
    p = re.sub(r"[^\d+]", "", raw.strip())
    if p.startswith("+62"):
        return p, "0" + p[3:]
    if p.startswith("62"):
        return "+" + p, "0" + p[2:]
    if p.startswith("0"):
        return "+62" + p[1:], p
    if p.startswith("+"):
        return p, p
    return "+62" + p, "0" + p


def analyze_indonesian_number(raw_phone: str) -> dict:
    e164, local_num = normalize_phone(raw_phone)
    provider, card_type = ID_PREFIX_MAP.get(local_num[:4], ("Operator Seluler / PSTN", "Reguler"))
    clean_digits = re.sub(r"[^\d]", "", e164)
    return {
        "e164": e164,
        "local": local_num,
        "clean_digits": clean_digits,
        "provider": provider,
        "card_type": card_type,
        "region": "Nasional (Indonesia)",
        "osint_links": {
            "whatsapp": f"https://api.whatsapp.com/send?phone={clean_digits}",
            "truecaller": f"https://www.truecaller.com/search/id/{clean_digits}",
            "syncme": f"https://sync.me/search/?number={clean_digits}",
            "tellows": f"https://id.tellows.net/num/{local_num}",
            "google_dork": f"https://www.google.com/search?q=%22{local_num}%22+OR+%22{e164}%22",
        }
    }


def gtc_call(endpoint: str, payload: dict, token: str, final_key: str, device_id: str, encrypted: bool = True) -> tuple[int, dict]:
    raw = json.dumps(payload, ensure_ascii=False)
    ts = _ts()
    clean_token = (token or "").strip()
    clean_key = (final_key or "").strip()
    clean_device = (device_id or secrets.token_hex(8)).strip()

    headers = {
        "Content-Type": "application/json",
        "x-os": ANDROID_OS,
        "x-app-version": APP_VERSION,
        "x-client-device-id": clean_device,
        "x-lang": LANG,
        "x-req-timestamp": ts,
        "x-country-code": COUNTRY,
        "x-encrypted": "1" if encrypted else "0",
        "x-req-signature": _sig(ts, raw, HMAC_KEY),
    }
    if clean_token:
        headers["x-token"] = clean_token

    try:
        body = json.dumps({"data": encrypt(raw, clean_key)}) if encrypted else raw
        r = requests.post(GTC_BASE + endpoint, data=body, headers=headers, timeout=22)
        parsed = r.json() if r.text.strip() else {}
    except Exception as e:
        return 500, {"meta": {"errorMessage": str(e)}}

    if encrypted and "data" in parsed:
        try:
            decrypted_str = decrypt(parsed["data"], clean_key)
            if decrypted_str:
                parsed = json.loads(decrypted_str)
        except Exception as e:
            return 400, {"meta": {"errorMessage": f"Decryption error: {str(e)}"}}

    return r.status_code, parsed


def vfk_call(endpoint: str, payload: dict, device_id: str) -> tuple[int, dict]:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    ts = _ts()
    headers = {
        "Content-Type": "application/json",
        "X-VFK-Client-Device-Id": device_id,
        "X-VFK-Client-Key": VFK_CLIENT_KEY,
        "X-VFK-Sdk-Version": "0.11.4",
        "X-VFK-Os": "android 9.0",
        "X-VFK-App-Version": "8.16.0",
        "X-VFK-Encrypted": "1",
        "X-VFK-Lang": "in_ID",
        "X-VFK-Req-Timestamp": ts,
        "X-VFK-Req-Signature": _sig(ts, raw, VFK_HMAC_KEY),
    }
    body = json.dumps({"data": encrypt(raw, VFK_FINAL_KEY)}, separators=(",", ":"))
    try:
        r = requests.post(VFK_BASE + endpoint, data=body, headers=headers, timeout=22)
        parsed = r.json()
        if "data" in parsed:
            parsed = json.loads(decrypt(parsed["data"], VFK_FINAL_KEY))
        return r.status_code, parsed
    except Exception as e:
        return 500, {"error": str(e)}


def extract_tags_from_dict(obj) -> list[dict]:
    found = []
    def _walk(node):
        if isinstance(node, list):
            for item in node:
                _walk(item)
        elif isinstance(node, dict):
            if "tag" in node and isinstance(node["tag"], str):
                found.append({"tag": node["tag"].strip(), "count": int(node.get("count") or 1)})
            elif "tagName" in node and isinstance(node["tagName"], str):
                found.append({"tag": node["tagName"].strip(), "count": int(node.get("count") or 1)})
            for v in node.values():
                if isinstance(v, (dict, list)):
                    _walk(v)
    _walk(obj)
    return found


# ==========================================
# FRONTEND SINGLE PAGE APPLICATION (HTML)
# ==========================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="id" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
    <title>OmniContact Nexus v3.0 | Full Tag Unlocker & Multi-Token Pool</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: { extend: { fontFamily: { sans: ['Plus Jakarta Sans', 'sans-serif'] } } }
        }
    </script>
    <style>
        [x-cloak] { display: none !important; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: rgba(15, 23, 42, 0.4); }
        ::-webkit-scrollbar-thumb { background: rgba(16, 185, 129, 0.4); border-radius: 9999px; }
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col selection:bg-emerald-500 selection:text-white antialiased" x-data="nexusAppV3()">

    <!-- NAVBAR -->
    <header class="border-b border-slate-800/80 bg-slate-900/80 backdrop-blur-xl sticky top-0 z-40">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 py-3.5 flex flex-wrap items-center justify-between gap-3">
            <div class="flex items-center space-x-3">
                <div class="h-10 w-10 sm:h-11 sm:w-11 rounded-2xl bg-gradient-to-tr from-emerald-500 via-teal-400 to-cyan-400 flex items-center justify-center shadow-lg shadow-emerald-500/25 text-slate-950 text-xl font-extrabold">
                    <i class="fa-solid fa-satellite-dish"></i>
                </div>
                <div>
                    <div class="flex items-center gap-2">
                        <h1 class="font-extrabold text-base sm:text-lg tracking-tight bg-gradient-to-r from-white via-slate-100 to-emerald-300 bg-clip-text text-transparent">
                            OmniContact Nexus
                        </h1>
                        <span class="px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded-full">v3.0 Full-Tag</span>
                    </div>
                    <p class="text-[11px] sm:text-xs text-slate-400">Multi-Token Pool, WA Token Generator & Deep Tag Extractor</p>
                </div>
            </div>

            <div class="flex flex-wrap items-center gap-2">
                <button @click="showGenModal = true" class="px-3 py-2 rounded-xl text-xs font-bold bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-slate-950 shadow-md shadow-emerald-500/10 transition flex items-center gap-1.5">
                    <i class="fa-brands fa-whatsapp text-sm"></i>
                    <span>+ Buat Token Baru (Unlock Semua Tag)</span>
                </button>
                <button @click="showCredModal = true" class="px-3 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition flex items-center gap-1.5">
                    <i class="fa-solid fa-users-gear text-cyan-400"></i>
                    <span>Pool Token (<span x-text="accountPool.length"></span>)</span>
                </button>
                <button @click="openCaptchaModal()" class="px-3 py-2 rounded-xl text-xs font-semibold bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition flex items-center gap-1.5">
                    <i class="fa-solid fa-shield-halved"></i>
                    <span class="hidden md:inline">Unblock 403</span>
                </button>
            </div>
        </div>
    </header>

    <!-- MAIN CONTENT -->
    <main class="flex-grow max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">

            <!-- KOLOM KIRI -->
            <div class="lg:col-span-4 space-y-6">

                <!-- FORM DETEKSI NOMOR -->
                <div class="bg-slate-900/70 backdrop-blur-md border border-slate-800/90 rounded-2xl p-5 shadow-xl space-y-4">
                    <div class="flex items-center justify-between">
                        <h2 class="font-bold text-slate-100 text-sm sm:text-base flex items-center gap-2">
                            <i class="fa-solid fa-magnifying-glass-chart text-emerald-400"></i>
                            Deteksi & Ekstrak Semua Tag
                        </h2>
                        <span class="text-[11px] font-mono text-emerald-400" x-text="accountPool.length + ' Token Aktif'"></span>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1.5">Nomor Telepon Target</label>
                        <div class="relative">
                            <span class="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-400">
                                <i class="fa-solid fa-phone text-xs"></i>
                            </span>
                            <input type="tel" x-model="phone" @keyup.enter="performSearch()" placeholder="Contoh: 085536666320"
                                class="w-full bg-slate-950/90 border border-slate-800 focus:border-emerald-500 rounded-xl pl-9 pr-9 py-3 text-sm font-semibold text-slate-100 placeholder-slate-600 focus:outline-none">
                            <button x-show="phone" @click="phone = ''" class="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500 hover:text-slate-300">
                                <i class="fa-solid fa-circle-xmark"></i>
                            </button>
                        </div>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1.5">Strategi Ekstraksi Tag</label>
                        <select x-model="searchMode" class="w-full bg-slate-950/90 border border-slate-800 focus:border-emerald-500 rounded-xl px-3.5 py-2.5 text-xs sm:text-sm text-slate-200 focus:outline-none">
                            <option value="deep_force">🚀 Deep Multi-Vector + Auto Token Rotation (Maksimal)</option>
                            <option value="hlr_osint">🌐 Alternatif: HLR + OSINT Lookup (Tanpa Token)</option>
                        </select>
                    </div>

                    <button @click="performSearch()" :disabled="loading"
                        class="w-full bg-gradient-to-r from-emerald-500 via-teal-500 to-cyan-500 hover:from-emerald-400 hover:to-teal-400 text-slate-950 font-extrabold py-3 px-4 rounded-xl shadow-lg shadow-emerald-500/20 transition disabled:opacity-50 flex items-center justify-center gap-2 text-sm">
                        <template x-if="!loading">
                            <span><i class="fa-solid fa-bolt mr-1"></i> Pindai & Buka Semua Tag</span>
                        </template>
                        <template x-if="loading">
                            <span><i class="fa-solid fa-circle-notch fa-spin mr-1"></i> Mengekstrak Multi-Endpoint...</span>
                        </template>
                    </button>
                </div>

                <!-- INFO PENTING KENAPA 2 DARI 149 TAG -->
                <div class="bg-gradient-to-br from-emerald-950/40 to-slate-900/90 border border-emerald-500/30 rounded-2xl p-4 shadow-xl space-y-2.5">
                    <div class="flex items-center gap-2 text-xs font-bold text-emerald-300">
                        <i class="fa-solid fa-lightbulb text-amber-400 text-sm"></i>
                        Cara Membuka 100% Tag Jika Kuota Detail 0/0:
                    </div>
                    <p class="text-[11px] text-slate-300 leading-relaxed">
                        Server GetContact memberikan <b>akses penuh (100% seluruh tag) tanpa kuota</b> jika nomor yang dicari memiliki Token di dalam <b>Pool Token</b>, atau jika salah satu Token Anda masih memiliki kuota <i>Detail Tag</i> (&gt;0).
                    </p>
                    <button @click="genPhone = phone || ''; showGenModal = true" class="w-full py-2 px-3 rounded-xl bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 text-xs font-bold transition flex items-center justify-center gap-1.5">
                        <i class="fa-brands fa-whatsapp"></i> Daftarkan Nomor via WA (30 Detik)
                    </button>
                </div>

                <!-- STATUS KUOTA AKUN AKTIF -->
                <div class="bg-slate-900/70 backdrop-blur-md border border-slate-800/90 rounded-2xl p-5 shadow-xl space-y-3">
                    <div class="flex items-center justify-between">
                        <h3 class="font-bold text-slate-200 text-xs sm:text-sm flex items-center gap-2">
                            <i class="fa-solid fa-gauge-high text-cyan-400"></i>
                            Status Kuota Token Utama
                        </h3>
                        <button @click="fetchQuota()" class="text-xs font-semibold text-emerald-400 hover:underline flex items-center gap-1">
                            <i class="fa-solid fa-rotate" :class="loadingQuota ? 'fa-spin' : ''"></i> Cek Kuota
                        </button>
                    </div>

                    <template x-if="quotaData">
                        <div class="grid grid-cols-2 gap-2.5 pt-1">
                            <div class="bg-slate-950/80 border border-slate-800/80 rounded-xl p-3">
                                <div class="text-[11px] text-slate-400">Kuota Search Profil</div>
                                <div class="text-base font-extrabold text-emerald-400 mt-0.5" x-text="quotaData.search"></div>
                            </div>
                            <div class="bg-slate-950/80 border border-slate-800/80 rounded-xl p-3">
                                <div class="text-[11px] text-slate-400">Kuota Detail Tag</div>
                                <div class="text-base font-extrabold" :class="quotaData.rawDetail > 0 ? 'text-emerald-400' : 'text-amber-400'" x-text="quotaData.numberDetail"></div>
                            </div>
                        </div>
                    </template>
                    <template x-if="!quotaData">
                        <p class="text-xs text-slate-500">Klik "Cek Kuota" untuk melihat sisa kuota token aktif.</p>
                    </template>
                </div>

                <!-- RIWAYAT PENCARIAN -->
                <div class="bg-slate-900/70 backdrop-blur-md border border-slate-800/90 rounded-2xl p-5 shadow-xl space-y-3">
                    <div class="flex items-center justify-between">
                        <h3 class="font-bold text-slate-200 text-xs sm:text-sm flex items-center gap-2">
                            <i class="fa-solid fa-clock-rotate-left text-purple-400"></i>
                            Riwayat Pencarian
                        </h3>
                        <button x-show="historyList.length > 0" @click="clearHistory()" class="text-[11px] text-rose-400 hover:underline">Hapus</button>
                    </div>
                    <div class="space-y-2 max-h-48 overflow-y-auto pr-1">
                        <template x-for="item in historyList" :key="item.phone">
                            <div @click="phone = item.phone; performSearch()" class="flex items-center justify-between p-2.5 rounded-xl bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800/70 cursor-pointer transition">
                                <div class="truncate pr-2">
                                    <div class="text-xs font-bold text-slate-200 truncate" x-text="item.name || item.phone"></div>
                                    <div class="text-[11px] text-slate-400 font-mono" x-text="item.phone + ' • ' + item.provider"></div>
                                </div>
                                <span class="px-2 py-0.5 text-[10px] font-semibold bg-emerald-500/15 text-emerald-400 rounded-lg shrink-0" x-text="item.tagCount + ' tag'"></span>
                            </div>
                        </template>
                    </div>
                </div>

            </div>

            <!-- KOLOM KANAN: DASHBOARD HASIL -->
            <div class="lg:col-span-8 space-y-6">
                <div class="bg-slate-900/70 backdrop-blur-md border border-slate-800/90 rounded-2xl p-5 sm:p-6 shadow-xl min-h-[560px] flex flex-col justify-between">
                    <div class="space-y-5">

                        <!-- TABS -->
                        <div class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
                            <div class="flex items-center gap-2">
                                <span class="h-2.5 w-2.5 rounded-full bg-emerald-400"></span>
                                <h3 class="font-bold text-slate-100 text-sm sm:text-base">Dashboard Hasil Intelijen Nomor</h3>
                            </div>
                            <div class="flex flex-wrap items-center gap-1.5">
                                <button @click="activeTab = 'overview'" :class="activeTab === 'overview' ? 'bg-emerald-500 text-slate-950 font-bold' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'" class="px-3 py-1.5 rounded-xl text-xs transition">
                                    <i class="fa-solid fa-tags mr-1"></i> Daftar Tag (<span x-text="extractedTags.length"></span>)
                                </button>
                                <button @click="activeTab = 'osint'" :class="activeTab === 'osint' ? 'bg-emerald-500 text-slate-950 font-bold' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'" class="px-3 py-1.5 rounded-xl text-xs transition">
                                    <i class="fa-solid fa-globe mr-1"></i> Alternatif Lookup & OSINT
                                </button>
                                <button @click="activeTab = 'raw'" :class="activeTab === 'raw' ? 'bg-emerald-500 text-slate-950 font-bold' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'" class="px-3 py-1.5 rounded-xl text-xs transition">
                                    <i class="fa-solid fa-code mr-1"></i> Raw JSON
                                </button>
                            </div>
                        </div>

                        <!-- STATE BELUM ADA DATA -->
                        <template x-if="!resultData && !loading">
                            <div class="flex flex-col items-center justify-center py-20 text-center px-4">
                                <div class="w-16 h-16 rounded-2xl bg-slate-800/80 border border-slate-700 flex items-center justify-center text-emerald-400 text-2xl mb-4">
                                    <i class="fa-solid fa-address-card"></i>
                                </div>
                                <h4 class="text-base font-bold text-slate-200">Siap Mengekstrak Seluruh Tag Kontak</h4>
                                <p class="text-xs sm:text-sm text-slate-400 max-w-md mt-1">
                                    Masukkan nomor telepon di sebelah kiri, atau tambahkan token baru melalui tombol <b>+ Buat Token Baru</b> di atas.
                                </p>
                            </div>
                        </template>

                        <!-- LOADING -->
                        <template x-if="loading">
                            <div class="flex flex-col items-center justify-center py-24 text-center space-y-3">
                                <div class="w-12 h-12 border-4 border-emerald-500/30 border-t-emerald-400 rounded-full animate-spin"></div>
                                <p class="text-sm font-semibold text-slate-300">Menjalankan Deep Multi-Vector Probe & Rotasi Token...</p>
                            </div>
                        </template>

                        <!-- HASIL -->
                        <template x-if="resultData && !loading">
                            <div class="space-y-5">

                                <!-- PROFIL HEADER -->
                                <div class="bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 border border-slate-800 rounded-2xl p-4 sm:p-5">
                                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                                        <div class="flex items-start sm:items-center gap-3.5">
                                            <div class="w-12 h-12 sm:w-14 sm:h-14 rounded-2xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400 text-xl sm:text-2xl font-bold shrink-0">
                                                <i class="fa-solid fa-user-check"></i>
                                            </div>
                                            <div>
                                                <div class="flex flex-wrap items-center gap-2">
                                                    <h4 class="text-base sm:text-xl font-extrabold text-white" x-text="getPrimaryName()"></h4>
                                                    <span class="px-2 py-0.5 text-[10px] font-bold bg-emerald-500/20 text-emerald-300 rounded-md border border-emerald-500/30" x-text="resultData.hlr.provider"></span>
                                                </div>
                                                <p class="text-xs sm:text-sm font-mono text-slate-400 mt-0.5">
                                                    <span x-text="resultData.hlr.e164"></span> &bull; <span x-text="resultData.hlr.local"></span>
                                                </p>
                                            </div>
                                        </div>

                                        <div class="flex flex-wrap items-center gap-2">
                                            <a :href="resultData.hlr.osint_links.whatsapp" target="_blank" class="px-3 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold flex items-center gap-1.5 transition">
                                                <i class="fa-brands fa-whatsapp"></i> Chat WA
                                            </a>
                                            <button @click="exportTagsCSV()" x-show="extractedTags.length > 0" class="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition">
                                                <i class="fa-solid fa-file-csv text-emerald-400"></i> Export CSV
                                            </button>
                                        </div>
                                    </div>

                                    <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5 mt-4 pt-4 border-t border-slate-800/80 text-xs">
                                        <div class="bg-slate-900/90 p-2.5 rounded-xl border border-slate-800/60">
                                            <span class="text-slate-400 block text-[10px] uppercase">Produk / Kartu</span>
                                            <span class="font-bold text-slate-200" x-text="resultData.hlr.card_type"></span>
                                        </div>
                                        <div class="bg-slate-900/90 p-2.5 rounded-xl border border-slate-800/60">
                                            <span class="text-slate-400 block text-[10px] uppercase">Total Tag Terbaca</span>
                                            <span class="font-extrabold text-emerald-400" x-text="extractedTags.length + ' / ' + (reportedTagCount || extractedTags.length) + ' Tag'"></span>
                                        </div>
                                        <div class="bg-slate-900/90 p-2.5 rounded-xl border border-slate-800/60">
                                            <span class="text-slate-400 block text-[10px] uppercase">Token Digunakan</span>
                                            <span class="font-bold text-cyan-400 truncate block" x-text="resultData.used_account || 'Token Utama'"></span>
                                        </div>
                                        <div class="bg-slate-900/90 p-2.5 rounded-xl border border-slate-800/60">
                                            <span class="text-slate-400 block text-[10px] uppercase">Status Ekstraksi</span>
                                            <span class="font-bold" :class="extractedTags.length >= reportedTagCount && reportedTagCount > 0 ? 'text-emerald-400' : 'text-amber-400'"
                                                x-text="extractedTags.length >= reportedTagCount && reportedTagCount > 0 ? '100% Terbuka Penuh' : 'Terbatas Kuota Server'"></span>
                                        </div>
                                    </div>

                                    <!-- BANNER SOLUSI JIKA TAG TERBATAS KARENA KUOTA 0/0 -->
                                    <template x-if="reportedTagCount > extractedTags.length">
                                        <div class="mt-4 bg-amber-500/10 border border-amber-500/30 rounded-xl p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                                            <div class="text-xs text-amber-200 space-y-0.5">
                                                <div class="font-bold text-amber-300 flex items-center gap-1.5">
                                                    <i class="fa-solid fa-unlock-keyhole"></i>
                                                    Terdeteksi <span x-text="reportedTagCount"></span> Tag di Server, namun Kuota Detail Token Anda sedang 0/0!
                                                </div>
                                                <p class="text-[11px] text-amber-200/80">
                                                    Untuk membuka seluruh <span x-text="reportedTagCount"></span> tag nomor <b x-text="resultData.hlr.local"></b> sekarang juga secara gratis, klik tombol di samping untuk memverifikasi WA nomor tersebut atau tambah token baru.
                                                </p>
                                            </div>
                                            <button @click="genPhone = resultData.hlr.local; showGenModal = true" class="px-3.5 py-2 rounded-xl bg-amber-400 hover:bg-amber-300 text-slate-950 font-extrabold text-xs shrink-0 transition shadow">
                                                <i class="fa-brands fa-whatsapp mr-1"></i> Buka <span x-text="reportedTagCount"></span> Tag via WA
                                            </button>
                                        </div>
                                    </template>
                                </div>

                                <!-- TAB 1: DAFTAR TAG -->
                                <div x-show="activeTab === 'overview'" class="space-y-4">
                                    <div class="bg-slate-950/60 border border-slate-800/90 rounded-2xl p-4 space-y-4">
                                        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                                            <div class="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                                                <i class="fa-solid fa-tags"></i>
                                                Daftar Tagname Kontak (<span x-text="filteredTags().length"></span>)
                                            </div>
                                            <div class="flex flex-wrap items-center gap-2">
                                                <input type="text" x-model="tagFilter" placeholder="Cari kata di dalam tag..."
                                                    class="w-full sm:w-48 bg-slate-900 border border-slate-800 rounded-xl px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500">
                                                <button @click="copyAllTags()" x-show="extractedTags.length > 0" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700">
                                                    <i class="fa-regular fa-copy mr-1"></i> Salin Semua
                                                </button>
                                            </div>
                                        </div>

                                        <template x-if="filteredTags().length > 0">
                                            <div class="flex flex-wrap gap-2 max-h-96 overflow-y-auto pr-1 pt-1">
                                                <template x-for="(item, idx) in filteredTags()" :key="idx">
                                                    <div class="inline-flex items-center px-3 py-1.5 rounded-xl text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 hover:border-emerald-500/40 transition">
                                                        <span class="text-slate-500 text-[10px] font-mono mr-1.5" x-text="(idx + 1) + '.'"></span>
                                                        <span class="font-semibold select-all" x-text="item.tag"></span>
                                                        <span class="ml-2 px-1.5 py-0.5 bg-emerald-500/15 text-emerald-400 rounded-md text-[10px] font-bold" x-text="'x' + item.count"></span>
                                                    </div>
                                                </template>
                                            </div>
                                        </template>
                                    </div>
                                </div>

                                <!-- TAB 2: OSINT -->
                                <div x-show="activeTab === 'osint'" x-cloak class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                    <a :href="resultData.hlr.osint_links.truecaller" target="_blank" class="p-4 rounded-xl bg-slate-950/80 hover:bg-slate-900 border border-slate-800 transition flex items-start justify-between">
                                        <div>
                                            <div class="text-xs font-bold text-blue-400"><i class="fa-solid fa-phone-volume mr-1"></i> Truecaller Web Lookup</div>
                                            <p class="text-[11px] text-slate-400 mt-1">Cek nama pemilik nomor di database Truecaller Indonesia.</p>
                                        </div>
                                        <i class="fa-solid fa-arrow-up-right-from-square text-xs text-slate-500"></i>
                                    </a>
                                    <a :href="resultData.hlr.osint_links.syncme" target="_blank" class="p-4 rounded-xl bg-slate-950/80 hover:bg-slate-900 border border-slate-800 transition flex items-start justify-between">
                                        <div>
                                            <div class="text-xs font-bold text-cyan-400"><i class="fa-solid fa-address-book mr-1"></i> Sync.ME Caller ID</div>
                                            <p class="text-[11px] text-slate-400 mt-1">Cek nama profil kontak dari database Sync.ME.</p>
                                        </div>
                                        <i class="fa-solid fa-arrow-up-right-from-square text-xs text-slate-500"></i>
                                    </a>
                                    <a :href="resultData.hlr.osint_links.tellows" target="_blank" class="p-4 rounded-xl bg-slate-950/80 hover:bg-slate-900 border border-slate-800 transition flex items-start justify-between">
                                        <div>
                                            <div class="text-xs font-bold text-amber-400"><i class="fa-solid fa-shield-virus mr-1"></i> Tellows Indonesia</div>
                                            <p class="text-[11px] text-slate-400 mt-1">Lihat laporan spam & skor keamanan nomor telepon.</p>
                                        </div>
                                        <i class="fa-solid fa-arrow-up-right-from-square text-xs text-slate-500"></i>
                                    </a>
                                    <a :href="resultData.hlr.osint_links.google_dork" target="_blank" class="p-4 rounded-xl bg-slate-950/80 hover:bg-slate-900 border border-slate-800 transition flex items-start justify-between">
                                        <div>
                                            <div class="text-xs font-bold text-emerald-400"><i class="fa-brands fa-google mr-1"></i> Google OSINT Phone Dork</div>
                                            <p class="text-[11px] text-slate-400 mt-1">Cari jejak digital nomor telepon di seluruh situs publik.</p>
                                        </div>
                                        <i class="fa-solid fa-arrow-up-right-from-square text-xs text-slate-500"></i>
                                    </a>
                                </div>

                                <!-- TAB 3: RAW JSON -->
                                <div x-show="activeTab === 'raw'" x-cloak>
                                    <div class="bg-slate-950 border border-slate-800 rounded-2xl p-4">
                                        <pre class="text-[11px] text-emerald-300 font-mono overflow-x-auto max-h-96" x-text="JSON.stringify(resultData, null, 2)"></pre>
                                    </div>
                                </div>

                            </div>
                        </template>

                    </div>

                    <div class="border-t border-slate-800/80 pt-4 mt-6 flex items-center justify-between text-[11px] text-slate-500">
                        <span>OmniContact Intelligence Nexus v3.0</span>
                        <span x-text="statusMessage"></span>
                    </div>
                </div>
            </div>

        </div>
    </main>

    <!-- MODAL 1: GENERATOR TOKEN BARU VIA WHATSAPP (FITUR DARI GTC-2.PY DI WEB) -->
    <div x-show="showGenModal" x-cloak class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-sm">
        <div @click.away="showGenModal = false" class="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div class="flex items-center justify-between border-b border-slate-800 pb-3">
                <h3 class="font-bold text-white text-sm sm:text-base flex items-center gap-2">
                    <i class="fa-brands fa-whatsapp text-emerald-400 text-lg"></i>
                    Buat Token Baru via WhatsApp (Unlock 100% Tag)
                </h3>
                <button @click="showGenModal = false" class="text-slate-400 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
            </div>

            <div class="text-xs text-slate-300 bg-slate-950/80 border border-slate-800 rounded-xl p-3.5 leading-relaxed">
                Fitur ini menjalankan protokol <b>Diffie-Hellman + VerifyKit</b> langsung dari browser Anda:
                <ul class="list-disc pl-4 mt-1 space-y-1 text-[11px] text-slate-400">
                    <li>Jika Anda memasukkan nomor istri/keluarga Anda dan mengirim chat verifikasi WA-nya, maka <b>seluruh 100% tag nomor tersebut langsung terbuka penuh tanpa terpotong kuota</b>!</li>
                    <li>Token yang dihasilkan juga otomatis menambah cadangan kuota di <b>Pool Token</b> Anda.</li>
                </ul>
            </div>

            <!-- STEP 1: INPUT NOMOR WA -->
            <div x-show="!genState.reference" class="space-y-3">
                <div>
                    <label class="block text-xs font-medium text-slate-400 mb-1">Nomor WhatsApp yang Akan Didaftarkan Tokennya</label>
                    <input type="tel" x-model="genPhone" placeholder="Contoh: 085536666320"
                        class="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm font-semibold text-white focus:outline-none focus:border-emerald-500">
                </div>
                <button @click="startGenerateToken()" :disabled="genLoading"
                    class="w-full py-3 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-extrabold text-xs sm:text-sm transition disabled:opacity-50">
                    <span x-text="genLoading ? 'Menghubungi Server Diffie-Hellman & VerifyKit...' : '1. Mulai & Dapatkan Link WhatsApp'"></span>
                </button>
            </div>

            <!-- STEP 2: KIRIM WA & VERIFIKASI -->
            <div x-show="genState.reference" class="space-y-4">
                <div class="bg-emerald-950/40 border border-emerald-500/40 rounded-xl p-4 space-y-2 text-center">
                    <div class="text-xs font-bold text-emerald-300">Langkah 1: Kirim Pesan Verifikasi WhatsApp</div>
                    <p class="text-[11px] text-slate-300">Klik tombol di bawah ini untuk membuka WhatsApp dan kirimkan kode verifikasi otomatisnya (pastikan dikirim dari nomor <b x-text="genPhone"></b>):</p>
                    <a :href="genState.deeplink" target="_blank" class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-extrabold text-xs shadow-lg">
                        <i class="fa-brands fa-whatsapp text-sm"></i> Buka WhatsApp & Kirim Kode
                    </a>
                    <div class="text-[11px] text-slate-400 pt-1">
                        Kode Teks Manual: <span class="font-mono font-bold text-white select-all" x-text="genState.code || '-'"></span>
                    </div>
                </div>

                <button @click="finishGenerateToken()" :disabled="genLoading"
                    class="w-full py-3 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-extrabold text-xs sm:text-sm transition disabled:opacity-50">
                    <span x-text="genLoading ? 'Memverifikasi Sesi...' : '2. Saya Sudah Kirim WA (Simpan Token & Buka Tag)'"></span>
                </button>

                <button @click="genState = {}" class="w-full py-1.5 text-xs text-slate-400 hover:text-white">Ulangi dari awal</button>
            </div>
        </div>
    </div>

    <!-- MODAL 2: MULTI-TOKEN POOL & PENGATURAN KREDENSIAL -->
    <div x-show="showCredModal" x-cloak class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-sm">
        <div @click.away="showCredModal = false" class="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
            <div class="flex items-center justify-between border-b border-slate-800 pb-3">
                <h3 class="font-bold text-slate-100 text-sm sm:text-base flex items-center gap-2">
                    <i class="fa-solid fa-users-gear text-cyan-400"></i>
                    Manajemen Multi-Token Pool & Kredensial Utama
                </h3>
                <button @click="showCredModal = false" class="text-slate-400 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
            </div>

            <!-- DAFTAR POOL TOKEN TERSIMPAN -->
            <div class="space-y-2">
                <div class="text-xs font-bold text-cyan-400 uppercase tracking-wider">Daftar Akun di Pool (<span x-text="accountPool.length"></span>)</div>
                <div class="space-y-2 max-h-44 overflow-y-auto pr-1">
                    <template x-for="(acc, i) in accountPool" :key="i">
                        <div class="flex items-center justify-between p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs">
                            <div class="truncate pr-2">
                                <span class="font-bold text-emerald-400" x-text="acc.label || ('Akun #' + (i+1))"></span>
                                <span class="text-slate-500 font-mono ml-2" x-text="acc.token.slice(0, 18) + '...'"></span>
                            </div>
                            <div class="flex items-center gap-1.5 shrink-0">
                                <button @click="useAccountFromPool(acc)" class="px-2.5 py-1 rounded-lg bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30 font-semibold text-[11px]">Jadikan Utama</button>
                                <button @click="removeAccountFromPool(i)" class="px-2 py-1 rounded-lg bg-rose-500/20 text-rose-300 hover:bg-rose-500/30 text-[11px]"><i class="fa-solid fa-trash"></i></button>
                            </div>
                        </div>
                    </template>
                </div>
            </div>

            <!-- FORM TAMBAH / EDIT TOKEN UTAMA -->
            <div class="space-y-3 pt-3 border-t border-slate-800">
                <div class="text-xs font-bold text-emerald-400 uppercase tracking-wider">Kredensial Aktif / Tambah Manual ke Pool</div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">Label / Nomor Pemilik Token</label>
                        <input type="text" x-model="accountLabel" placeholder="Contoh: 085895283075 (Pak Wanto)" class="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">Client Device ID</label>
                        <input type="text" x-model="deviceId" placeholder="Device ID..." class="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-200">
                    </div>
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">Token (`x-token`)</label>
                    <textarea rows="2" x-model="token" class="w-full bg-slate-950 border border-slate-800 rounded-xl p-2 text-xs font-mono text-slate-200"></textarea>
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">Final Key (64-char Hex)</label>
                    <textarea rows="2" x-model="finalKey" class="w-full bg-slate-950 border border-slate-800 rounded-xl p-2 text-xs font-mono text-slate-200"></textarea>
                </div>
            </div>

            <div class="flex justify-between gap-2 pt-3 border-t border-slate-800">
                <button @click="addCurrentToPool()" class="px-4 py-2 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/30 font-bold text-xs">
                    + Simpan ke Pool
                </button>
                <button @click="showCredModal = false" class="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs">
                    Selesai & Tutup
                </button>
            </div>
        </div>
    </div>

    <!-- MODAL 3: CAPTCHA UNBLOCK -->
    <div x-show="showCaptchaModal" x-cloak class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-sm">
        <div @click.away="showCaptchaModal = false" class="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div class="flex items-center justify-between border-b border-slate-800 pb-3">
                <h3 class="font-bold text-amber-300 text-sm"><i class="fa-solid fa-shield-halved mr-1"></i> Buka Blokir Captcha 403</h3>
                <button @click="showCaptchaModal = false" class="text-slate-400 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
            </div>
            <div class="space-y-3 text-center">
                <template x-if="captchaImage">
                    <img :src="'data:image/jpeg;base64,' + captchaImage" class="mx-auto rounded-xl border border-slate-700 max-h-36">
                </template>
                <input type="text" x-model="captchaCode" @keyup.enter="submitCaptcha()" placeholder="Ketik kode captcha..."
                    class="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-center font-bold tracking-widest text-white">
            </div>
            <div class="flex justify-end gap-2">
                <button @click="submitCaptcha()" class="px-4 py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs">Verifikasi</button>
            </div>
        </div>
    </div>

    <script>
        function nexusAppV3() {
            return {
                accountLabel: localStorage.getItem('gtc_label') || 'Akun Utama',
                token: (localStorage.getItem('gtc_token') || '').trim(),
                finalKey: (localStorage.getItem('gtc_finalKey') || '').trim(),
                deviceId: (localStorage.getItem('gtc_deviceId') || '').trim(),
                accountPool: JSON.parse(localStorage.getItem('gtc_pool') || '[]'),
                phone: '',
                genPhone: '',
                genLoading: false,
                genState: {},
                searchMode: 'deep_force',
                activeTab: 'overview',
                tagFilter: '',
                showCredModal: false,
                showGenModal: false,
                showCaptchaModal: false,
                captchaImage: null,
                captchaCode: '',
                loading: false,
                loadingQuota: false,
                resultData: null,
                extractedTags: [],
                reportedTagCount: 0,
                quotaData: null,
                statusMessage: 'Sistem Siap',
                historyList: JSON.parse(localStorage.getItem('nexus_history') || '[]'),

                init() {
                    if (this.token && this.finalKey && this.accountPool.length === 0) {
                        this.accountPool.push({
                            label: this.accountLabel,
                            token: this.token,
                            finalKey: this.finalKey,
                            deviceId: this.deviceId
                        });
                        localStorage.setItem('gtc_pool', JSON.stringify(this.accountPool));
                    }
                    this.$watch('token', v => localStorage.setItem('gtc_token', (v || '').trim()));
                    this.$watch('finalKey', v => localStorage.setItem('gtc_finalKey', (v || '').trim()));
                    this.$watch('deviceId', v => localStorage.setItem('gtc_deviceId', (v || '').trim()));
                },

                addCurrentToPool() {
                    if (!this.token || !this.finalKey) return;
                    const exists = this.accountPool.some(a => a.token === this.token.trim());
                    if (!exists) {
                        this.accountPool.push({
                            label: this.accountLabel || 'Akun Pool',
                            token: this.token.trim(),
                            finalKey: this.finalKey.trim(),
                            deviceId: this.deviceId.trim()
                        });
                        localStorage.setItem('gtc_pool', JSON.stringify(this.accountPool));
                    }
                    Swal.fire({ icon: 'success', title: 'Tersimpan di Pool', timer: 1200, showConfirmButton: false, background: '#0f172a', color: '#f8fafc' });
                },

                useAccountFromPool(acc) {
                    this.accountLabel = acc.label;
                    this.token = acc.token;
                    this.finalKey = acc.finalKey;
                    this.deviceId = acc.deviceId;
                },

                removeAccountFromPool(idx) {
                    this.accountPool.splice(idx, 1);
                    localStorage.setItem('gtc_pool', JSON.stringify(this.accountPool));
                },

                getPrimaryName() {
                    if (!this.resultData) return '-';
                    if (this.resultData.profile && this.resultData.profile.displayName) return this.resultData.profile.displayName;
                    if (this.extractedTags.length > 0) return this.extractedTags[0].tag;
                    return 'Nama Belum Terindeks';
                },

                filteredTags() {
                    if (!this.tagFilter.trim()) return this.extractedTags;
                    const q = this.tagFilter.toLowerCase();
                    return this.extractedTags.filter(t => t.tag.toLowerCase().includes(q));
                },

                async performSearch() {
                    if (!this.phone.trim()) return;
                    this.loading = true;
                    this.statusMessage = 'Mengekstrak seluruh tag...';
                    try {
                        let poolToSend = [...this.accountPool];
                        if (this.token && this.finalKey && !poolToSend.some(a => a.token === this.token)) {
                            poolToSend.unshift({ label: this.accountLabel, token: this.token, finalKey: this.finalKey, deviceId: this.deviceId });
                        }
                        const res = await fetch('/api/search', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                phone: this.phone,
                                mode: this.searchMode,
                                accounts: poolToSend
                            })
                        });
                        const data = await res.json();
                        this.resultData = data;
                        this.extractedTags = data.merged_tags || [];
                        this.reportedTagCount = (data.profile && data.profile.tagCount) ? data.profile.tagCount : this.extractedTags.length;
                        this.statusMessage = 'Pemindaian selesai';

                        let filtered = this.historyList.filter(h => h.phone !== data.hlr.local);
                        filtered.unshift({
                            phone: data.hlr.local,
                            name: this.getPrimaryName(),
                            provider: data.hlr.provider,
                            tagCount: this.extractedTags.length
                        });
                        this.historyList = filtered.slice(0, 15);
                        localStorage.setItem('nexus_history', JSON.stringify(this.historyList));
                    } catch (err) {
                        Swal.fire({ icon: 'error', title: 'Error', text: String(err), background: '#0f172a', color: '#f8fafc' });
                    } finally {
                        this.loading = false;
                    }
                },

                async startGenerateToken() {
                    if (!this.genPhone.trim()) return;
                    this.genLoading = true;
                    try {
                        const res = await fetch('/api/generate/start', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ phone: this.genPhone })
                        });
                        const data = await res.json();
                        if (res.status === 200 && data.reference) {
                            this.genState = data;
                        } else {
                            Swal.fire({ icon: 'error', title: 'Gagal Inisialisasi', text: data.error || 'Gagal menghubungi VerifyKit', background: '#0f172a', color: '#f8fafc' });
                        }
                    } catch (e) {
                        Swal.fire({ icon: 'error', title: 'Error', text: String(e), background: '#0f172a', color: '#f8fafc' });
                    } finally {
                        this.genLoading = false;
                    }
                },

                async finishGenerateToken() {
                    this.genLoading = true;
                    try {
                        const res = await fetch('/api/generate/verify', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(this.genState)
                        });
                        const data = await res.json();
                        if (res.status === 200 && data.token) {
                            const newAcc = {
                                label: data.phone,
                                token: data.token,
                                finalKey: data.finalKey,
                                deviceId: data.deviceId
                            };
                            this.accountPool.unshift(newAcc);
                            localStorage.setItem('gtc_pool', JSON.stringify(this.accountPool));
                            this.useAccountFromPool(newAcc);
                            this.showGenModal = false;
                            this.phone = data.phone;
                            this.genState = {};
                            Swal.fire({ icon: 'success', title: 'Token Berhasil Dibuat!', text: 'Memindai ulang seluruh tag nomor Anda...', timer: 1800, showConfirmButton: false, background: '#0f172a', color: '#f8fafc' });
                            this.performSearch();
                        } else {
                            Swal.fire({ icon: 'warning', title: 'Belum Terverifikasi', text: data.error || 'Pastikan pesan WhatsApp sudah terkirim (centang dua) lalu klik lagi.', background: '#0f172a', color: '#f8fafc' });
                        }
                    } catch (e) {
                        Swal.fire({ icon: 'error', title: 'Error', text: String(e), background: '#0f172a', color: '#f8fafc' });
                    } finally {
                        this.genLoading = false;
                    }
                },

                clearHistory() {
                    this.historyList = [];
                    localStorage.removeItem('nexus_history');
                },

                copyAllTags() {
                    const text = this.extractedTags.map(t => `${t.tag} (x${t.count})`).join('\\n');
                    navigator.clipboard.writeText(text);
                    Swal.fire({ icon: 'success', title: 'Disalin!', text: `${this.extractedTags.length} tag disalin.`, timer: 1300, showConfirmButton: false, background: '#0f172a', color: '#f8fafc' });
                },

                exportTagsCSV() {
                    let csv = 'No,Tag Name,Count\\n';
                    this.extractedTags.forEach((item, idx) => {
                        csv += `${idx + 1},"${item.tag.replace(/"/g, '""')}",${item.count}\\n`;
                    });
                    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
                    const link = document.createElement('a');
                    link.href = URL.createObjectURL(blob);
                    link.download = `tags-${this.resultData.hlr.local}.csv`;
                    link.click();
                },

                async fetchQuota() {
                    if (!this.token || !this.finalKey) { this.showCredModal = true; return; }
                    this.loadingQuota = true;
                    try {
                        const res = await fetch('/api/quota', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ token: this.token, finalKey: this.finalKey, deviceId: this.deviceId })
                        });
                        const data = await res.json();
                        const u = data?.result?.subscriptionInfo?.usage;
                        if (u) {
                            this.quotaData = {
                                search: `${u.search?.remainingCount ?? 0} / ${u.search?.limit ?? 0}`,
                                numberDetail: `${u.numberDetail?.remainingCount ?? 0} / ${u.numberDetail?.limit ?? 0}`,
                                rawDetail: u.numberDetail?.remainingCount ?? 0
                            };
                        }
                    } finally {
                        this.loadingQuota = false;
                    }
                },

                async openCaptchaModal() {
                    if (!this.token || !this.finalKey) { this.showCredModal = true; return; }
                    this.showCaptchaModal = true;
                    const res = await fetch('/api/captcha/refresh', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token: this.token, finalKey: this.finalKey, deviceId: this.deviceId })
                    });
                    const data = await res.json();
                    if (data?.result?.image) {
                        this.captchaImage = data.result.image;
                    } else {
                        this.showCaptchaModal = false;
                        Swal.fire({ icon: 'info', title: 'Aman', text: 'Akun tidak terkena blokir Captcha 403.', background: '#0f172a', color: '#f8fafc' });
                    }
                },

                async submitCaptcha() {
                    const res = await fetch('/api/captcha/verify', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token: this.token, finalKey: this.finalKey, deviceId: this.deviceId, code: this.captchaCode })
                    });
                    if (res.status === 200) {
                        this.showCaptchaModal = false;
                        this.captchaCode = '';
                        Swal.fire({ icon: 'success', title: 'Berhasil Dibuka!', background: '#0f172a', color: '#f8fafc' });
                    }
                }
            }
        }
    </script>
</body>
</html>
"""


# ==========================================
# FLASK ROUTES & DEEP MULTI-VECTOR PROBE
# ==========================================
@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/search", methods=["POST"])
def api_search_endpoint():
    data = request.json or {}
    phone_raw = data.get("phone", "")
    mode = data.get("mode", "deep_force")
    accounts = data.get("accounts") or []

    hlr_info = analyze_indonesian_number(phone_raw)
    e164_phone = hlr_info["e164"]
    local_phone = hlr_info["local"]

    response_payload = {
        "hlr": hlr_info,
        "profile": {},
        "merged_tags": [],
        "used_account": None,
        "gtc_raw": {}
    }

    if mode == "hlr_osint" or not accounts:
        return jsonify(response_payload), 200

    # Urutkan akun: jika ada akun di pool yang labelnya cocok dengan nomor yang dicari, prioritaskan di urutan pertama!
    def _acc_priority(acc):
        lbl = re.sub(r"[^\d]", "", str(acc.get("label", "")))
        target_digits = hlr_info["clean_digits"][-9:]
        return 0 if (target_digits and target_digits in lbl) else 1

    sorted_accounts = sorted(accounts, key=_acc_priority)
    tag_map: dict[str, int] = {}

    for idx, acc in enumerate(sorted_accounts):
        token = (acc.get("token") or "").strip()
        final_key = (acc.get("finalKey") or "").strip()
        device_id = (acc.get("deviceId") or "").strip()
        acc_label = acc.get("label") or f"Token #{idx + 1}"

        if not token or not final_key:
            continue

        # Multi-Vector Probe: 1) Search Popular Tags, 2) Number-Detail Profile, 3) Number-Detail Search Source
        probes = [
            ("search_popular", "/v2.8/search", {
                "countryCode": COUNTRY, "phoneNumber": e164_phone,
                "source": "search", "initiatedFrom": "POPULAR_TAGS", "token": token
            }),
            ("detail_profile", "/v2.8/number-detail", {
                "countryCode": COUNTRY, "phoneNumber": e164_phone,
                "source": "profile", "token": token
            }),
            ("detail_history", "/v2.8/number-detail", {
                "countryCode": COUNTRY, "phoneNumber": e164_phone,
                "source": "searchHistory", "token": token
            }),
        ]

        for probe_name, endpoint, payload in probes:
            code, body = gtc_call(endpoint, payload, token, final_key, device_id)
            response_payload["gtc_raw"][f"{acc_label}_{probe_name}"] = body

            if code == 200 and isinstance(body.get("result"), dict):
                prof = body["result"].get("profile")
                if prof and not response_payload["profile"].get("displayName"):
                    response_payload["profile"] = prof
                elif prof and prof.get("tagCount", 0) > response_payload["profile"].get("tagCount", 0):
                    response_payload["profile"] = prof

                for t in extract_tags_from_dict(body["result"]):
                    t_name = t["tag"]
                    if t_name:
                        tag_map[t_name] = max(tag_map.get(t_name, 0), t["count"])

        response_payload["used_account"] = acc_label
        reported_total = response_payload["profile"].get("tagCount", 0)

        # Jika seluruh tag sudah berhasil ditarik (jumlah tag >= tagCount server atau > 5 tag), hentikan rotasi token
        if len(tag_map) > 5 or (reported_total > 0 and len(tag_map) >= reported_total):
            break

    merged_list = [{"tag": k, "count": v} for k, v in tag_map.items()]
    merged_list.sort(key=lambda x: x["count"], reverse=True)
    response_payload["merged_tags"] = merged_list

    return jsonify(response_payload), 200


# ==========================================
# ENDPOINT WEB GENERATOR TOKEN (DARI GTC-2.PY)
# ==========================================
@app.route("/api/generate/start", methods=["POST"])
def api_generate_start():
    data = request.json or {}
    raw_phone = (data.get("phone") or "").strip()
    if not raw_phone:
        return jsonify({"error": "Nomor telepon kosong"}), 400

    e164_phone, local_phone = normalize_phone(raw_phone)
    device_id = secrets.token_hex(8)
    priv, pub = dh_keypair()

    # 1. Register Diffie-Hellman
    ts = _ts()
    reg_body = {
        "carrierCountryCode": CARRIER[0], "carrierName": CARRIER[1],
        "carrierNetworkCode": CARRIER[2], "countryCode": COUNTRY, "deepLink": None,
        "deviceName": DEVICE_NAME, "deviceType": "Android", "email": None,
        "notificationToken": "", "oldToken": None, "peerKey": pub,
        "timeZone": TIME_ZONE, "token": "",
    }
    raw = json.dumps(reg_body, ensure_ascii=False)
    r = requests.post(GTC_BASE + "/v2.8/register", data=raw, headers={
        "Content-Type": "application/json", "x-os": ANDROID_OS,
        "x-app-version": APP_VERSION, "x-client-device-id": device_id, "x-lang": LANG,
        "x-req-timestamp": ts, "x-country-code": COUNTRY, "x-encrypted": "0",
        "x-req-signature": _sig(ts, raw, HMAC_KEY),
    }, timeout=20)

    if r.status_code != 201:
        return jsonify({"error": f"Register DH gagal (HTTP {r.status_code})"}), 400

    reg = r.json()
    token = reg.get("result", {}).get("token")
    server_key = reg.get("result", {}).get("serverKey")
    if not token or not server_key:
        return jsonify({"error": "Token/ServerKey tidak ditemukan"}), 400

    final_key = dh_final_key(priv, server_key)
    base = {
        "carrierCountryCode": CARRIER[0], "carrierName": CARRIER[1],
        "carrierNetworkCode": CARRIER[2], "countryCode": COUNTRY,
        "deviceName": DEVICE_NAME, "notificationToken": "", "timeZone": TIME_ZONE,
        "token": token,
    }
    steps = [
        ("/v2.8/init-basic", base),
        ("/v2.8/ad-settings", {"source": "init", "token": token}),
        ("/v2.8/init-intro", {**base, "hasRouting": False}),
        ("/v2.8/email-code-validate/start", {
            "email": f"user{random.randint(10**7, 10**8 - 1)}@gmail.com",
            "fullName": f"User{random.randint(1000, 999999)}", "token": token
        }),
        ("/v2.8/country", {"countryCode": COUNTRY.upper(), "token": token}),
        ("/v2.8/validation-start", {"app": "verifykit", "countryCode": COUNTRY, "notificationToken": "", "token": token}),
    ]
    for ep, pl in steps:
        gtc_call(ep, pl, token, final_key, device_id)

    # 2. VerifyKit Init, Country, Start
    vfk_call("/v2.0/init", {
        "isCallPermissionGranted": True, "countryCode": "ID", "deviceName": DEVICE_NAME,
        "installedApps": '{"whatsapp":0,"telegram":0,"viber":0}',
        "outsideCountryCode": "ID", "outsidePhoneNumber": local_phone,
        "timezone": TIME_ZONE, "bundleId": BUNDLE_ID,
    }, device_id)
    vfk_call("/v2.0/country", {"countryCode": "ID", "bundleId": BUNDLE_ID}, device_id)
    code, vfk_body = vfk_call("/v2.0/start", {
        "countryCode": "ID", "mcc": CARRIER[0], "mnc": CARRIER[2],
        "phoneNumber": e164_phone, "app": "whatsapp", "bundleId": BUNDLE_ID,
    }, device_id)

    deeplink = vfk_body.get("result", {}).get("deeplink")
    reference = vfk_body.get("result", {}).get("reference")
    if not deeplink or not reference:
        return jsonify({"error": f"Gagal membuat link WhatsApp VerifyKit: {vfk_body}"}), 400

    codes = re.findall(r"\*(.*?)\*", urllib.parse.unquote(deeplink))
    verification_code = next((c for c in codes if re.fullmatch(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+", c)), "")

    gtc_call("/v2.8/validation-start", {"app": "verifykit", "countryCode": COUNTRY, "notificationToken": "", "token": token}, token, final_key, device_id)

    return jsonify({
        "phone": local_phone,
        "deviceId": device_id,
        "token": token,
        "finalKey": final_key,
        "reference": reference,
        "deeplink": deeplink,
        "code": verification_code
    }), 200


@app.route("/api/generate/verify", methods=["POST"])
def api_generate_verify():
    data = request.json or {}
    reference = data.get("reference")
    device_id = data.get("deviceId")
    token = data.get("token")
    final_key = data.get("finalKey")
    phone = data.get("phone")

    code, vfk_check = vfk_call("/v2.0/check", {"reference": reference, "bundleId": BUNDLE_ID}, device_id)
    session_id = vfk_check.get("result", {}).get("sessionId")
    if not session_id:
        return jsonify({"error": "Verifikasi WA belum terdeteksi oleh server. Pastikan pesan WA sudah terkirim (centang dua)."}), 400

    code_g, gtc_res = gtc_call("/v2.8/verifykit-result", {"sessionId": session_id, "token": token}, token, final_key, device_id)
    val_date = gtc_res.get("result", {}).get("validationDate")
    if not val_date:
        return jsonify({"error": f"Gagal memvalidasi sesi token: {gtc_res}"}), 400

    return jsonify({
        "phone": phone,
        "token": token,
        "finalKey": final_key,
        "deviceId": device_id,
        "validationDate": val_date
    }), 200


@app.route("/api/quota", methods=["POST"])
def api_quota_endpoint():
    data = request.json or {}
    code, body = gtc_call("/v2.8/subscription", {"token": data.get("token", "")}, data.get("token", ""), data.get("finalKey", ""), data.get("deviceId", ""))
    return jsonify(body), code


@app.route("/api/captcha/refresh", methods=["POST"])
def api_captcha_refresh():
    data = request.json or {}
    code, body = gtc_call("/v2.8/refresh-code", {"token": data.get("token", "")}, data.get("token", ""), data.get("finalKey", ""), data.get("deviceId", ""))
    return jsonify(body), code


@app.route("/api/captcha/verify", methods=["POST"])
def api_captcha_verify():
    data = request.json or {}
    code, body = gtc_call("/v2.8/verify-code", {"validationCode": data.get("code", ""), "token": data.get("token", "")}, data.get("token", ""), data.get("finalKey", ""), data.get("deviceId", ""))
    return jsonify(body), code


if __name__ == "__main__":
    app.run(debug=True, port=5000)
