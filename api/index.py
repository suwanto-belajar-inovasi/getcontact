from __future__ import annotations
import base64
import hashlib
import hmac
import json
import re
import time
import requests
from flask import Flask, render_template_string, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

# ==========================================
# KONFIGURASI KONSTANTA & ENKRIPSI
# ==========================================
GTC_BASE = "https://pbssrv-centralevents.com"
HMAC_KEY = "31426764382a642f3a6665497235466f3d236d5d785b722b4c657457442a495b494524324866782a2364292478587a78662d7a7b7578593f71703e2b7e365762"
ANDROID_OS = "android 9"
APP_VERSION = "8.4.0"
LANG = "en_US"
COUNTRY = "id"

# Database Prefix Operator Seluler Indonesia (HLR Lookup)
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

ID_AREA_CODES = {
    "021": "Jabodetabek (DKI Jakarta, Bogor, Depok, Tangerang, Bekasi)",
    "022": "Bandung & Cimahi (Jawa Barat)",
    "024": "Semarang & Demak (Jawa Tengah)",
    "0274": "DI Yogyakarta",
    "031": "Surabaya, Sidoarjo & Gresik (Jawa Timur)",
    "0341": "Malang & Batu (Jawa Timur)",
    "0361": "Denpasar & Badung (Bali)",
    "061": "Medan & Deli Serdang (Sumatera Utara)",
    "0711": "Palembang (Sumatera Selatan)",
    "0411": "Makassar (Sulawesi Selatan)",
}


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
    try:
        b_key = bytes.fromhex(clean_key)
        dec = Cipher(algorithms.AES(b_key), modes.ECB()).decryptor()
        decoded_bytes = base64.b64decode(data)
        out = dec.update(decoded_bytes) + dec.finalize()
        if not out:
            return ""
        pad_len = out[-1]
        unpadded = out if (pad_len > 16 or pad_len <= 0) else out[:-pad_len]
        return unpadded.decode("utf-8", errors="ignore").strip()
    except Exception as e:
        raise ValueError(f"Proses dekripsi gagal: {str(e)}")


def _ts() -> str:
    return str(int(time.time() * 1000))


def normalize_phone(raw: str) -> tuple[str, str]:
    """Mengembalikan tuple (format_E164, format_lokal_08)"""
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
    provider = "Tidak Diketahui / Internasional"
    card_type = "Reguler"
    number_category = "Seluler (Mobile)"
    region = "Nasional (Indonesia)"

    prefix4 = local_num[:4]
    prefix3 = local_num[:3]

    if prefix4 in ID_PREFIX_MAP:
        provider, card_type = ID_PREFIX_MAP[prefix4]
    elif prefix4 in ID_AREA_CODES:
        provider = "Telkom PSTN / Fixed Line"
        card_type = "Telepon Rumah / Kantor"
        number_category = "Fixed Line (PSTN)"
        region = ID_AREA_CODES[prefix4]
    elif prefix3 in ID_AREA_CODES:
        provider = "Telkom PSTN / Fixed Line"
        card_type = "Telepon Rumah / Kantor"
        number_category = "Fixed Line (PSTN)"
        region = ID_AREA_CODES[prefix3]

    clean_digits = re.sub(r"[^\d]", "", e164)
    return {
        "e164": e164,
        "local": local_num,
        "clean_digits": clean_digits,
        "provider": provider,
        "card_type": card_type,
        "category": number_category,
        "region": region,
        "is_valid_length": 10 <= len(local_num) <= 14,
        "osint_links": {
            "whatsapp": f"https://api.whatsapp.com/send?phone={clean_digits}",
            "truecaller": f"https://www.truecaller.com/search/id/{clean_digits}",
            "syncme": f"https://sync.me/search/?number={clean_digits}",
            "tellows": f"https://id.tellows.net/num/{local_num}",
            "google_dork": f"https://www.google.com/search?q=%22{local_num}%22+OR+%22{e164}%22+OR+%22{clean_digits}%22",
        }
    }


def gtc_call(endpoint: str, payload: dict, token: str, final_key: str, device_id: str) -> tuple[int, dict]:
    raw = json.dumps(payload, ensure_ascii=False)
    ts = _ts()
    clean_token = (token or "").strip()
    clean_key = (final_key or "").strip()
    clean_device = (device_id or "default_device_id").strip()

    if not clean_key or len(clean_key) < 32:
        return 400, {"meta": {"errorMessage": "Final Key tidak valid (minimal 32 karakter hex)."}}

    headers = {
        "Content-Type": "application/json",
        "x-os": ANDROID_OS,
        "x-app-version": APP_VERSION,
        "x-client-device-id": clean_device,
        "x-lang": LANG,
        "x-req-timestamp": ts,
        "x-country-code": COUNTRY,
        "x-encrypted": "1",
        "x-req-signature": _sig(ts, raw, HMAC_KEY),
    }
    if clean_token:
        headers["x-token"] = clean_token

    try:
        body = json.dumps({"data": encrypt(raw, clean_key)})
    except Exception as e:
        return 400, {"meta": {"errorMessage": f"Encryption error: {str(e)}"}}

    try:
        r = requests.post(GTC_BASE + endpoint, data=body, headers=headers, timeout=25)
        text_content = r.text.strip()
        if not text_content:
            return r.status_code, {"meta": {"errorMessage": "Server merespons dengan data kosong."}}
        parsed = r.json()
    except Exception as e:
        return 500, {"meta": {"errorMessage": f"Network/JSON error: {str(e)}"}}

    if "data" in parsed:
        try:
            decrypted_str = decrypt(parsed["data"], clean_key)
            if decrypted_str:
                parsed = json.loads(decrypted_str)
        except Exception as e:
            if r.status_code == 200:
                return 400, {"meta": {"errorMessage": f"Decryption failed: {str(e)}"}}

    return r.status_code, parsed


# ==========================================
# FRONTEND SINGLE PAGE APPLICATION (HTML)
# ==========================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="id" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
    <title>OmniContact Intelligence Nexus | Multi-Source Contact & Tag Detector</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['Plus Jakarta Sans', 'sans-serif'] }
                }
            }
        }
    </script>
    <style>
        [x-cloak] { display: none !important; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: rgba(15, 23, 42, 0.4); }
        ::-webkit-scrollbar-thumb { background: rgba(16, 185, 129, 0.4); border-radius: 9999px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(16, 185, 129, 0.8); }
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col selection:bg-emerald-500 selection:text-white antialiased" x-data="contactNexusApp()">

    <!-- NAVBAR RESPONSIF -->
    <header class="border-b border-slate-800/80 bg-slate-900/75 backdrop-blur-xl sticky top-0 z-40">
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
                        <span class="px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 rounded-full">v2.0 Pro</span>
                    </div>
                    <p class="text-[11px] sm:text-xs text-slate-400">Multi-Engine Caller ID, HLR Analyzer & Tag Lookup</p>
                </div>
            </div>

            <div class="flex items-center gap-2 sm:gap-3">
                <button @click="showCredModal = true" class="px-3 py-2 rounded-xl text-xs font-semibold bg-slate-800/90 hover:bg-slate-700 text-slate-200 border border-slate-700/80 transition flex items-center gap-2">
                    <i class="fa-solid fa-key text-emerald-400"></i>
                    <span class="hidden sm:inline">Pengaturan API & Token</span>
                    <span class="sm:hidden">Kredensial</span>
                </button>
                <button @click="openCaptchaModal()" class="px-3 py-2 rounded-xl text-xs font-semibold bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition flex items-center gap-1.5" title="Buka Blokir Captcha 403">
                    <i class="fa-solid fa-shield-halved"></i>
                    <span class="hidden md:inline">Unblock 403</span>
                </button>
            </div>
        </div>
    </header>

    <!-- MAIN CONTENT -->
    <main class="flex-grow max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 sm:py-8">
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">

            <!-- KOLOM KIRI: INPUT PENCARIAN & KUOTA (4 KOLOM DI DESKTOP) -->
            <div class="lg:col-span-4 space-y-6">

                <!-- CARD PENCARIAN UTAMA -->
                <div class="bg-slate-900/70 backdrop-blur-md border border-slate-800/90 rounded-2xl p-5 sm:p-6 shadow-xl space-y-4">
                    <div class="flex items-center justify-between">
                        <h2 class="font-bold text-slate-100 text-sm sm:text-base flex items-center gap-2">
                            <i class="fa-solid fa-magnifying-glass-chart text-emerald-400"></i>
                            Deteksi Nomor Telepon
                        </h2>
                        <span class="text-[11px] text-slate-400">ID / Global</span>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1.5">Nomor Telepon Target</label>
                        <div class="relative">
                            <span class="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-400">
                                <i class="fa-solid fa-phone text-xs"></i>
                            </span>
                            <input type="tel" x-model="phone" @keyup.enter="performSearch()" placeholder="Contoh: 081234567890"
                                class="w-full bg-slate-950/90 border border-slate-800 focus:border-emerald-500 rounded-xl pl-9 pr-9 py-3 text-sm font-medium text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 transition">
                            <button x-show="phone" @click="phone = ''" class="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500 hover:text-slate-300">
                                <i class="fa-solid fa-circle-xmark"></i>
                            </button>
                        </div>
                    </div>

                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1.5">Metode & Engine Pencarian</label>
                        <select x-model="searchMode" class="w-full bg-slate-950/90 border border-slate-800 focus:border-emerald-500 rounded-xl px-3.5 py-2.5 text-xs sm:text-sm text-slate-200 focus:outline-none">
                            <option value="combined">🔥 Smart Hybrid (HLR + Multi-API + Dual Tag Query)</option>
                            <option value="hlr_osint">🌐 Alternatif: HLR + Veriphone API + OSINT (Tanpa Token GTC)</option>
                            <option value="gtc_dual">🏷️ Deep Tag Query (Gabungan Search + Number-Detail)</option>
                        </select>
                    </div>

                    <button @click="performSearch()" :disabled="loading"
                        class="w-full bg-gradient-to-r from-emerald-500 via-teal-500 to-cyan-500 hover:from-emerald-400 hover:to-teal-400 text-slate-950 font-bold py-3 px-4 rounded-xl shadow-lg shadow-emerald-500/20 transition transform active:scale-[0.99] disabled:opacity-50 flex items-center justify-center gap-2 text-sm">
                        <template x-if="!loading">
                            <span class="flex items-center gap-2"><i class="fa-solid fa-bolt"></i> Analisis & Lacak Sekarang</span>
                        </template>
                        <template x-if="loading">
                            <span class="flex items-center gap-2"><i class="fa-solid fa-circle-notch fa-spin"></i> Sedang Memindai Data...</span>
                        </template>
                    </button>
                </div>

                <!-- CARD STATUS KUOTA AKUN -->
                <div class="bg-slate-900/70 backdrop-blur-md border border-slate-800/90 rounded-2xl p-5 shadow-xl space-y-3">
                    <div class="flex items-center justify-between">
                        <h3 class="font-bold text-slate-200 text-xs sm:text-sm flex items-center gap-2">
                            <i class="fa-solid fa-gauge-high text-cyan-400"></i>
                            Status Kuota API Token
                        </h3>
                        <button @click="fetchQuota()" class="text-xs font-semibold text-emerald-400 hover:text-emerald-300 flex items-center gap-1">
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
                                <div class="text-base font-extrabold text-cyan-400 mt-0.5" x-text="quotaData.numberDetail"></div>
                            </div>
                        </div>
                    </template>
                    <template x-if="!quotaData">
                        <p class="text-xs text-slate-500">Klik "Cek Kuota" untuk memeriksa sisa limit pencarian profil & tag akun Anda.</p>
                    </template>
                </div>

                <!-- CARD RIWAYAT PENCARIAN TERAKHIR -->
                <div class="bg-slate-900/70 backdrop-blur-md border border-slate-800/90 rounded-2xl p-5 shadow-xl space-y-3">
                    <div class="flex items-center justify-between">
                        <h3 class="font-bold text-slate-200 text-xs sm:text-sm flex items-center gap-2">
                            <i class="fa-solid fa-clock-rotate-left text-purple-400"></i>
                            Riwayat Pencarian
                        </h3>
                        <button x-show="historyList.length > 0" @click="clearHistory()" class="text-[11px] text-rose-400 hover:underline">Hapus</button>
                    </div>

                    <div class="space-y-2 max-h-52 overflow-y-auto pr-1">
                        <template x-for="item in historyList" :key="item.phone">
                            <div @click="phone = item.phone; performSearch()" class="flex items-center justify-between p-2.5 rounded-xl bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800/70 cursor-pointer transition">
                                <div class="truncate pr-2">
                                    <div class="text-xs font-bold text-slate-200 truncate" x-text="item.name || item.phone"></div>
                                    <div class="text-[11px] text-slate-400 font-mono" x-text="item.phone + ' • ' + item.provider"></div>
                                </div>
                                <span class="px-2 py-0.5 text-[10px] font-semibold bg-emerald-500/15 text-emerald-400 rounded-lg shrink-0" x-text="item.tagCount + ' tag'"></span>
                            </div>
                        </template>
                        <template x-if="historyList.length === 0">
                            <p class="text-xs text-slate-500 py-2 text-center">Belum ada riwayat pencarian.</p>
                        </template>
                    </div>
                </div>

            </div>

            <!-- KOLOM KANAN: HASIL ANALISIS MULTI-ENGINE (8 KOLOM DI DESKTOP) -->
            <div class="lg:col-span-8 space-y-6">

                <div class="bg-slate-900/70 backdrop-blur-md border border-slate-800/90 rounded-2xl p-5 sm:p-6 shadow-xl min-h-[540px] flex flex-col justify-between">
                    <div class="space-y-6">

                        <!-- HEADER HASIL & FILTER TAB -->
                        <div class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
                            <div class="flex items-center gap-2">
                                <span class="h-2.5 w-2.5 rounded-full bg-emerald-400"></span>
                                <h3 class="font-bold text-slate-100 text-sm sm:text-base">Dashboard Hasil Intelijen Nomor</h3>
                            </div>
                            <div class="flex flex-wrap items-center gap-1.5">
                                <button @click="activeTab = 'overview'" :class="activeTab === 'overview' ? 'bg-emerald-500 text-slate-950 font-bold' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'" class="px-3 py-1.5 rounded-xl text-xs transition">
                                    <i class="fa-solid fa-layer-group mr-1"></i> Ringkasan & Tag
                                </button>
                                <button @click="activeTab = 'osint'" :class="activeTab === 'osint' ? 'bg-emerald-500 text-slate-950 font-bold' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'" class="px-3 py-1.5 rounded-xl text-xs transition">
                                    <i class="fa-solid fa-globe mr-1"></i> Alternatif Lookup & OSINT
                                </button>
                                <button @click="activeTab = 'raw'" :class="activeTab === 'raw' ? 'bg-emerald-500 text-slate-950 font-bold' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'" class="px-3 py-1.5 rounded-xl text-xs transition">
                                    <i class="fa-solid fa-code mr-1"></i> Raw JSON
                                </button>
                            </div>
                        </div>

                        <!-- STATE KOSONG -->
                        <template x-if="!resultData && !loading">
                            <div class="flex flex-col items-center justify-center py-20 text-center px-4">
                                <div class="w-16 h-16 rounded-2xl bg-slate-800/80 border border-slate-700 flex items-center justify-center text-emerald-400 text-2xl mb-4 shadow-inner">
                                    <i class="fa-solid fa-address-card"></i>
                                </div>
                                <h4 class="text-base font-bold text-slate-200">Siap Melakukan Pemindaian Nomor</h4>
                                <p class="text-xs sm:text-sm text-slate-400 max-w-md mt-1">
                                    Masukkan nomor telepon pada panel di samping. Anda dapat menggunakan mode <b>Alternatif (HLR + Veriphone + OSINT)</b> tanpa akun GetContact, atau mode <b>Smart Hybrid</b>.
                                </p>
                            </div>
                        </template>

                        <!-- STATE LOADING -->
                        <template x-if="loading">
                            <div class="flex flex-col items-center justify-center py-24 text-center space-y-3">
                                <div class="w-12 h-12 border-4 border-emerald-500/30 border-t-emerald-400 rounded-full animate-spin"></div>
                                <p class="text-sm font-semibold text-slate-300">Mengumpulkan intelijen nomor dari berbagai sumber...</p>
                            </div>
                        </template>

                        <!-- HASIL PENCARIAN -->
                        <template x-if="resultData && !loading">
                            <div class="space-y-6">

                                <!-- BANNER IDENTITAS UTAMA & HLR INDONESIA -->
                                <div class="bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 border border-slate-800 rounded-2xl p-4 sm:p-5 shadow-inner">
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
                                            <a :href="resultData.hlr.osint_links.whatsapp" target="_blank" class="px-3 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold flex items-center gap-1.5 transition shadow">
                                                <i class="fa-brands fa-whatsapp text-sm"></i> Chat WA
                                            </a>
                                            <button @click="exportTagsCSV()" x-show="extractedTags.length > 0" class="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition">
                                                <i class="fa-solid fa-file-csv text-emerald-400"></i> Export CSV
                                            </button>
                                        </div>
                                    </div>

                                    <!-- GRID METADATA HLR & VERIPHONE -->
                                    <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5 mt-4 pt-4 border-t border-slate-800/80 text-xs">
                                        <div class="bg-slate-900/90 p-2.5 rounded-xl border border-slate-800/60">
                                            <span class="text-slate-400 block text-[10px] uppercase">Produk / Kartu</span>
                                            <span class="font-bold text-slate-200" x-text="resultData.hlr.card_type"></span>
                                        </div>
                                        <div class="bg-slate-900/90 p-2.5 rounded-xl border border-slate-800/60">
                                            <span class="text-slate-400 block text-[10px] uppercase">Wilayah / Area</span>
                                            <span class="font-bold text-slate-200" x-text="resultData.hlr.region"></span>
                                        </div>
                                        <div class="bg-slate-900/90 p-2.5 rounded-xl border border-slate-800/60">
                                            <span class="text-slate-400 block text-[10px] uppercase">Total Tag Terbaca</span>
                                            <span class="font-extrabold text-emerald-400" x-text="extractedTags.length + ' Tag' + (reportedTagCount > extractedTags.length ? ' (Server: ' + reportedTagCount + ')' : '')"></span>
                                        </div>
                                        <div class="bg-slate-900/90 p-2.5 rounded-xl border border-slate-800/60">
                                            <span class="text-slate-400 block text-[10px] uppercase">Veriphone Carrier Status</span>
                                            <span class="font-bold text-cyan-400" x-text="resultData.veriphone && resultData.veriphone.phone_valid ? 'Valid (' + (resultData.veriphone.carrier || 'Active') + ')' : 'Aktif (HLR Lokal)'"></span>
                                        </div>
                                    </div>
                                </div>

                                <!-- TAB 1: OVERVIEW & DAFTAR TAG -->
                                <div x-show="activeTab === 'overview'" class="space-y-4">

                                    <!-- PERINGATAN JIKA ERROR / KUOTA HABIS -->
                                    <template x-if="resultData.gtc_errors && resultData.gtc_errors.length > 0">
                                        <div class="bg-amber-950/40 border border-amber-700/60 rounded-xl p-3.5 text-amber-200 text-xs space-y-1">
                                            <div class="font-bold flex items-center gap-1.5 text-amber-300">
                                                <i class="fa-solid fa-triangle-exclamation"></i> Catatan Respons Endpoint GetContact:
                                            </div>
                                            <template x-for="err in resultData.gtc_errors">
                                                <div class="pl-5 text-[11px]" x-text="'• ' + err"></div>
                                            </template>
                                            <div class="pl-5 pt-1 text-[11px] text-amber-400/90">
                                                Tips: Jika muncul HTTP 403, klik tombol <b>Unblock 403</b> di kanan atas. Jika kuota <i>numberDetail</i> akun non-premium habis, gunakan tab <b>Alternatif Lookup & OSINT</b> di atas.
                                            </div>
                                        </div>
                                    </template>

                                    <!-- FILTER & KONTROL TAG -->
                                    <div class="bg-slate-950/60 border border-slate-800/90 rounded-2xl p-4 space-y-4">
                                        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                                            <div class="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                                                <i class="fa-solid fa-tags"></i>
                                                Daftar Tagname Kontak (<span x-text="filteredTags().length"></span>)
                                            </div>

                                            <div class="flex flex-wrap items-center gap-2">
                                                <div class="relative flex-grow sm:flex-grow-0">
                                                    <input type="text" x-model="tagFilter" placeholder="Cari kata di dalam tag..."
                                                        class="w-full sm:w-48 bg-slate-900 border border-slate-800 rounded-xl px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500">
                                                </div>
                                                <button @click="copyAllTags()" x-show="extractedTags.length > 0" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition">
                                                    <i class="fa-regular fa-copy mr-1"></i> Salin Semua
                                                </button>
                                            </div>
                                        </div>

                                        <template x-if="filteredTags().length > 0">
                                            <div class="flex flex-wrap gap-2 max-h-80 overflow-y-auto pr-1 pt-1">
                                                <template x-for="(item, idx) in filteredTags()" :key="idx">
                                                    <div class="group inline-flex items-center px-3 py-1.5 rounded-xl text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 hover:border-emerald-500/40 transition shadow-sm">
                                                        <span class="text-slate-500 text-[10px] font-mono mr-1.5" x-text="(idx + 1) + '.'"></span>
                                                        <span class="font-semibold select-all" x-text="item.tag"></span>
                                                        <span class="ml-2 px-1.5 py-0.5 bg-emerald-500/15 text-emerald-400 rounded-md text-[10px] font-bold" x-text="'x' + item.count"></span>
                                                    </div>
                                                </template>
                                            </div>
                                        </template>

                                        <template x-if="filteredTags().length === 0">
                                            <div class="text-center py-8 text-slate-500 text-xs space-y-2">
                                                <i class="fa-solid fa-folder-open text-xl text-slate-600"></i>
                                                <p>Tidak ada daftar tag detail yang dikembalikan oleh sesi token saat ini, atau nomor belum memiliki tag.</p>
                                                <button @click="activeTab = 'osint'" class="text-emerald-400 hover:underline font-semibold">
                                                    Buka Tab Alternatif Lookup (Truecaller / Sync.ME / Tellows) &rarr;
                                                </button>
                                            </div>
                                        </template>
                                    </div>
                                </div>

                                <!-- TAB 2: ALTERNATIF SELAIN GETCONTACT (OSINT & CALLER ID LAINNYA) -->
                                <div x-show="activeTab === 'osint'" x-cloak class="space-y-4">
                                    <div class="bg-slate-950/60 border border-slate-800/90 rounded-2xl p-4 sm:p-5 space-y-4">
                                        <div>
                                            <h4 class="text-sm font-bold text-white flex items-center gap-2">
                                                <i class="fa-solid fa-compass text-emerald-400"></i>
                                                Alternatif Pelacakan Identitas Kontak (Tanpa Akun Premium GetContact)
                                            </h4>
                                            <p class="text-xs text-slate-400 mt-1">
                                                Gunakan berbagai platform Caller ID global & pemindai reputasi publik di bawah ini untuk melihat nama pemilik nomor dan laporan spam dari database selain GetContact:
                                            </p>
                                        </div>

                                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                            <a :href="resultData.hlr.osint_links.truecaller" target="_blank" class="p-4 rounded-xl bg-slate-900/90 hover:bg-slate-800 border border-slate-800 hover:border-blue-500/40 transition flex items-start justify-between group">
                                                <div class="space-y-1">
                                                    <div class="text-xs font-bold text-blue-400 flex items-center gap-1.5">
                                                        <i class="fa-solid fa-phone-volume"></i> Truecaller Web Lookup
                                                    </div>
                                                    <p class="text-[11px] text-slate-400">Cek nama pemilik nomor & label bisnis langsung dari database Truecaller Indonesia.</p>
                                                </div>
                                                <i class="fa-solid fa-arrow-up-right-from-square text-xs text-slate-500 group-hover:text-blue-400"></i>
                                            </a>

                                            <a :href="resultData.hlr.osint_links.syncme" target="_blank" class="p-4 rounded-xl bg-slate-900/90 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 transition flex items-start justify-between group">
                                                <div class="space-y-1">
                                                    <div class="text-xs font-bold text-cyan-400 flex items-center gap-1.5">
                                                        <i class="fa-solid fa-address-book"></i> Sync.ME Caller ID
                                                    </div>
                                                    <p class="text-[11px] text-slate-400">Alternatif populer untuk melacak profil kontak yang tersinkronisasi dari media sosial.</p>
                                                </div>
                                                <i class="fa-solid fa-arrow-up-right-from-square text-xs text-slate-500 group-hover:text-cyan-400"></i>
                                            </a>

                                            <a :href="resultData.hlr.osint_links.tellows" target="_blank" class="p-4 rounded-xl bg-slate-900/90 hover:bg-slate-800 border border-slate-800 hover:border-amber-500/40 transition flex items-start justify-between group">
                                                <div class="space-y-1">
                                                    <div class="text-xs font-bold text-amber-400 flex items-center gap-1.5">
                                                        <i class="fa-solid fa-shield-virus"></i> Tellows Indonesia (Cek Skor Spam)
                                                    </div>
                                                    <p class="text-[11px] text-slate-400">Lihat ulasan komunitas apakah nomor ini telemarketing, pinjol, penipuan, atau aman.</p>
                                                </div>
                                                <i class="fa-solid fa-arrow-up-right-from-square text-xs text-slate-500 group-hover:text-amber-400"></i>
                                            </a>

                                            <a :href="resultData.hlr.osint_links.google_dork" target="_blank" class="p-4 rounded-xl bg-slate-900/90 hover:bg-slate-800 border border-slate-800 hover:border-emerald-500/40 transition flex items-start justify-between group">
                                                <div class="space-y-1">
                                                    <div class="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                                                        <i class="fa-brands fa-google"></i> Google OSINT Phone Dork
                                                    </div>
                                                    <p class="text-[11px] text-slate-400">Lacak jejak nomor di marketplace, forum, dokumen publik, atau pengumuman web.</p>
                                                </div>
                                                <i class="fa-solid fa-arrow-up-right-from-square text-xs text-slate-500 group-hover:text-emerald-400"></i>
                                            </a>
                                        </div>
                                    </div>
                                </div>

                                <!-- TAB 3: RAW JSON -->
                                <div x-show="activeTab === 'raw'" x-cloak>
                                    <div class="bg-slate-950 border border-slate-800 rounded-2xl p-4">
                                        <div class="flex items-center justify-between mb-2">
                                            <span class="text-xs font-bold text-slate-400 uppercase">Raw Combined Payload</span>
                                        </div>
                                        <pre class="text-[11px] text-emerald-300 font-mono overflow-x-auto max-h-96" x-text="JSON.stringify(resultData, null, 2)"></pre>
                                    </div>
                                </div>

                            </div>
                        </template>

                    </div>

                    <!-- FOOTER DALAM CARD -->
                    <div class="border-t border-slate-800/80 pt-4 mt-6 flex flex-col sm:flex-row items-center justify-between text-[11px] text-slate-500 gap-2">
                        <span>OmniContact Intelligence Nexus &bull; Responsive Multi-Device Web App</span>
                        <span x-text="statusMessage"></span>
                    </div>
                </div>

            </div>
        </div>
    </main>

    <!-- MODAL PENGATURAN KREDENSIAL & API ALTERNATIF -->
    <div x-show="showCredModal" x-cloak class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
        <div @click.away="showCredModal = false" class="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
            <div class="flex items-center justify-between border-b border-slate-800 pb-3">
                <h3 class="font-bold text-slate-100 text-sm sm:text-base flex items-center gap-2">
                    <i class="fa-solid fa-sliders text-emerald-400"></i>
                    Konfigurasi Kredensial & API Alternatif
                </h3>
                <button @click="showCredModal = false" class="text-slate-400 hover:text-white">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>

            <div class="space-y-3">
                <div class="text-xs font-bold text-emerald-400 uppercase tracking-wider">1. Kredensial GetContact (Opsional)</div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">Token (`x-token`)</label>
                    <textarea rows="2" x-model="token" placeholder="Masukkan Token GetContact..." class="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"></textarea>
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">Final Key (64-char Hex)</label>
                    <textarea rows="2" x-model="finalKey" placeholder="Masukkan Final Key..." class="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"></textarea>
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">Client Device ID</label>
                    <input type="text" x-model="deviceId" placeholder="Contoh: a1b2c3d4e5f60718" class="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500">
                </div>
            </div>

            <div class="space-y-3 pt-3 border-t border-slate-800">
                <div class="text-xs font-bold text-cyan-400 uppercase tracking-wider">2. API Alternatif: Veriphone.io (Gratis 1000 Req/Bulan)</div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">Veriphone API Key (Opsional - Daftar gratis di veriphone.io)</label>
                    <input type="text" x-model="veriphoneKey" placeholder="Masukkan API Key Veriphone jika ada..." class="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500">
                </div>
            </div>

            <div class="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button @click="showCredModal = false" class="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs transition">
                    Simpan & Tutup
                </button>
            </div>
        </div>
    </div>

    <!-- MODAL UNBLOCK CAPTCHA 403 -->
    <div x-show="showCaptchaModal" x-cloak class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
        <div @click.away="showCaptchaModal = false" class="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div class="flex items-center justify-between border-b border-slate-800 pb-3">
                <h3 class="font-bold text-amber-300 text-sm flex items-center gap-2">
                    <i class="fa-solid fa-shield-halved"></i> Verifikasi Captcha (Buka Blokir 403)
                </h3>
                <button @click="showCaptchaModal = false" class="text-slate-400 hover:text-white">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>

            <div class="space-y-3 text-center">
                <template x-if="captchaImage">
                    <img :src="'data:image/jpeg;base64,' + captchaImage" class="mx-auto rounded-xl border border-slate-700 max-h-36" alt="Captcha">
                </template>
                <template x-if="!captchaImage">
                    <p class="text-xs text-slate-400 py-4">Memuat gambar captcha dari server...</p>
                </template>

                <input type="text" x-model="captchaCode" @keyup.enter="submitCaptcha()" placeholder="Ketik kode pada gambar..."
                    class="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-center font-bold tracking-widest text-white focus:outline-none focus:border-amber-400">
            </div>

            <div class="flex justify-between gap-2 pt-2">
                <button @click="openCaptchaModal()" class="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs text-slate-300">
                    <i class="fa-solid fa-rotate mr-1"></i> Muat Ulang Gambar
                </button>
                <button @click="submitCaptcha()" class="px-4 py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs">
                    Verifikasi Kode
                </button>
            </div>
        </div>
    </div>

    <script>
        function contactNexusApp() {
            return {
                token: (localStorage.getItem('gtc_token') || '').trim(),
                finalKey: (localStorage.getItem('gtc_finalKey') || '').trim(),
                deviceId: (localStorage.getItem('gtc_deviceId') || '').trim(),
                veriphoneKey: (localStorage.getItem('alt_veriphoneKey') || '').trim(),
                phone: '',
                searchMode: 'combined',
                activeTab: 'overview',
                tagFilter: '',
                showCredModal: false,
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
                    this.$watch('token', v => localStorage.setItem('gtc_token', (v || '').trim()));
                    this.$watch('finalKey', v => localStorage.setItem('gtc_finalKey', (v || '').trim()));
                    this.$watch('deviceId', v => localStorage.setItem('gtc_deviceId', (v || '').trim()));
                    this.$watch('veriphoneKey', v => localStorage.setItem('alt_veriphoneKey', (v || '').trim()));
                },

                getPrimaryName() {
                    if (!this.resultData) return '-';
                    if (this.resultData.profile && this.resultData.profile.displayName) {
                        return this.resultData.profile.displayName;
                    }
                    if (this.extractedTags.length > 0) {
                        return this.extractedTags[0].tag;
                    }
                    return 'Nama Belum Terindeks (Gunakan Tab OSINT)';
                },

                filteredTags() {
                    if (!this.tagFilter.trim()) return this.extractedTags;
                    const q = this.tagFilter.toLowerCase();
                    return this.extractedTags.filter(t => t.tag.toLowerCase().includes(q));
                },

                parseAllTags(rawResponses) {
                    let extracted = [];
                    function scanObj(obj) {
                        if (!obj) return;
                        if (Array.isArray(obj)) {
                            obj.forEach(item => scanObj(item));
                        } else if (typeof obj === 'object') {
                            if (obj.tag && typeof obj.tag === 'string') {
                                extracted.push({ tag: obj.tag, count: Number(obj.count) || 1 });
                            } else if (obj.tagName && typeof obj.tagName === 'string') {
                                extracted.push({ tag: obj.tagName, count: Number(obj.count) || 1 });
                            }
                            Object.values(obj).forEach(val => {
                                if (typeof val === 'object' && val !== null) scanObj(val);
                            });
                        }
                    }
                    scanObj(rawResponses);

                    let map = new Map();
                    extracted.forEach(t => {
                        let name = t.tag.trim();
                        if (name) {
                            map.set(name, map.has(name) ? Math.max(map.get(name), t.count) : t.count);
                        }
                    });

                    let list = [];
                    map.forEach((count, tag) => list.push({ tag, count }));
                    list.sort((a, b) => b.count - a.count);
                    return list;
                },

                async performSearch() {
                    if (!this.phone.trim()) {
                        Swal.fire({ icon: 'warning', title: 'Nomor Kosong', text: 'Masukkan nomor telepon terlebih dahulu!', background: '#0f172a', color: '#f8fafc' });
                        return;
                    }

                    if (this.searchMode !== 'hlr_osint' && (!this.token || !this.finalKey)) {
                        Swal.fire({
                            icon: 'info',
                            title: 'Mode Tanpa Token Aktif',
                            text: 'Karena Token GetContact kosong, pencarian dialihkan otomatis ke Engine Alternatif (HLR + OSINT).',
                            background: '#0f172a', color: '#f8fafc', timer: 2500
                        });
                    }

                    this.loading = true;
                    this.statusMessage = 'Memindai nomor...';
                    try {
                        const res = await fetch('/api/search', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                phone: this.phone,
                                mode: this.searchMode,
                                token: this.token,
                                finalKey: this.finalKey,
                                deviceId: this.deviceId,
                                veriphoneKey: this.veriphoneKey
                            })
                        });
                        const data = await res.json();
                        this.resultData = data;
                        this.extractedTags = this.parseAllTags(data.gtc_raw);
                        this.reportedTagCount = (data.profile && data.profile.tagCount) ? data.profile.tagCount : this.extractedTags.length;
                        this.statusMessage = 'Pemindaian selesai';

                        // Simpan ke riwayat lokal
                        this.saveToHistory({
                            phone: data.hlr.local,
                            name: this.getPrimaryName(),
                            provider: data.hlr.provider,
                            tagCount: this.extractedTags.length || this.reportedTagCount
                        });
                    } catch (err) {
                        Swal.fire({ icon: 'error', title: 'Gagal Memproses', text: String(err), background: '#0f172a', color: '#f8fafc' });
                        this.statusMessage = 'Gagal memuat data';
                    } finally {
                        this.loading = false;
                    }
                },

                saveToHistory(entry) {
                    let filtered = this.historyList.filter(h => h.phone !== entry.phone);
                    filtered.unshift(entry);
                    this.historyList = filtered.slice(0, 15);
                    localStorage.setItem('nexus_history', JSON.stringify(this.historyList));
                },

                clearHistory() {
                    this.historyList = [];
                    localStorage.removeItem('nexus_history');
                },

                copyAllTags() {
                    const text = this.extractedTags.map(t => `${t.tag} (x${t.count})`).join('\\n');
                    navigator.clipboard.writeText(text);
                    Swal.fire({ icon: 'success', title: 'Berhasil Disalin!', text: `${this.extractedTags.length} tag disalin ke clipboard.`, timer: 1500, showConfirmButton: false, background: '#0f172a', color: '#f8fafc' });
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
                    if (!this.token || !this.finalKey) {
                        this.showCredModal = true;
                        return;
                    }
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
                                numberDetail: `${u.numberDetail?.remainingCount ?? 0} / ${u.numberDetail?.limit ?? 0}`
                            };
                        } else {
                            Swal.fire({ icon: 'error', title: 'Gagal Cek Kuota', text: data?.meta?.errorMessage || 'Token tidak valid', background: '#0f172a', color: '#f8fafc' });
                        }
                    } catch (e) {
                        Swal.fire({ icon: 'error', title: 'Error Server', text: String(e), background: '#0f172a', color: '#f8fafc' });
                    } finally {
                        this.loadingQuota = false;
                    }
                },

                async openCaptchaModal() {
                    if (!this.token || !this.finalKey) {
                        this.showCredModal = true;
                        return;
                    }
                    this.showCaptchaModal = true;
                    this.captchaImage = null;
                    const res = await fetch('/api/captcha/refresh', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token: this.token, finalKey: this.finalKey, deviceId: this.deviceId })
                    });
                    const data = await res.json();
                    if (data?.result?.image) {
                        this.captchaImage = data.result.image;
                    } else {
                        Swal.fire({ icon: 'info', title: 'Tidak Ada Captcha', text: 'Akun Anda sedang tidak terblokir captcha (403).', background: '#0f172a', color: '#f8fafc' });
                        this.showCaptchaModal = false;
                    }
                },

                async submitCaptcha() {
                    if (!this.captchaCode.trim()) return;
                    const res = await fetch('/api/captcha/verify', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            token: this.token,
                            finalKey: this.finalKey,
                            deviceId: this.deviceId,
                            code: this.captchaCode.trim()
                        })
                    });
                    const data = await res.json();
                    if (res.status === 200) {
                        Swal.fire({ icon: 'success', title: 'Captcha Terverifikasi!', text: 'Blokir 403 berhasil dibuka. Silakan cari nomor kembali.', background: '#0f172a', color: '#f8fafc' });
                        this.showCaptchaModal = false;
                        this.captchaCode = '';
                    } else {
                        Swal.fire({ icon: 'error', title: 'Kode Salah', text: 'Silakan coba kode captcha yang baru.', background: '#0f172a', color: '#f8fafc' });
                        if (data?.result?.image) this.captchaImage = data.result.image;
                    }
                }
            }
        }
    </script>
</body>
</html>
"""


# ==========================================
# FLASK API ROUTES
# ==========================================
@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/search", methods=["POST"])
def api_search_endpoint():
    data = request.json or {}
    phone_raw = data.get("phone", "")
    mode = data.get("mode", "combined")
    token = (data.get("token") or "").strip()
    final_key = (data.get("finalKey") or "").strip()
    device_id = (data.get("deviceId") or "").strip()
    veriphone_key = (data.get("veriphoneKey") or "").strip()

    # 1. Jalankan Engine HLR & OSINT Lokal (Selalu Aktif & Gratis)
    hlr_info = analyze_indonesian_number(phone_raw)
    e164_phone = hlr_info["e164"]

    response_payload = {
        "hlr": hlr_info,
        "veriphone": None,
        "profile": {},
        "gtc_raw": {},
        "gtc_errors": []
    }

    # 2. Jalankan Alternatif Veriphone API jika API Key diisi
    if veriphone_key:
        try:
            vp_res = requests.get(
                "https://api.veriphone.io/v2/verify",
                params={"phone": e164_phone, "key": veriphone_key},
                timeout=10
            )
            if vp_res.status_code == 200:
                response_payload["veriphone"] = vp_res.json()
        except Exception:
            pass

    # 3. Jalankan Dual-Endpoint GetContact jika Token diisi dan mode bukan murni HLR
    if mode in ("combined", "gtc_dual") and token and final_key:
        # Query A: /v2.8/search (Profil Utama & Popular Tags)
        payload_search = {
            "countryCode": COUNTRY,
            "phoneNumber": e164_phone,
            "source": "search",
            "initiatedFrom": "POPULAR_TAGS",
            "token": token,
        }
        code_s, body_s = gtc_call("/v2.8/search", payload_search, token, final_key, device_id)
        response_payload["gtc_raw"]["search_endpoint"] = body_s

        if code_s == 200 and isinstance(body_s.get("result"), dict):
            prof = body_s["result"].get("profile")
            if prof:
                response_payload["profile"] = prof
        else:
            err_msg = body_s.get("meta", {}).get("errorMessage") or f"HTTP {code_s} pada /v2.8/search"
            response_payload["gtc_errors"].append(err_msg)

        # Query B: /v2.8/number-detail (Daftar Lengkap Tag sebagaimana di gtc-2.py)
        payload_detail = {
            "countryCode": COUNTRY,
            "phoneNumber": e164_phone,
            "source": "profile",
            "token": token,
        }
        code_d, body_d = gtc_call("/v2.8/number-detail", payload_detail, token, final_key, device_id)
        response_payload["gtc_raw"]["number_detail_endpoint"] = body_d

        if code_d == 200 and isinstance(body_d.get("result"), dict):
            prof_d = body_d["result"].get("profile")
            if prof_d and not response_payload["profile"]:
                response_payload["profile"] = prof_d
        else:
            err_msg_d = body_d.get("meta", {}).get("errorMessage") or f"HTTP {code_d} pada /v2.8/number-detail"
            response_payload["gtc_errors"].append(err_msg_d)

    return jsonify(response_payload), 200


@app.route("/api/quota", methods=["POST"])
def api_quota_endpoint():
    data = request.json or {}
    token = data.get("token", "")
    final_key = data.get("finalKey", "")
    device_id = data.get("deviceId", "")

    code, body = gtc_call("/v2.8/subscription", {"token": token}, token, final_key, device_id)
    return jsonify(body), code


@app.route("/api/captcha/refresh", methods=["POST"])
def api_captcha_refresh():
    data = request.json or {}
    token = data.get("token", "")
    final_key = data.get("finalKey", "")
    device_id = data.get("deviceId", "")

    code, body = gtc_call("/v2.8/refresh-code", {"token": token}, token, final_key, device_id)
    return jsonify(body), code


@app.route("/api/captcha/verify", methods=["POST"])
def api_captcha_verify():
    data = request.json or {}
    token = data.get("token", "")
    final_key = data.get("finalKey", "")
    device_id = data.get("deviceId", "")
    validation_code = data.get("code", "")

    code, body = gtc_call(
        "/v2.8/verify-code",
        {"validationCode": validation_code, "token": token},
        token, final_key, device_id
    )
    return jsonify(body), code


if __name__ == "__main__":
    app.run(debug=True, port=5000)
