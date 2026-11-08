from flask import Flask, request, jsonify, make_response
import os, sys, time, threading, json, random, requests, re, codecs, base64, hmac, hashlib, string, logging
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
import concurrent.futures

urllib3.disable_warnings()

# ========== LOGGING ==========
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', stream=sys.stdout)
log = logging.getLogger("ffgen")

# ========== OWNER & ENV CONFIG ==========
OWNER_NAME = "MANNPROJECTGEN"
OWNER_WA   = "6285165918835 & 6285746054082"

KV_URL = os.environ.get("KV_REST_API_URL", "")
KV_TOKEN = os.environ.get("KV_REST_API_TOKEN", "")
HAS_KV = bool(KV_URL and KV_TOKEN)

TG_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TG_CHAT  = os.environ.get("TELEGRAM_CHAT_ID", "")
HAS_TG   = bool(TG_TOKEN and TG_CHAT)

# ========== KV & TELEGRAM HELPERS ==========
def kv_cmd(cmd_list):
    if not HAS_KV: return None
    try:
        r = requests.post(KV_URL, headers={"Authorization": f"Bearer {KV_TOKEN}"}, json=cmd_list, timeout=3)
        if r.status_code == 200: return r.json().get("result")
    except: pass
    return None

def kv_incr(key):
    if not HAS_KV: return 0
    try:
        res = kv_cmd(["INCR", key])
        return int(res) if res else 0
    except: return 0

def kv_get(key):
    if not HAS_KV: return 0
    try:
        res = kv_cmd(["GET", key])
        return int(res) if res else 0
    except: return 0

def send_telegram(text):
    if not HAS_TG: return False
    try:
        requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", json={"chat_id": TG_CHAT, "text": text}, timeout=5)
    except: pass

# ========== DEBUG BUFFER ==========
_thread_local = threading.local()
_debug_buffer = []
_debug_lock = threading.Lock()
_rl_count = 0
_rl_lock = threading.Lock()
_forbidden_count = 0
_forbidden_lock = threading.Lock()

def _bump_rl():
    global _rl_count
    with _rl_lock:
        _rl_count += 1

def _bump_forbidden():
    global _forbidden_count
    with _forbidden_lock:
        _forbidden_count += 1

def _safe(v):
    if v is None or isinstance(v, (str, int, float, bool)): return v
    if isinstance(v, (bytes, bytearray)):
        try: return v.decode("utf-8")
        except: return bytes(v).hex()
    if isinstance(v, dict): return {str(k): _safe(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)): return [_safe(x) for x in v]
    return str(v)

def _is_debug(): return bool(getattr(_thread_local, "debug_enabled", False))

def dbg(tag, **fields):
    if not _is_debug(): return
    payload = {"ts": datetime.now().isoformat()}
    payload.update({k: _safe(v) for k, v in fields.items()})
    try: line = json.dumps(payload, ensure_ascii=False)
    except: line = str(payload)
    with _debug_lock:
        _debug_buffer.append(f"[{tag}] {line}")
        if len(_debug_buffer) > 200: _debug_buffer.pop(0)

# ========== KONFIG GARENA ==========
REGION_LANG = {"ME":"ar","IND":"hi","ID":"id","VN":"vi","TH":"th","BD":"bn","PK":"ur","TW":"zh","CIS":"ru","RU":"ru","SAC":"es","BR":"pt","SG":"en","MY":"ms","PH":"en","US":"en"}
HEX_KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")

# Rute OAuth yang activo (verificado por sonda: /api/v2/oauth:register NO existe)
REGISTER_URL = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
TOKEN_URL    = "https://100067.connect.garena.com/oauth/guest/token/grant"

OPT = {'timeout': 12, 'retries': 5, 'backoff': 0.35}
RARITY_SCORE_THRESHOLD = 8
# 429 es por IP en el limitador de Garena: mas workers = mas 429. Sube por env si hace falta.
FIXED_WORKERS = int(os.environ.get("WORKERS", "10"))
TARGET_ACC_PER_SEC = float(os.environ.get("TARGET_APS", "20"))
# Reintentos del MajorRegister con dispositivo/IP nuevos antes de descartar la cuenta.
REG_ATTEMPTS = int(os.environ.get("REG_ATTEMPTS", "3"))

# ========== IP SPOOFER (POR REGION) ==========
# X-Forwarded-For solo es una sugerencia, pero loginbp la honra y valida pais.
# Por eso el pool debe corresponder a la region pedida: una IP BR con region=US
# devuelve 400 BR_IP_FORBIDDEN_REGISTER y la cuenta muere en MajorRegister.
class FastIPSpoofer:
    _PREFIX = {
        "ID":  ("36.66","36.68","36.72","36.85","36.88","36.90","110.136","110.137","114.122","114.124","180.241","180.244","202.152","103.10"),
        "IND": ("49.36","49.37","103.87","115.114","122.161","106.51"),
        "SG":  ("116.12","118.189","175.156","219.74","128.199","139.59","165.22"),
        "MY":  ("115.164","175.139","60.48","118.100","124.13","202.186"),
        "PH":  ("112.198","112.201","120.28","49.145","110.54","122.2","203.177"),
        "TH":  ("49.228","49.237","171.100","184.22","110.164","203.150","27.55"),
        "VN":  ("113.161","113.171","171.244","27.72","116.96","42.112","14.161"),
        "BD":  ("103.230","103.108","119.30","103.4","202.134","27.147"),
        "PK":  ("39.40","39.57","103.255","119.73","202.83","39.32"),
        "TW":  ("1.34","1.161","36.226","111.250","114.32","61.216"),
        "CIS": ("95.24","95.108","178.176","188.170","31.173","46.188","5.16"),
        "RU":  ("95.24","95.108","178.176","188.170","31.173","46.188","5.16"),
        "SAC": ("190.60","181.48","200.87","190.14","186.84","181.64"),
        "ME":  ("37.9","37.236","5.156","94.200","185.93","213.158"),
        "BR":  ("45.112","177.54","177.129","189.34","191.6","201.17","187.17","179.108"),
        "US":  ("3.80","3.208","4.14","20.0","34.192","52.0","54.208","104.28","172.58","173.245"),
    }
    _DEFAULT = _PREFIX["US"]
    _INDEX, _LOCK = {}, threading.Lock()

    @classmethod
    def get_ip(cls, region="US"):
        pool = cls._PREFIX.get((region or "US").upper(), cls._DEFAULT)
        with cls._LOCK:
            i = cls._INDEX.get(region, 0)
            cls._INDEX[region] = i + 1
            pref = pool[i % len(pool)]
        return f"{pref}.{random.randint(0, 255)}.{random.randint(1, 254)}"

# ========== DEVICE POOL ==========
class DevicePool:
    _devices, _index, _lock = [], 0, threading.Lock()
    DEVICE_MODELS = [
        ("Asus ASUS_I005DA", "ARMv7 VFPv3 NEON VMH | 2400 | 2", "Adreno (TM) 640"),
        ("SM-A525F", "ARMv8 VFPv4 NEON VMH | 2200 | 8", "Adreno (TM) 618"),
        ("SM-A325M", "ARMv8 VFPv4 NEON VMH | 2000 | 8", "Mali-G52"),
        ("SM-S918B", "ARMv8 VFPv4 NEON VMH | 3200 | 8", "Adreno (TM) 740"),
        ("Redmi Note 10","ARMv8 VFPv4 NEON VMH | 2200 | 8","Adreno (TM) 619"),
        ("Redmi Note 11","ARMv8 VFPv4 NEON VMH | 2400 | 8","Adreno (TM) 610"),
        ("Poco X3","ARMv8 VFPv4 NEON VMH | 2300 | 8","Adreno (TM) 618"),
        ("Poco M4 Pro","ARMv8 VFPv4 NEON VMH | 2200 | 8","Mali-G57"),
        ("Pixel 6","ARMv8 VFPv4 NEON VMH | 2800 | 8","Mali-G78"),
        ("Pixel 7 Pro","ARMv8 VFPv4 NEON VMH | 2800 | 8","Mali-G710"),
        ("OnePlus 9","ARMv8 VFPv4 NEON VMH | 2800 | 8","Adreno (TM) 660"),
        ("Infinix X6819","ARMv8 VFPv4 NEON VMH | 2400 | 8","Mali-G57"),
        ("vivo 1906","ARMv8 VFPv4 NEON VMH | 2000 | 8","Adreno (TM) 610"),
    ]
    ANDROID_VERSIONS = [
        ("Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)","9","28"),
        ("Android OS 10 / API-29 (QKQ1.200114.002)","10","29"),
        ("Android OS 11 / API-30 (RP1A.201005.001)","11","30"),
        ("Android OS 12 / API-31 (SP1A.210812.016)","12","31"),
        ("Android OS 13 / API-33 (TQ3A.230805.001)","13","33"),
        ("Android OS 14 / API-34 (UP1A.231005.007)","14","34"),
    ]
    NETWORKS = ["WIFI","4G","5G"]
    OPERATORS = ["ATM Mobils","Telkomsel","Indosat","XL Axiata","Airtel","Jio","Vodafone","Globe","Smart","Viettel","Mobifone","Claro","Vivo"]
    SDK_VER = ["4.0.38","4.0.39","4.0.40","4.0.41","4.0.42"]

    @classmethod
    def _rh(cls, n): return ''.join(random.choices("0123456789abcdef", k=n))
    @classmethod
    def _uuid(cls): return f"{cls._rh(8)}-{cls._rh(4)}-{cls._rh(4)}-{cls._rh(4)}-{cls._rh(12)}"
    @classmethod
    def _mac(cls): return "02:" + ":".join(cls._rh(2) for _ in range(5))

    @classmethod
    def init_pool(cls, count=2500):
        if cls._devices: return
        for _ in range(count):
            model, cpu, gpu = random.choice(cls.DEVICE_MODELS)
            android_full, android_ver, api = random.choice(cls.ANDROID_VERSIONS)
            dev = {
                "model": model, "brand": model.split()[0], "cpu": cpu, "gpu": gpu,
                "android_full": android_full, "android_version": android_ver, "api_level": api,
                "operator": random.choice(cls.OPERATORS), "network": random.choice(cls.NETWORKS),
                "sdk": random.choice(cls.SDK_VER), "mac": cls._mac(),
                "device_id": cls._rh(32), "android_id": cls._rh(16), "uuid": cls._uuid(),
                "imei": cls._rh(15), "fingerprint": cls._rh(40),
            }
            dev["_hdr"] = {
                "X-Device-Id": dev["device_id"], "X-Android-Id": dev["android_id"],
                "X-Device-Model": dev["model"], "X-Device-Brand": dev["brand"],
                "X-OS-Version": dev["android_version"], "X-API-Level": dev["api_level"],
                "X-SDK-Version": dev["sdk"], "X-Network-Type": dev["network"],
                "X-Operator": dev["operator"], "X-IMEI": dev["imei"],
                "X-Mac": dev["mac"], "X-Client-Uuid": dev["uuid"],
            }
            dev["_gpu_full"] = f"{gpu}|OpenGL ES 3.2"
            cls._devices.append(dev)

    @classmethod
    def get(cls):
        with cls._lock:
            dev = cls._devices[cls._index % len(cls._devices)]
            cls._index += 1
            return dev

    @classmethod
    def headers(cls, device=None):
        d = device or cls.get()
        return d.get("_hdr") or {}

DevicePool.init_pool(2500)

def get_thread_device():
    if not hasattr(_thread_local, "device"):
        _thread_local.device = DevicePool.get()
        _thread_local.dev_headers = _thread_local.device["_hdr"]
    return _thread_local.device

def get_thread_dev_headers():
    if not hasattr(_thread_local, "dev_headers"):
        _thread_local.device = DevicePool.get()
        _thread_local.dev_headers = _thread_local.device["_hdr"]
    return _thread_local.dev_headers

def reset_thread_device():
    _thread_local.device = DevicePool.get()
    _thread_local.dev_headers = _thread_local.device["_hdr"]
    s = getattr(_thread_local, "session", None)
    if s is not None: s.cookies.clear()

def get_thread_session():
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=4, max_retries=0, pool_block=False)
        s.mount("https://", adapter); s.mount("http://", adapter)
        _thread_local.session = s
    return s

def encode_f14(s):
    ks = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30, 0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37, 0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31, 0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
    return bytes(ord(c) ^ ks[i % len(ks)] for i, c in enumerate(s))

FIELD_22 = bytes.fromhex(
    "4747524501010100620200001052aa0d669c6a368f08338060d2ee0690053af84a41edcd3558556ec10f24f4"
    "6c93ac64ca41a16732c46a2cb071246a79b8929032f9e1b6f4ef331bd53cabf29b09b97349a46e9863c0314e"
    "1a0d80819fef8aabf03876b3d037db354a7ccb5c1bce96411fb3753f6f50e44c69c4ed617fa30efb8ffc0517"
    "ff2f636739be1f304d999cfd6fd48bf69454199794c3dc88f55a4bdbd66534d5a061359cdfd1fb680cd37918"
    "df9fdb3cf7d80067b0a3506c90063cf62b2ccec11e23913a2fd7c4ef091331967bb518a5ad1e551146b90821"
    "be800883abadde39d6c80a5d798611466c748f075481806c5842ce45e6bd4e3368ec08fe2ec41ceb880cd862"
    "49eb71693f79f0bccf9e590c3fae12519fe08c7a1905d0927690109e0df28574bb14847225db1a59230e6662"
    "ed7730e15ff9a6c815cb41b420edeada735a4b03e181037c37c2c850257311df2f07b0a56e759372cbd0268e"
    "3f13a292ee4373e38ab5096e0342a5e0d7fec6da2bbc265d74baadd2b24ee4f74862f82c21d6694bac53f8ce"
    "80312a30068a6276a641c19b11d0305c6fe2f531ac7de578b29f543697f5c73663e6f23aa15277b6122dcd4d"
    "4171e38f9ac0b173f39c58416a16c5c1f4a35acd065ce78f449cf538a249339e763272d458e4ed86c976591a"
    "9c066b3a37111e44091eb6b5a795249f3e5145db022a6055f2cc675936391312f688f89627845df222a91156"
    "555225be36f9714a0ba50246d0f003bda3c9c1292ab73b4f79635ddd023218eda93a302d79e023404c143965"
    "44a930b98ed54771aca7fec10d095587685b473e81a9619764fad9256529dcd6e911f4f4629612287d4ee3ec"
    "5389f6ec4ec020b0e2aac017232a9197be9e46239ce690fe5d4872b2e98e651510c971667f3aca8b59f3e9d5"
    "0e43"
)

class WAFBypass:
    @staticmethod
    def get_ua(region=None):
        dev = random.choice(DevicePool.DEVICE_MODELS)[0]
        android_full, ver, api = random.choice(DevicePool.ANDROID_VERSIONS)
        sdk = random.choice(DevicePool.SDK_VER)
        reg = (region or "US").upper()
        lang = REGION_LANG.get(reg) or random.choice(["en", "id", "ar", "hi", "vi", "th", "pt", "ru", "es", "bn", "ur", "zh"])
        return f"GarenaMSDK/{sdk}({dev};Android {ver};{lang};{reg};)"

session = requests.Session()
_IP_HEADER_KEYS = ("X-Forwarded-For", "X-Real-IP", "X-Client-IP", "CF-Connecting-IP", "True-Client-IP")

def _merge_headers(headers, device=None, rotate_ip=False, region="US"):
    if headers is None: headers = {}
    merged = dict(headers)
    dev_h = DevicePool.headers(device) if device is not None else get_thread_dev_headers()
    for k, v in dev_h.items(): merged.setdefault(k, v)
    if rotate_ip or "X-Forwarded-For" not in merged:
        ip = FastIPSpoofer.get_ip(region)
        for k in _IP_HEADER_KEYS: merged[k] = ip
        merged["Forwarded"] = f"for={ip}"
    return merged

def _retry_after(resp, attempt):
    """Espera el Retry-After del servidor si viene, si no backoff exponencial con jitter."""
    try:
        ra = resp.headers.get("Retry-After")
        if ra:
            wait = float(ra)
        else:
            wait = OPT['backoff'] * (2 ** attempt)
    except Exception:
        wait = OPT['backoff'] * (2 ** attempt)
    time.sleep(min(wait, 12.0) + random.uniform(0, 0.5))

_RETRY_STATUS = (429, 500, 502, 503, 504, 408, 403)

def _is_retryable(resp):
    if resp.status_code in _RETRY_STATUS:
        return True
    # 400 con cuerpo FORBIDDEN = rechazo por geo del X-Forwarded-For, no por payload.
    if resp.status_code == 400:
        try: body = resp.content or b""
        except Exception: body = b""
        if b"FORBIDDEN" in body:
            _bump_forbidden()
            return True
    return False

def request_retry(method, url, tag="HTTP", region="US", retries=None, **kwargs):
    sess = get_thread_session()
    limit = OPT['retries'] if retries is None else retries
    for attempt in range(limit + 1):
        try:
            kwargs.setdefault('timeout', OPT['timeout'])
            kwargs['headers'] = _merge_headers(kwargs.get('headers'), rotate_ip=(attempt > 0), region=region)
            kwargs['verify'] = False
            resp = sess.request(method, url, **kwargs)
            if _is_retryable(resp):
                if resp.status_code == 429: _bump_rl()
                if attempt < limit:
                    _retry_after(resp, attempt)
                    reset_thread_device(); sess = get_thread_session(); continue
            return resp
        except Exception:
            if attempt < limit:
                time.sleep(OPT['backoff'] * (2 ** attempt) + random.uniform(0, 0.4))
                reset_thread_device(); sess = get_thread_session(); continue
            return None
    return None

def encode_varint(n):
    if n < 0: return b''
    result = []
    while True:
        byte = n & 0x7F; n >>= 7
        if n: byte |= 0x80
        result.append(byte)
        if not n: break
    return bytes(result)

def create_proto_field(field_num, value):
    if isinstance(value, dict):
        nested = create_proto_field(field_num, value)
        return encode_varint((field_num << 3) | 2) + encode_varint(len(nested)) + nested
    elif isinstance(value, int):
        return encode_varint((field_num << 3) | 0) + encode_varint(value)
    elif isinstance(value, (str, bytes)):
        ev = value.encode() if isinstance(value, str) else value
        return encode_varint((field_num << 3) | 2) + encode_varint(len(ev)) + ev
    return b''

def build_proto(fields):
    return b''.join(create_proto_field(k, v) for k, v in fields.items())

_AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
_AES_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

def aes_encrypt(hex_data):
    data = bytes.fromhex(hex_data)
    return AES.new(_AES_KEY, AES.MODE_CBC, _AES_IV).encrypt(pad(data, AES.block_size))

def encrypt_api(plain_hex):
    plain = bytes.fromhex(plain_hex)
    return AES.new(_AES_KEY, AES.MODE_CBC, _AES_IV).encrypt(pad(plain, AES.block_size)).hex()

def create_account(region, account_name, password_prefix):
    try:
        rand_part = "".join(random.choices("0123456789ABCDEF", k=16))
        password = f"{password_prefix}_{rand_part}"
        url = REGISTER_URL
        payload = {"app_id": 100067, "client_type": 2, "password": password, "source": 2}
        body_json = json.dumps(payload, separators=(",", ":"))
        signature = hmac.new(HEX_KEY, body_json.encode("utf-8"), hashlib.sha256).hexdigest()

        dbg("Register.request", url=url, body=body_json, signature=signature)
        dev = get_thread_device()
        headers = _merge_headers({
            "User-Agent": WAFBypass.get_ua(region),
            "Connection": "Keep-Alive", "Accept": "application/json", "Accept-Encoding": "gzip",
            "Authorization": f"Signature {signature}", "Content-Type": "application/json; charset=utf-8",
            "Host": "100067.connect.garena.com",
        }, device=dev, region=region)

        resp = request_retry('POST', url, tag="Register", region=region, headers=headers, data=body_json)
        if resp and resp.status_code == 200:
            try:
                res = resp.json()
            except Exception:
                res = {}
            if "data" in res and "uid" in res["data"]:
                uid = res["data"]["uid"]
                dbg("Register.success", uid=uid)
                return get_token(str(uid), password, region, account_name, password_prefix)
            dbg("Register.badjson", text=getattr(resp, "text", ""))
            return None

        dbg("Register.fail",
            status=getattr(resp, "status_code", None),
            headers=dict(getattr(resp, "headers", {}) or {}),
            text=getattr(resp, "text", ""))
        return None
    except Exception as e:
        dbg("Register.error", raw=str(e))
        return None

def get_token(uid, password, region, account_name, password_prefix):
    try:
        url = TOKEN_URL
        dev = get_thread_device()
        headers = _merge_headers({"Content-Type": "application/x-www-form-urlencoded", "User-Agent": WAFBypass.get_ua(region)}, device=dev, region=region)
        body = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": HEX_KEY.decode(), "client_id": "100067"}

        resp = request_retry('POST', url, tag="Token", region=region, headers=headers, data=body)
        if resp and resp.status_code == 200:
            try:
                j = resp.json()
            except Exception:
                j = {}
            if 'open_id' in j:
                open_id = j['open_id']; access_token = j["access_token"]
                dbg("Token.success", open_id=open_id)

                keystream = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
                encoded = "".join(chr(ord(open_id[i]) ^ keystream[i % len(keystream)]) for i in range(len(open_id)))
                field = codecs.decode(''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in encoded), 'unicode_escape').encode('latin1')

                return major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix)

        dbg("Token.fail", status=getattr(resp, "status_code", None),
            headers=dict(getattr(resp, "headers", {}) or {}),
            text=getattr(resp, "text", ""))
        return None
    except Exception as e:
        dbg("Token.error", raw=str(e))
        return None

def _loginbp(region, path):
    r = (region or "US").upper()
    if r == "BR":
        host = "loginbp.ggpolarbear.com"        # infra BR: no acepta IP de otro pais ni region BR en host US
    elif r in ("ME", "TH"):
        host = "loginbp.common.ggbluefox.com"
    else:
        host = "loginbp.ppmainecoonghj.com"
    return f"https://{host}/{path}", host

def major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix):
    try:
        url, host = _loginbp(region, "MajorRegister")
        name = generate_random_name(account_name)
        lang = REGION_LANG.get(region.upper(), "en")
        reg_msg = {1: name, 2: access_token, 3: open_id, 5: 102000007, 6: 4, 7: 1, 13: 1, 14: encode_f14(open_id), 15: lang, 16: 2, 20: "2.132.4", 21: 1, 22: FIELD_22}
        encrypted = aes_encrypt(build_proto(reg_msg).hex())

        ok = False
        for attempt in range(REG_ATTEMPTS):
            dev = get_thread_device()
            headers = _merge_headers({
                'Host': host, 'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
                'Accept': '*/*', 'Accept-Encoding': 'deflate, gzip', 'Authorization': 'Bearer', 'X-GA': 'v1 1',
                'ReleaseVersion': "OB55", 'Content-Type': 'application/x-www-form-urlencoded', 'X-Unity-Version': '2018.4.12f1',
            }, device=dev, rotate_ip=True, region=region)

            resp = request_retry('POST', url, tag="MajorRegister", region=region, retries=2, headers=headers, data=encrypted)
            status = getattr(resp, "status_code", None)
            rtext = getattr(resp, "text", "") or ""
            dbg("MajorRegister.response", attempt=attempt, status=status, text=rtext[:300])

            if status == 200:
                ok = True
                break

            # 400/403 aqui = geo o nombre rechazado, no token invalido: vale reintentar con
            # otro dispositivo e IP de la misma region. BR_IP_FORBIDDEN_REGISTER cae aca.
            if status in (400, 403):
                reset_thread_device()
                continue
            break

        if not ok:
            # Sin MajorRegister no existe cuenta de juego: MajorLogin daria 404 y solo
            # gastaria un request. Se descarta la cuenta aqui y se reporta la causa.
            dbg("MajorRegister.abort", reason="no_200", status=getattr(resp, "status_code", None))
            return None

        login_result = major_login(uid, password, access_token, open_id, region)
        account_id = login_result.get("account_id", "N/A")
        jwt_token  = login_result.get("jwt_token", "")

        if account_id != "N/A":
            if jwt_token and region.upper() != "BR":
                try: force_region_bind(region, jwt_token)
                except: pass
            return {"uid": uid, "password": password, "name": name, "region": region, "account_id": account_id, "jwt_token": jwt_token, "device_model": dev["model"], "device_id": dev["device_id"], "created_at": datetime.now().isoformat()}
        return None
    except Exception as e:
        dbg("MajorRegister.error", raw=str(e))
        return None

def major_login(uid, password, access_token, open_id, region):
    try:
        lang = REGION_LANG.get(region.upper(), "en")
        dev  = get_thread_device()
        gpu_full, gpu, model, os_str, operator, network, device_uuid, cpu = dev["_gpu_full"], dev["gpu"], dev["model"], dev["android_full"], dev["operator"], dev["network"], dev["uuid"], dev["cpu"]
        ip_addr = FastIPSpoofer.get_ip(region)

        open_id_b = open_id.encode() if isinstance(open_id, str) else open_id
        access_token_b = access_token.encode() if isinstance(access_token, str) else access_token

        payload_dict = {
            3: datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), 4: b'free fire', 5: 1, 7: "2.132.4", 8: os_str, 9: b'Handheld',
            10: operator, 11: network, 12: 1280, 13: 720, 14: b'240', 15: cpu, 16: random.choice([5951, 6000, 6100, 5500]),
            17: gpu, 18: gpu_full, 19: f'Google|{device_uuid}', 20: ip_addr, 21: lang, 22: open_id_b, 23: b'4', 24: b'Handheld',
            25: model, 26: lang, 29: access_token_b, 30: 1, 41: operator, 42: network, 57: b'1ac4b80ecf0478a44203bf8fac6120f5',
            60: 30000, 61: 30000, 62: 2519, 63: 243, 64: 32357, 65: 34308, 66: 32357, 67: 34308, 73: 1,
            74: b'/data/app/~~iw-K-GR3srU7dLE-UxJ4bg==/com.dts.freefiremax-kbPhw3SUYautW0I_oayB_A==/lib/arm', 76: 2,
            77: b'428775ab8c8845bd341b5357ec61d15e|/data/app/~~iw-K-GR3srU7dLE-UxJ4bg==/com.dts.freefiremax-kbPhw3SUYautW0I_oayB_A==/base.apk', 78: 2, 79: 1,
            81: b'32', 83: b'2019118525', 85: 3, 86: b'OpenGLES3', 87: 4095, 88: 4, 92: random.choice([19788, 20000, 21000]),
            93: b'android_max', 94: b'KqsHT2gyPt7vUCc9SCjv2ioi3WEZSEL86ErvXB38suVVK/Z4IVt78ESl/r2S15C1pqu/j6ZmgFL7HbwoFiiVconX08ooKiisQffvEAPCo/C+Lahr',
            96: b'{"cur_rate":null,"support_etc2":true}', 97: 1, 98: 1, 99: b'4', 100: b'4', 102: b'', 104: 77149, 105: 1,
            106: b'https://dl.cdn.freefiremobile.com/live/ABHotUpdates/|https://dl-core.cdn.freefiremobile.com/live/ABHotUpdates/|6b2078db9d22dd98f8e9386a39af8462',
            107: b'c8e41b7a93f02d56e1a94c7b8203f5d1',
        }
        data = build_proto(payload_dict)
        url, host = _loginbp(region, "MajorLogin")
        headers = _merge_headers({
            'Host': host, 'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Accept': '*/*', 'Accept-Encoding': 'deflate, gzip', 'Authorization': 'Bearer', 'X-GA': 'v1 1',
            'X-Ga-Sv': '1789534056', 'ReleaseVersion': "OB55", 'Content-Type': 'application/x-www-form-urlencoded', 'X-Unity-Version': '2018.4.12f1',
        }, device=dev, rotate_ip=True, region=region)
        enc_hex = encrypt_api(data.hex())

        resp = request_retry('POST', url, tag="MajorLogin", region=region, headers=headers, data=bytes.fromhex(enc_hex))
        dbg("MajorLogin.response", status=getattr(resp, "status_code", None), text=getattr(resp, "text", "")[:300])

        if resp and resp.status_code == 200 and len(resp.text) > 10:
            jwt_start = resp.text.find("eyJ")
            if jwt_start != -1:
                jwt_token = resp.text[jwt_start:]
                second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                    try:
                        parts = jwt_token.split('.')
                        if len(parts) >= 2:
                            pp = parts[1]; padding = 4 - len(pp) % 4
                            if padding != 4: pp += '=' * padding
                            claims = json.loads(base64.urlsafe_b64decode(pp))
                            account_id = claims.get('account_id') or claims.get('external_id')
                            if account_id: return {"account_id": str(account_id), "jwt_token": jwt_token}
                    except: pass
        return {"account_id": "N/A", "jwt_token": ""}
    except Exception as e:
        dbg("MajorLogin.error", raw=str(e))
        return {"account_id": "N/A", "jwt_token": ""}

def force_region_bind(region, jwt_token):
    try:
        url, host = _loginbp(region, "ChooseRegion")
        region_code = "RU" if region.upper() == "CIS" else region.upper()
        proto_data = build_proto({1: region_code})
        encrypted = encrypt_api(proto_data.hex())
        dev = get_thread_device()
        headers = _merge_headers({
            "Host": host,
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Accept": "*/*", "Accept-Encoding": "deflate, gzip", "X-Ga-Sv": "1789534056",
            "Authorization": f"Bearer {jwt_token}", "X-Ga": "v1 1", "Releaseversion": "OB55",
            "Content-Type": "application/x-www-form-urlencoded", "X-Unity-Version": "2018.4.12f1"
        }, device=dev, rotate_ip=True, region=region)
        request_retry('POST', url, tag="ForceRegionBind", region=region, data=bytes.fromhex(encrypted), headers=headers)
    except: pass

def generate_random_name(name_prefix): return name_prefix + ''.join(random.choices(string.ascii_letters + string.digits, k=6)).upper()

def check_rarity(account_data):
    account_id = account_data.get("account_id", "")
    if not account_id or account_id == "N/A": return False, None, None, 0
    score = 0; patterns_found = []
    digits = [int(d) for d in account_id if d.isdigit()]
    if len(set(digits)) == 1 and len(digits) >= 4: score += min(len(digits)*2, 12); patterns_found.append("UNIFORM")
    if len(account_id) <= 8 and account_id.isdigit(): score += 5; patterns_found.append("LOW_ID")
    if account_id.isdigit() and len(account_id) > 0: score += 2; patterns_found.append("CLEAN_DIGIT")
    if len(account_id) >= 3 and account_id == account_id[::-1]: score += 6; patterns_found.append("PALINDROME")

    if score >= RARITY_SCORE_THRESHOLD:
        rtype = "LEGENDARY" if score >= 20 else "MYTHIC" if score >= 16 else "EPIC" if score >= 12 else "RARE"
        return True, rtype, ",".join(patterns_found[:10]), score
    return False, None, None, score

def generate_single_account(region, name_prefix, password_prefix, api_name):
    reset_thread_device()
    account_result = create_account(region, name_prefix, password_prefix)

    if account_result and account_result.get("account_id", "N/A") != "N/A":
        is_rare, rtype, reason, rscore = check_rarity(account_result)
        account_result["rarity"] = rtype if is_rare else "NORMAL"
        account_result["rarity_score"] = rscore if is_rare else 0
        account_result["patterns"] = reason.split(",") if is_rare else []

        total = kv_incr("total")
        kv_incr(f"api:{api_name}")
        kv_incr(f"region:{region}")
        kv_incr(f"date:{datetime.now().strftime('%Y-%m-%d')}")

        if total > 0 and total % 100 == 0:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            text = (f"MANN-PROJECTGEN MILESTONE\n\n"
                    f"Total Gen: {total}\n"
                    f"API: {api_name.upper()}\n"
                    f"Region: {region.upper()}\n"
                    f"Waktu: {now}\n\n"
                    f"Status: ONLINE\n"
                    f"Engine: Garena Direct OB55")
            send_telegram(text)

        return account_result
    return None

# ========== FLASK APP & ROUTES ==========
app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,OPTIONS')
    return response

def _process_request(api_name):
    global _rl_count, _forbidden_count
    if request.method == 'OPTIONS': return make_response('', 200)
    count = request.args.get('count', default=1, type=int)
    name = request.args.get('name', default='MANN', type=str)
    password = request.args.get('password', default='Pass', type=str)
    region = request.args.get('region', default='ID', type=str).upper()
    debug = request.args.get('debug', default=0, type=int) == 1

    if count < 1 or count > 2000: return jsonify({"error": "count must be between 1 and 2000"}), 400
    if region not in REGION_LANG: return jsonify({"error": f"invalid region, allowed: {list(REGION_LANG.keys())}"}), 400

    _thread_local.debug_enabled = debug
    with _rl_lock: _rl_count = 0
    with _forbidden_lock: _forbidden_count = 0

    max_workers = min(FIXED_WORKERS, count)
    deadline = time.time() + max((count / TARGET_ACC_PER_SEC) * 3, 45)
    max_attempts = count * 6

    accounts, attempts = [], 0
    lock, stop_flag, done_event = threading.Lock(), threading.Event(), threading.Event()

    def worker():
        nonlocal attempts
        _thread_local.debug_enabled = debug
        while not stop_flag.is_set():
            with lock:
                if len(accounts) >= count or attempts >= max_attempts or time.time() > deadline:
                    stop_flag.set(); done_event.set(); return
                attempts += 1
            try: acc = generate_single_account(region, name, password, api_name)
            except: acc = None
            if acc:
                with lock:
                    if len(accounts) < count:
                        accounts.append(acc)
                        if len(accounts) >= count: stop_flag.set(); done_event.set()

    t_start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for _ in range(max_workers): ex.submit(worker)
        done_event.wait(timeout=deadline - t_start + 15)
        stop_flag.set()
    elapsed = time.time() - t_start

    with _rl_lock: rl = _rl_count
    with _forbidden_lock: fb = _forbidden_count

    res_data = {
        "success": len(accounts) > 0,
        "total_requested": count, "total_created": len(accounts),
        "accounts": accounts, "attempts_made": attempts, "workers": max_workers,
        "rate_limited": rl, "ip_forbidden": fb,
        "elapsed_seconds": round(elapsed, 2), "debug": debug,
    }
    if debug:
        with _debug_lock: res_data["debug_logs"] = _debug_buffer[-50:]
    return jsonify(res_data)

@app.route('/', methods=['GET'])
@app.route('/api', methods=['GET'])
def index():
    text = f"""
==================================================
  MANN-PROJECTGEN API - v1.2 (OB55)
==================================================
Owner      : {OWNER_NAME}
WhatsApp   : {OWNER_WA}
Status     : ONLINE
KV Active  : {"YES" if HAS_KV else "NO"}
Telegram   : {"YES" if HAS_TG else "NO"}
Workers    : {FIXED_WORKERS}
IP Spoof   : POR REGION (coherente con region=)
Reg Attempts: {REG_ATTEMPTS}

[ ENDPOINT GENERATE ]
- /api/v1/gen        : Generate Akun (Utama)
- /api/v1/gen/batch  : Generate Banyak (Alias)
- /api/v2/gen        : Generate Akun (Cadangan 1)
- /api/v3/gen        : Generate Akun (Cadangan 2)
- /gen               : Generate Akun (Legacy)

[ ENDPOINT INFO & STATS ]
- /api/status        : Status API
- /api/health        : Health Check
- /api/stats         : Statistik Akun (KV)
- /api/info          : Metadata API
- /api/regions       : Daftar Region
- /api/v1/status     : Status API v1
- /api/v1/stats      : Statistik Akun v1
- /api/v1/info       : Metadata v1

[ PARAMETER ]
- region   : ID, SG, ME, IND, BR, TH, VN, PK, BD, TW, RU, SAC, US, CIS
- name     : Custom nama (opsional)
- password : Custom password (opsional)
- count    : Jumlah akun (1-2000, untuk batch)
- debug    : 1 untuk melihat log error

[ CARA PAKAI ]
GET /api/v1/gen?region=ID
GET /api/v1/gen?region=ID&count=5

[ CATATAN ]
ip_forbidden > 0 = Garena rechazo la geo del X-Forwarded-For.
region=BR usa loginbp.ggpolarbear.com y no aplica ChooseRegion.
==================================================
"""
    return make_response(text, 200, {'Content-Type': 'text/plain; charset=utf-8'})

@app.route('/api/status', methods=['GET'])
@app.route('/api/v1/status', methods=['GET'])
def status():
    return jsonify({"status": "online", "owner": OWNER_NAME, "version": "v1.2", "engine": "OB55", "workers": FIXED_WORKERS, "reg_attempts": REG_ATTEMPTS, "ip_mode": "region", "kv": HAS_KV, "telegram": HAS_TG})

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/api/info', methods=['GET'])
@app.route('/api/v1/info', methods=['GET'])
def info():
    return jsonify({"name": "MANN-PROJECTGEN API", "owner": OWNER_NAME, "whatsapp": OWNER_WA, "regions": list(REGION_LANG.keys()), "version": "v1.2"})

@app.route('/api/stats', methods=['GET'])
@app.route('/api/v1/stats', methods=['GET'])
def stats():
    return jsonify({
        "total_all_time": kv_get("total"),
        "today": kv_get(f"date:{datetime.now().strftime('%Y-%m-%d')}"),
        "api_v1": kv_get("api:v1"), "api_v2": kv_get("api:v2"), "api_v3": kv_get("api:v3"),
        "kv_active": HAS_KV
    })

@app.route('/api/regions', methods=['GET'])
def regions():
    return jsonify({"regions": list(REGION_LANG.keys())})

@app.route('/api/v1/gen', methods=['GET', 'OPTIONS'])
@app.route('/api/v1/gen/batch', methods=['GET', 'OPTIONS'])
def gen_v1(): return _process_request("v1")

@app.route('/api/v2/gen', methods=['GET', 'OPTIONS'])
def gen_v2(): return _process_request("v2")

@app.route('/api/v3/gen', methods=['GET', 'OPTIONS'])
@app.route('/gen', methods=['GET', 'OPTIONS'])
def gen_v3(): return _process_request("v3")

def application(environ, start_response): return app(environ, start_response)

if __name__ == "__main__":
    app.run(debug=False, threaded=True, host='0.0.0.0', port=3000)
