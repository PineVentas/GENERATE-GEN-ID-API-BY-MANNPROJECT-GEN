#!/usr/bin/env python3
"""Genera cuentas Free Fire por region. Salida: accounts_<region>.txt (uid|pass|name|account_id).

Variables de entorno:
  REGION      US | SAC | BR        (default US)
  LOCK_FIELD  campo protobuf de lock_region en MajorRegister (default 4) -> hay que probarlo
  PROXY       http://user:pass@ip:puerto para salir por IP de la region (opcional)
  COUNT, NAME_PREFIX, WORKERS, OUT_FILE
  HOST_US / HOST_SAC / HOST_BR   override de host
"""
import os, sys, json, time, random, string, hmac, hashlib, codecs, base64, threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import requests, urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

urllib3.disable_warnings()

COUNT   = int(os.environ.get("COUNT", "30"))
PREFIX  = os.environ.get("NAME_PREFIX", "PIP")
WORKERS = max(1, int(os.environ.get("WORKERS", "2")))

REGION = os.environ.get("REGION", "US").upper()
if REGION not in ("US", "SAC", "BR"):
    print(f"REGION invalida: {REGION} (usa US, SAC o BR)"); sys.exit(2)
LANG = {"US": "en", "SAC": "es", "BR": "pt"}.get(REGION, "en")

OUT = os.environ.get("OUT_FILE", f"accounts_{REGION.lower()}.txt")

HOSTS = {
    "US":  os.environ.get("HOST_US",  "login.us.freefiremobile.com"),
    "SAC": os.environ.get("HOST_SAC", "loginbp.ppmainecoonghj.com"),
    "BR":  os.environ.get("HOST_BR",  "loginbp.ppmainecoonghj.com"),
}
HOST = HOSTS[REGION]

LOCK_FIELD = int(os.environ.get("LOCK_FIELD", "4"))
VERBOSE    = bool(os.environ.get("VERBOSE"))

PROXY   = os.environ.get("PROXY") or None
PROXIES = {"http": PROXY, "https": PROXY} if PROXY else None

UA = f"GarenaMSDK/4.0.42(SM-A525F;Android 12;{LANG};{REGION};)"
KEY  = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")
SECRET = KEY.decode()

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
    "0e43")

AK  = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
KS  = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
       0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]

# X-Forwarded-For NO fija la region: Garena la resuelve por la conexion TCP.
# Se mantiene solo como coherencia. Para forzar de verdad: lock_region + host + PROXY.
US_PREFIX = ("3.80","3.208","4.14","20.0","34.192","52.0","54.208","104.28","172.58","173.245")
_IPI, _IPL = 0, threading.Lock()

def next_ip():
    global _IPI
    with _IPL:
        p = US_PREFIX[_IPI % len(US_PREFIX)]
        _IPI += 1
    return f"{p}.{random.randint(0,255)}.{random.randint(1,254)}"

def hdr(ip, **kw):
    h = {"User-Agent": UA, "Accept": "application/json"}
    for k in ("X-Forwarded-For","X-Real-IP","X-Client-IP","CF-Connecting-IP","True-Client-IP"):
        h[k] = ip
    h["Forwarded"] = f"for={ip}"
    h.update(kw)
    return h

def enc(hexdata):
    return AES.new(AK, AES.MODE_CBC, IV).encrypt(pad(bytes.fromhex(hexdata), 16)).hex()

def varint(n):
    o = []
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        o.append(b)
        if not n: break
    return bytes(o)

def fld(k, v):
    if isinstance(v, int): return varint((k << 3) | 0) + varint(v)
    b = v.encode() if isinstance(v, str) else v
    return varint((k << 3) | 2) + varint(len(b)) + b

def proto(d): return b"".join(fld(k, v) for k, v in d.items())
def f14(s): return bytes(ord(c) ^ KS[i % len(KS)] for i, c in enumerate(s))
def rh(n): return "".join(random.choices("0123456789abcdef", k=n))

def region_of(token):
    try:
        pp = token.split(".")[1]; pp += "=" * (-len(pp) % 4)
        return (json.loads(base64.urlsafe_b64decode(pp)).get("lock_region") or "").upper()
    except Exception:
        return None

STATS = {"attempts": 0, "ok": 0, "err_429": 0, "err_forbidden": 0, "err_region": 0, "err_other": 0}
SLOCK = threading.Lock()
RESULTS = []
STOP = threading.Event()

def bump(k):
    with SLOCK: STATS[k] += 1

def post(url, ip, retries=3, **kw):
    """POST con reintentos. Rota IP y rota proxy en 429 / FORBIDDEN / 5xx."""
    last = None
    for a in range(retries + 1):
        try:
            kw.setdefault("timeout", 15)
            kw["verify"] = False
            r = requests.post(url, headers=kw.pop("headers", hdr(ip)), proxies=PROXIES, **kw)
            last = r
            if r.status_code == 429:
                bump("err_429"); time.sleep(2.0 * (a + 1) + random.uniform(0, 1.5))
                ip = next_ip(); kw["headers"] = hdr(ip); continue
            if r.status_code == 400 and b"FORBIDDEN" in (r.content or b""):
                bump("err_forbidden"); ip = next_ip(); kw["headers"] = hdr(ip); continue
            if r.status_code in (500, 502, 503, 504, 408):
                time.sleep(1.0 * (a + 1)); ip = next_ip(); kw["headers"] = hdr(ip); continue
            return r
        except Exception:
            time.sleep(1.0 * (a + 1)); ip = next_ip(); kw["headers"] = hdr(ip)
    return last

def make_one():
    ip = next_ip()
    try:
        # 1. registro guest (global, independiente de region)
        pw = "Pass_" + "".join(random.choices("0123456789ABCDEF", k=16))
        body = json.dumps({"app_id":100067,"client_type":2,"password":pw,"source":2}, separators=(",",":"))
        sig = hmac.new(KEY, body.encode(), hashlib.sha256).hexdigest()
        r = post("https://100067.connect.garena.com/api/v2/oauth/guest:register", ip,
                 headers=hdr(ip, **{"Content-Type":"application/json; charset=utf-8","Authorization":f"Signature {sig}"}),
                 data=body)
        if not r or r.status_code != 200: bump("err_other"); return None
        uid = str(r.json()["data"]["uid"])

        # 2. token guest
        r = post("https://100067.connect.garena.com/oauth/guest/token/grant", ip,
                 headers=hdr(ip, **{"Content-Type":"application/x-www-form-urlencoded"}),
                 data={"uid":uid,"password":pw,"response_type":"token","client_type":"2",
                       "client_secret":SECRET,"client_id":"100067"})
        if not r or r.status_code != 200: bump("err_other"); return None
        j = r.json(); open_id, at = j["open_id"], j["access_token"]

        # 3. ChooseRegion ANTES de crear la cuenta, con el token guest
        post(f"https://{HOST}/ChooseRegion", ip,
             headers={"Host":HOST,"User-Agent":"UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
                      "Accept":"*/*","Authorization":f"Bearer {at}","X-GA":"v1 1","X-Ga-Sv":"1789534056",
                      "Releaseversion":"OB55","Content-Type":"application/x-www-form-urlencoded",
                      "X-Unity-Version":"2018.4.12f1","X-Forwarded-For":ip},
             data=bytes.fromhex(enc(proto({1:REGION}).hex())), retries=2)

        # 4. MajorRegister (crea la cuenta) — aqui se fija lock_region
        name = PREFIX + rh(6).upper()
        msg = {1:name,2:at,3:open_id,5:102000007,6:4,7:1,13:1,14:f14(open_id),15:LANG,16:2,20:"2.132.4",21:1,22:FIELD_22}
        msg[LOCK_FIELD] = REGION
        r = post(f"https://{HOST}/MajorRegister", ip,
                 headers={"Host":HOST,"User-Agent":"UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
                          "Accept":"*/*","Accept-Encoding":"deflate, gzip","Authorization":"Bearer","X-GA":"v1 1",
                          "ReleaseVersion":"OB55","Content-Type":"application/x-www-form-urlencoded",
                          "X-Unity-Version":"2018.4.12f1","X-Forwarded-For":ip},
                 data=bytes.fromhex(enc(proto(msg).hex())))
        if not r or r.status_code != 200: bump("err_other"); return None

        # 5. MajorLogin (obtiene account_id y el JWT con lock_region)
        lp = {3:datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),4:b"free fire",5:1,7:"2.132.4",
              8:"Android OS 12 / API-31 (SP1A.210812.016)",9:b"Handheld",10:"ATM Mobils",11:"WIFI",
              12:1280,13:720,14:b"240",15:"ARMv8 VFPv4 NEON VMH | 2200 | 8",16:6000,17:"Adreno (TM) 618",
              18:"Adreno (TM) 618|OpenGL ES 3.2",19:f"Google|{rh(8)}-{rh(4)}-{rh(4)}-{rh(4)}-{rh(12)}",
              20:ip,21:LANG,22:open_id,23:b"4",24:b"Handheld",25:"SM-A525F",26:LANG,29:at,30:1,
              41:"ATM Mobils",42:"WIFI",57:b"1ac4b80ecf0478a44203bf8fac6120f5",60:30000,61:30000,62:2519,
              63:243,64:32357,65:34308,66:32357,67:34308,73:1,
              74:b"/data/app/~~iw-K-GR3srU7dLE-UxJ4bg==/com.dts.freefiremax-kbPhw3SUYautW0I_oayB_A==/lib/arm",76:2,
              77:b"428775ab8c8845bd341b5357ec61d15e|/data/app/~~iw-K-GR3srU7dLE-UxJ4bg==/com.dts.freefiremax-kbPhw3SUYautW0I_oayB_A==/base.apk",78:2,79:1,
              81:b"32",83:b"2019118525",85:3,86:b"OpenGLES3",87:4095,88:4,92:19788,93:b"android_max",
              94:b"KqsHT2gyPt7vUCc9SCjv2ioi3WEZSEL86ErvXB38suVVK/Z4IVt78ESl/r2S15C1pqu/j6ZmgFL7HbwoFiiVconX08ooKiisQffvEAPCo/C+Lahr",
              96:b'{"cur_rate":null,"support_etc2":true}',97:1,98:1,99:b"4",100:b"4",102:b"",104:77149,105:1,
              106:b"https://dl.cdn.freefiremobile.com/live/ABHotUpdates/|https://dl-core.cdn.freefiremobile.com/live/ABHotUpdates/|6b2078db9d22dd98f8e9386a39af8462",
              107:b"c8e41b7a93f02d56e1a94c7b8203f5d1"}
        r = post(f"https://{HOST}/MajorLogin", ip,
                 headers={"Host":HOST,"User-Agent":"UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
                          "Accept":"*/*","Accept-Encoding":"deflate, gzip","Authorization":"Bearer","X-GA":"v1 1",
                          "X-Ga-Sv":"1789534056","ReleaseVersion":"OB55","Content-Type":"application/x-www-form-urlencoded",
                          "X-Unity-Version":"2018.4.12f1","X-Forwarded-For":ip},
                 data=bytes.fromhex(enc(proto(lp).hex())))
        if not r or r.status_code != 200: bump("err_other"); return None

        tok = r.text[r.text.find("eyJ"):]
        second = tok.find(".", tok.find(".") + 1)
        if second == -1: bump("err_other"); return None
        tok = tok[:second + 44]

        claims = {}
        try:
            pp = tok.split(".")[1]; pp += "=" * (-len(pp) % 4)
            claims = json.loads(base64.urlsafe_b64decode(pp))
        except Exception:
            pass
        acc_id = claims.get("account_id") or claims.get("external_id")
        if not acc_id: bump("err_other"); return None

        # 6. GATE: la region del JWT tiene que ser la pedida
        real = region_of(tok)
        if real != REGION:
            bump("err_region")
            if VERBOSE:
                print(f"  descartada region={real or '?'} (pedida {REGION})", flush=True)
            return None

        bump("ok")
        return {"uid": uid, "password": pw, "name": name, "account_id": str(acc_id), "region": real}
    except Exception:
        bump("err_other")
        return None

def worker():
    while not STOP.is_set():
        with SLOCK:
            if STATS["ok"] >= COUNT: STOP.set(); return
            STATS["attempts"] += 1
        acc = make_one()
        if acc:
            with SLOCK:
                RESULTS.append(acc)
                n = len(RESULTS)
            print(f"[{n:02d}] {acc['uid']} | {acc['password']} | {acc['name']} | {acc['account_id']} | {acc['region']}", flush=True)
            with open(OUT, "a", encoding="utf-8") as f:
                f.write(f"{acc['uid']}|{acc['password']}|{acc['name']}|{acc['account_id']}\n")
            if n >= COUNT: STOP.set(); return
        time.sleep(random.uniform(0.6, 1.4))

def main():
    open(OUT, "w").close()
    print(f"region={REGION} host={HOST} lang={LANG} lock_field={LOCK_FIELD}")
    print(f"proxy={'si' if PROXY else 'no'} objetivo={COUNT} prefijo={PREFIX} workers={WORKERS}\n")
    if LOCK_FIELD in (1,2,3,5,6,7,13,14,15,16,20,21,22):
        print(f"AVISO: LOCK_FIELD={LOCK_FIELD} colisiona con un campo ya usado en MajorRegister\n")

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for _ in range(WORKERS): ex.submit(worker)
        while not STOP.is_set():
            time.sleep(0.5)
            with SLOCK:
                if STATS["attempts"] >= max(COUNT * 12, 40): STOP.set()

    with SLOCK: s = dict(STATS)
    print(f"\n=== {len(RESULTS)}/{COUNT} cuentas en {time.time()-t0:.0f}s "
          f"| intentos={s['attempts']} 429={s['err_429']} forbidden={s['err_forbidden']} "
          f"region_mala={s['err_region']} otros={s['err_other']}")
    print(f"archivo: {OUT}")
    if len(RESULTS) < COUNT: sys.exit(1)

if __name__ == "__main__":
    main()
