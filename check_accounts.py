#!/usr/bin/env python3
"""Valida cuentas: token/grant + MajorLogin. Escribe alive.txt con los JWT buenos."""
import json, sys, time, hmac, hashlib, base64, random, os
import requests, urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

urllib3.disable_warnings()

IN   = os.environ.get("IN_FILE", "accounts.txt")
ALIVE, DEAD = "alive.txt", "dead.txt"
HOST = "loginbp.ppmainecoonghj.com"
SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
UA = "GarenaMSDK/4.0.44(SM-G998B ;Android 9;en;US;app 1.132.1 2019121229;)"
US_PREFIX = ("3.80","3.208","4.14","20.0","34.192","52.0","54.208","104.28","172.58","173.245")
_i = 0

def next_ip():
    global _i
    p = US_PREFIX[_i % len(US_PREFIX)]; _i += 1
    return f"{p}.{random.randint(0,255)}.{random.randint(1,254)}"

AK = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
IV = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

def enc(h): return AES.new(AK, AES.MODE_CBC, IV).encrypt(pad(bytes.fromhex(h), 16)).hex()
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
def rh(n): return "".join(random.choices("0123456789abcdef", k=n))

def hdr(ip, **kw):
    h = {"User-Agent": UA, "Accept": "*/*"}
    for k in ("X-Forwarded-For","X-Real-IP","X-Client-IP","CF-Connecting-IP","True-Client-IP"): h[k] = ip
    h.update(kw); return h

def post(url, ip, retries=3, **kw):
    for a in range(retries + 1):
        try:
            kw.setdefault("timeout", 20); kw["verify"] = False
            r = requests.post(url, **kw)
            if r.status_code in (429, 500, 502, 503, 504):
                time.sleep(1.5 * (a + 1)); ip = next_ip(); kw["headers"] = hdr(ip); continue
            return r
        except Exception:
            time.sleep(1.0 * (a + 1)); ip = next_ip(); kw["headers"] = hdr(ip)
    return None

def check(uid, pw, name, acc):
    ip = next_ip()
    r = post("https://100067.connect.garena.com/oauth/guest/token/grant", ip,
             headers=hdr(ip, **{"Content-Type": "application/x-www-form-urlencoded"}),
             data={"uid":uid,"password":pw,"response_type":"token","client_type":"2",
                   "client_secret":SECRET,"client_id":"100067"})
    if not r or r.status_code != 200:
        return "NO_TOKEN", None, None
    j = r.json(); open_id, at = j["open_id"], j["access_token"]

    lp = {3:time.strftime("%Y-%m-%d %H:%M:%S"),4:b"free fire",5:1,7:"2.132.4",
          8:"Android OS 12 / API-31 (SP1A.210812.016)",9:b"Handheld",10:"ATM Mobils",11:"WIFI",
          12:1280,13:720,14:b"240",15:"ARMv8 VFPv4 NEON VMH | 2200 | 8",16:6000,17:"Adreno (TM) 618",
          18:"Adreno (TM) 618|OpenGL ES 3.2",19:f"Google|{rh(8)}-{rh(4)}-{rh(4)}-{rh(4)}-{rh(12)}",
          20:ip,21:"en",22:open_id,23:b"4",24:b"Handheld",25:"SM-A525F",26:"en",29:at,30:1,
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
             headers=hdr(ip, **{"Host":HOST,"Authorization":"Bearer","X-GA":"v1 1","X-Ga-Sv":"1789534056",
                                "ReleaseVersion":"OB55","Content-Type":"application/x-www-form-urlencoded",
                                "X-Unity-Version":"2018.4.12f1"}),
             data=bytes.fromhex(enc(proto(lp).hex())))

    if not r or r.status_code != 200:
        return f"HTTP_{getattr(r,'status_code','ERR')}", None, None
    txt = r.text
    if "eyJ" not in txt:
        return "BANEADA_O_SIN_TOKEN", None, None

    tok = txt[txt.find("eyJ"):]
    d2 = tok.find(".", tok.find(".") + 1)
    tok = tok[:d2 + 44] if d2 != -1 else tok
    region = None
    try:
        pp = tok.split(".")[1]; pp += "=" * (-len(pp) % 4)
        claims = json.loads(base64.urlsafe_b64decode(pp))
        if claims.get("account_id") and str(claims["account_id"]) != acc:
            return "UID_NO_COINCIDE", tok, None
        region = claims.get("region") or claims.get("lock_region")
    except Exception:
        pass
    if not region:
        for m in (b"\x22\x02", b"\x1a\x02"):
            i = txt.encode("latin1", "ignore").find(m)
            if i != -1:
                cand = txt.encode("latin1", "ignore")[i+2:i+4].decode("latin1", "ignore")
                if cand.isalpha() and cand.isupper(): region = cand; break
    return "VIVA", tok, region

def main():
    open(ALIVE, "w").close(); open(DEAD, "w").close()
    lines = [l.strip() for l in open(IN) if l.strip()]
    ok = 0
    for n, line in enumerate(lines, 1):
        parts = line.split("|")
        if len(parts) != 4:
            print(f"[{n:02d}] formato raro: {line}"); continue
        uid, pw, name, acc = parts
        st, tok, region = check(uid, pw, name, acc)
        if st == "VIVA":
            ok += 1
            print(f"[{n:02d}] VIVA  {acc} {name} region={region}")
            with open(ALIVE, "a") as f: f.write(f"{acc}|{uid}|{pw}|{name}|{region}|{tok}\n")
        else:
            print(f"[{n:02d}] {st}  {acc} {name}")
            with open(DEAD, "a") as f: f.write(f"{acc}|{uid}|{name}|{st}\n")
        time.sleep(0.8)
    print(f"\nvivas={ok} muertas={len(lines)-ok} de {len(lines)}")
    print("alive.txt = cuentas usables | dead.txt = descartes")

if __name__ == "__main__":
    main()
