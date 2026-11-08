#!/usr/bin/env python3
"""Reintenta fijar region US en las cuentas desviadas y verifica el resultado."""
import json, sys, time, random, base64, os
import requests, urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

urllib3.disable_warnings()

IN  = os.environ.get("IN_FILE", "accounts.txt")
OUT = "region_report.txt"
HOST = "loginbp.ppmainecoonghj.com"
SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
UA = "GarenaMSDK/4.0.44(SM-G998B ;Android 9;en;US;app 1.132.1 2019121229;)"

# Solo rangos que si geolocalizan US: AWS us-east-1, T-Mobile, Google, Azure del runner.
US_PREFIX = ("54.208","3.80","172.58","8.8","34.192","57.151","4.154")
_i = 0
def next_ip():
    global _i
    p = US_PREFIX[_i % len(US_PREFIX)]; _i += 1
    return f"{p}.{random.randint(0,255)}.{random.randint(1,254)}"

AK = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
IV = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
def enc(h): return AES.new(AK, AES.MODE_CBC, IV).encrypt(pad(bytes.fromhex(h), 16)).hex()
def varint(n):
    o=[]
    while True:
        b=n&0x7F; n>>=7
        if n: b|=0x80
        o.append(b)
        if not n: break
    return bytes(o)
def fld(k,v):
    if isinstance(v,int): return varint((k<<3)|0)+varint(v)
    b=v.encode() if isinstance(v,str) else v
    return varint((k<<3)|2)+varint(len(b))+b
def proto(d): return b"".join(fld(k,v) for k,v in d.items())
def rh(n): return "".join(random.choices("0123456789abcdef", k=n))

def rvarint(b, off):
    v=0; s=0
    while off < len(b) and s <= 63:
        x=b[off]; off+=1; v |= (x&0x7F)<<s
        if not x&0x80: return v, off
        s+=7
    raise ValueError

def fields_of(b):
    out={}; off=0
    while off < len(b):
        tag, off = rvarint(b, off)
        fn, wt = tag>>3, tag&7
        if not fn: raise ValueError
        if wt==0: v, off = rvarint(b, off); out[fn]=v
        elif wt==2:
            ln, off = rvarint(b, off)
            if off+ln > len(b): raise ValueError
            out[fn]=b[off:off+ln]; off+=ln
        else: raise ValueError
    return out

def parse_regions(raw):
    """Devuelve (ipRegion, notiRegion, lockRegion) recorriendo el proto, no escaneando."""
    for off in range(min(64, len(raw))):
        try:
            f = fields_of(raw[off:])
        except Exception:
            continue
        def g(k):
            v = f.get(k)
            return v.decode("latin1","ignore") if isinstance(v, bytes) and 1 <= len(v) <= 3 else None
        if f.get(29) or f.get(22):
            return g(2), g(3), g(4)
    return None, None, None

def hdr(ip, **kw):
    h={"User-Agent":UA,"Accept":"*/*"}
    for k in ("X-Forwarded-For","X-Real-IP","X-Client-IP","CF-Connecting-IP","True-Client-IP"): h[k]=ip
    h.update(kw); return h

def post(url, ip, retries=3, **kw):
    for a in range(retries+1):
        try:
            kw.setdefault("timeout",20); kw["verify"]=False
            r = requests.post(url, **kw)
            if r.status_code in (429,500,502,503,504):
                time.sleep(1.5*(a+1)); ip=next_ip(); kw["headers"]=hdr(ip); continue
            return r
        except Exception:
            time.sleep(1.0*(a+1)); ip=next_ip(); kw["headers"]=hdr(ip)
    return None

def login(uid, pw):
    ip = next_ip()
    r = post("https://100067.connect.garena.com/oauth/guest/token/grant", ip,
             headers=hdr(ip, **{"Content-Type":"application/x-www-form-urlencoded"}),
             data={"uid":uid,"password":pw,"response_type":"token","client_type":"2",
                   "client_secret":SECRET,"client_id":"100067"})
    if not r or r.status_code != 200: return None, None, None
    j = r.json(); oid, at = j["open_id"], j["access_token"]
    lp = {3:time.strftime("%Y-%m-%d %H:%M:%S"),4:b"free fire",5:1,7:"2.132.4",
          8:"Android OS 12 / API-31 (SP1A.210812.016)",9:b"Handheld",10:"ATM Mobils",11:"WIFI",
          12:1280,13:720,14:b"240",15:"ARMv8 VFPv4 NEON VMH | 2200 | 8",16:6000,17:"Adreno (TM) 618",
          18:"Adreno (TM) 618|OpenGL ES 3.2",19:f"Google|{rh(8)}-{rh(4)}-{rh(4)}-{rh(4)}-{rh(12)}",
          20:ip,21:"en",22:oid,23:b"4",24:b"Handheld",25:"SM-A525F",26:"en",29:at,30:1,
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
    if not r or r.status_code != 200: return None, None, None
    raw = r.content
    if b"eyJ" not in raw: return None, None, None
    t = raw[raw.find(b"eyJ"):].decode("latin1")
    d2 = t.find(".", t.find(".")+1); tok = t[:d2+44] if d2 != -1 else t
    return tok, raw, parse_regions(raw)

def choose(region, tok):
    ip = next_ip()
    return post(f"https://{HOST}/ChooseRegion", ip,
                headers=hdr(ip, **{"Host":HOST,"Authorization":f"Bearer {tok}","X-GA":"v1 1",
                                   "X-Ga-Sv":"1789534056","ReleaseVersion":"OB55",
                                   "Content-Type":"application/x-www-form-urlencoded",
                                   "X-Unity-Version":"2018.4.12f1"}),
                data=bytes.fromhex(enc(proto({1:region}).hex())), retries=1)

def main():
    open(OUT,"w").close()
    lines=[l.strip() for l in open(IN) if l.strip()]
    for n,line in enumerate(lines,1):
        p=line.split("|")
        if len(p)!=4: continue
        uid,pw,name,acc=p
        tok, raw, before = login(uid,pw)
        if not tok:
            print(f"[{n:02d}] {acc} login FALLO"); continue
        lock_b = before[2] or "?"
        if lock_b in ("US","NA"):
            print(f"[{n:02d}] {acc} ya en {lock_b}, no toco")
            open(OUT,"a").write(f"{acc}|{lock_b}|OK\n"); time.sleep(0.7); continue
        r = choose("US", tok)
        st = getattr(r,"status_code","ERR")
        tok2, raw2, after = login(uid,pw)
        lock_a = (after[2] if after else None) or "?"
        print(f"[{n:02d}] {acc} {lock_b} -> ChooseRegion {st} -> {lock_a}")
        open(OUT,"a").write(f"{acc}|{lock_b}|{st}|{lock_a}\n")
        time.sleep(1.0)

if __name__ == "__main__":
    main()
