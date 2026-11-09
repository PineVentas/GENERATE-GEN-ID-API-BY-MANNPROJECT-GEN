#!/usr/bin/env python3
"""Diagnostico de un solo intento, con log por paso. No crea nada si falla antes."""
import os, sys, socket, ssl, json, hmac, hashlib, random, base64, time
import requests, urllib3
import gen_us as g

urllib3.disable_warnings()
REGION = os.environ.get("REGION", "US")
HOST   = os.environ.get("HOST_US", "login.us.freefiremobile.com")
TIMEOUT = float(os.environ.get("T", "20"))

def log(*a): print(*a, flush=True)

def dns(h):
    try:
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo(h, 443)})
        log(f"DNS  {h}: OK {ips}")
        return True
    except Exception as e:
        log(f"DNS  {h}: FALLA {e}")
        return False

def tls(h):
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((h, 443), timeout=TIMEOUT) as s:
            with ctx.wrap_socket(s, server_hostname=h) as ss:
                log(f"TLS  {h}: OK {ss.version()}")
        return True
    except Exception as e:
        log(f"TLS  {h}: FALLA {type(e).__name__}: {e}")
        return False

def step(tag, url, **kw):
    t0 = time.time()
    try:
        kw.setdefault("timeout", TIMEOUT)
        r = requests.post(url, verify=False, proxies=g.PROXIES, **kw)
        dt = time.time() - t0
        log(f"{tag}: HTTP {r.status_code} en {dt:.1f}s | {r.text[:300]!r}")
        return r if r.status_code == 200 else None
    except Exception as e:
        log(f"{tag}: EXCEPCION {type(e).__name__}: {e} ({time.time()-t0:.1f}s)")
        return None

if not (dns("100067.connect.garena.com") and dns(HOST)):
    sys.exit(1)
if not tls(HOST):
    log("-> el host de login no completa TLS. Probá HOST_US=loginbp.ggblueshark.com")

ip = g.next_ip()
pw = "Pass_" + "".join(random.choices("0123456789ABCDEF", k=16))
body = json.dumps({"app_id": 100067, "client_type": 2, "password": pw, "source": 2}, separators=(",", ":"))
sig = hmac.new(g.KEY, body.encode(), hashlib.sha256).hexdigest()

r = step("1 register", "https://100067.connect.garena.com/api/v2/oauth/guest:register",
         headers=g.hdr(ip, **{"Content-Type": "application/json; charset=utf-8",
                              "Authorization": f"Signature {sig}"}), data=body)
if not r: sys.exit(1)
uid = str(r.json()["data"]["uid"])
log(f"uid={uid}")

r = step("2 token", "https://100067.connect.garena.com/oauth/guest/token/grant",
         headers=g.hdr(ip, **{"Content-Type": "application/x-www-form-urlencoded"}),
         data={"uid": uid, "password": pw, "response_type": "token", "client_type": "2",
               "client_secret": g.SECRET, "client_id": "100067"})
if not r: sys.exit(1)
j = r.json(); open_id, at = j["open_id"], j["access_token"]

hbase = {"Host": HOST, "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
         "Accept": "*/*", "X-GA": "v1 1", "X-Ga-Sv": "1789534056", "ReleaseVersion": "OB55",
         "Content-Type": "application/x-www-form-urlencoded", "X-Unity-Version": "2018.4.12f1",
         "X-Forwarded-For": ip}

step("3 ChooseRegion", f"https://{HOST}/ChooseRegion",
     headers={**hbase, "Authorization": f"Bearer {at}"},
     data=bytes.fromhex(g.enc(g.proto({1: REGION}).hex())))

name = g.PREFIX + g.rh(6).upper()
msg = {1: name, 2: at, 3: open_id, 5: 102000007, 6: 4, 7: 1, 13: 1, 14: g.f14(open_id),
       15: g.LANG, 16: 2, 20: "2.132.4", 21: 1, 22: g.FIELD_22}
msg[g.LOCK_FIELD] = REGION

r = step("4 MajorRegister", f"https://{HOST}/MajorRegister",
         headers={**hbase, "Authorization": "Bearer"},
         data=bytes.fromhex(g.enc(g.proto(msg).hex())))
if not r: sys.exit(1)

r = step("5 MajorLogin", f"https://{HOST}/MajorLogin",
         headers={**hbase, "Authorization": "Bearer"},
         data=bytes.fromhex(g.enc(g.proto({1: name, 22: open_id, 29: at, 21: g.LANG}).hex())))
if not r: sys.exit(1)
log("TODO OK hasta MajorLogin")
