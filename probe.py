import json, hmac, hashlib, requests, urllib3
urllib3.disable_warnings()

KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")
BASE = "https://100067.connect.garena.com"
UA = "GarenaMSDK/4.0.42(SM-A525F;Android 12;en;US;)"

PATHS = [
    "/api/v2/oauth:register",
    "/api/v2/oauth/guest/token:register",
    "/api/v2/oauth/guest/token:grant",
    "/oauth/guest/register",
    "/oauth/guest/token/grant",
    "/oauth/token/inspect?token=x",
]

def hdr(spoof, ip, auth=None, ctype=None):
    h = {"User-Agent": UA, "Accept": "application/json", "Connection": "Keep-Alive"}
    if spoof:
        for k in ("X-Forwarded-For", "X-Real-IP", "X-Client-IP",
                  "CF-Connecting-IP", "True-Client-IP"):
            h[k] = ip
        h["Forwarded"] = f"for={ip}"
    if auth: h["Authorization"] = f"Signature {auth}"
    if ctype: h["Content-Type"] = ctype
    return h

def show(tag, r):
    print(f"{tag} -> {r.status_code} len={len(r.text)} "
          f"server={r.headers.get('server')} ray={r.headers.get('cf-ray')} "
          f"trace={r.headers.get('x-trace-id')}")
    print(f"   body: {r.text[:200]!r}")

# 0. control de conectividad
try:
    r = requests.get(BASE + "/", headers={"User-Agent": UA}, timeout=15, verify=False)
    show("CONTROL GET /", r)
except Exception as e:
    print("CONTROL GET / -> ERR", e)

# 1. mapa de rutas: 405 = existe, 404 = muerta
live = []
for p in PATHS:
    try:
        r = requests.get(BASE + p, headers=hdr(False, None), timeout=15, verify=False)
        show(f"GET {p}", r)
        if r.status_code != 404: live.append(p)
    except Exception as e:
        print(f"GET {p} -> ERR {e}")

print(f"\n### RUTAS VIVAS: {live}\n")
if not live:
    print("### Ninguna ruta responde. Host o app_id muerto.")
    raise SystemExit(0)

# 2. matriz: encoding x firma x IP falsa
body = {"app_id": 100067, "client_type": 2, "password": "Pass_ABC123", "source": 2}
j = json.dumps(body, separators=(",", ":"))
sig = hmac.new(KEY, j.encode(), hashlib.sha256).hexdigest()
IP = "45.112.9.80"

for p in live:
    for enc in ("json", "form"):
        for auth in (True, False):
            for spoof in (False, True):
                h = hdr(spoof, IP, sig if auth else None,
                        "application/json; charset=utf-8" if enc == "json" else
                        "application/x-www-form-urlencoded")
                d = j if enc == "json" else body
                try:
                    r = requests.post(BASE + p, headers=h, data=d, timeout=15, verify=False)
                    show(f"POST {p} {enc} auth={auth} spoof={spoof}", r)
                except Exception as e:
                    print(f"POST {p} {enc} auth={auth} spoof={spoof} -> ERR {e}")
