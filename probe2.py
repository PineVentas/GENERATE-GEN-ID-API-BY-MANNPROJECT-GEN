import json, hmac, hashlib, uuid, requests, urllib3
urllib3.disable_warnings()

SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
KEY = SECRET.encode()
BASE = "https://100067.connect.garena.com"
UA = "GarenaMSDK/4.0.42(SM-A525F;Android 12;en;US;)"
PW = "Pass_ABC123"

PATHS = ["/oauth/guest/register",
         "/api/v2/oauth/guest/token:register",
         "/api/v2/oauth/guest:register"]

BODIES = {
    "base":     {"app_id": 100067, "client_type": 2, "password": PW, "source": 2},
    "secret":   {"app_id": 100067, "client_type": 2, "password": PW, "source": 2, "client_secret": SECRET},
    "cid":      {"app_id": 100067, "client_type": 2, "password": PW, "source": 2, "client_id": "100067", "client_secret": SECRET},
    "strid":    {"app_id": "100067", "client_type": "2", "password": PW, "source": "2"},
}
QUERIES = ["", "?app_id=100067"]
CTS = ["application/json; charset=utf-8", "application/x-www-form-urlencoded"]

hits = []

def run(path, q, body, ct, extra, label):
    j = json.dumps(body, separators=(",", ":"))
    sig = hmac.new(KEY, j.encode(), hashlib.sha256).hexdigest()
    h = {"User-Agent": UA, "Accept": "application/json", "Content-Type": ct}
    if extra == "reqid":
        h.update({"X-Request-Id": str(uuid.uuid4()), "X-App-Version": "2.132.4", "X-GA": "v1 1"})
    elif extra == "sig":
        h["Authorization"] = f"Signature {sig}"
    d = j if ct.startswith("application/json") else body
    try:
        r = requests.post(BASE + path + q, headers=h, data=d, timeout=15, verify=False)
        mark = " <<<" if r.status_code not in (400, 404, 405) else ""
        print(f"{r.status_code} {path}{q} {label} ct={'json' if 'json' in ct else 'form'} x={extra}{mark} :: {r.text[:110]}")
        if r.status_code not in (400, 404, 405):
            hits.append((path, q, label, ct, extra, r.status_code, r.text[:300]))
    except Exception as e:
        print(f"ERR {path}{q} {label} :: {e}")

for p in PATHS:
    for name, b in BODIES.items():
        for q in QUERIES:
            for ct in CTS:
                for x in ("none", "reqid", "sig"):
                    run(p, q, b, ct, x, name)

print("\n### HITS")
for h in hits:
    print(h)
if not hits:
    print("### nada fuera de 400/404/405")

# host alternativo para la ruta muerta
print("\n### hosts para /api/v2/oauth:register")
for host in ["https://connect.garena.com", "https://100067.msdk.garena.com",
             "https://ffmconnect.live.garena.com"]:
    j = json.dumps(BODIES["secret"], separators=(",", ":"))
    sig = hmac.new(KEY, j.encode(), hashlib.sha256).hexdigest()
    try:
        r = requests.post(host + "/api/v2/oauth:register",
                          headers={"User-Agent": UA, "Content-Type": "application/json",
                                   "Authorization": f"Signature {sig}"},
                          data=j, timeout=15, verify=False)
        print(f"{r.status_code} {host} :: {r.text[:110]}")
    except Exception as e:
        print(f"ERR {host} :: {e}")
