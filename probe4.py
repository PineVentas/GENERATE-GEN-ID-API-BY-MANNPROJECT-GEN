import json, hmac, hashlib, random, base64, codecs, requests, urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
urllib3.disable_warnings()

KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")
SECRET = KEY.decode()
REGION = "US"
LANG = "en"
UA = "GarenaMSDK/4.0.42(SM-A525F;Android 12;en;US;)"

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

AK = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
IV = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

def enc(hexd):
    return AES.new(AK, AES.MODE_CBC, IV).encrypt(pad(bytes.fromhex(hexd), AES.block_size)).hex()

def varint(n):
    out = []
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def fld(k, v):
    if isinstance(v, int):
        return varint((k << 3) | 0) + varint(v)
    b = v.encode() if isinstance(v, str) else v
    return varint((k << 3) | 2) + varint(len(b)) + b

def proto(d):
    return b"".join(fld(k, v) for k, v in d.items())

def f14(s):
    ks = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
    return bytes(ord(c) ^ ks[i % len(ks)] for i, c in enumerate(s))

IP = "45.112.9.80"
def H(**kw):
    h = {"User-Agent": UA, "Accept": "application/json"}
    for k in ("X-Forwarded-For","X-Real-IP","X-Client-IP","CF-Connecting-IP","True-Client-IP"):
        h[k] = IP
    h.update(kw)
    return h

# ---- 1. REGISTER ----
pw = f"Pass_{random.randrange(16**8):08X}"
body = json.dumps({"app_id":100067,"client_type":2,"password":pw,"source":2}, separators=(",",":"))
sig = hmac.new(KEY, body.encode(), hashlib.sha256).hexdigest()
r = requests.post("https://100067.connect.garena.com/api/v2/oauth/guest:register",
                  headers=H(**{"Content-Type":"application/json; charset=utf-8","Authorization":f"Signature {sig}"}),
                  data=body, timeout=15, verify=False)
print(f"[1 REGISTER] {r.status_code} :: {r.text[:200]}")
if r.status_code != 200: raise SystemExit("register fallo, para aqui")
uid = str(r.json()["data"]["uid"])
print(f"    uid={uid} pw={pw}")

# ---- 2. TOKEN ----
r = requests.post("https://100067.connect.garena.com/oauth/guest/token/grant",
                  headers=H(**{"Content-Type":"application/x-www-form-urlencoded"}),
                  data={"uid":uid,"password":pw,"response_type":"token","client_type":"2",
                        "client_secret":SECRET,"client_id":"100067"}, timeout=15, verify=False)
print(f"[2 TOKEN] {r.status_code} :: {r.text[:300]}")
if r.status_code != 200: raise SystemExit("token fallo, para aqui")
j = r.json()
open_id, at = j["open_id"], j["access_token"]
print(f"    open_id={open_id[:24]}... at_len={len(at)}")

# ---- 3. MAJOR REGISTER ----
name = "MANN" + "".join(random.choices("ABCDEF0123456789", k=6))
msg = {1:name,2:at,3:open_id,5:102000007,6:4,7:1,13:1,14:f14(open_id),15:LANG,16:2,20:"2.132.4",21:1,22:FIELD_22}
r = requests.post("https://loginbp.ppmainecoonghj.com/MajorRegister",
                  headers={"Host":"loginbp.ppmainecoonghj.com","User-Agent":"UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
                           "Accept":"*/*","Accept-Encoding":"deflate, gzip","Authorization":"Bearer","X-GA":"v1 1",
                           "ReleaseVersion":"OB55","Content-Type":"application/x-www-form-urlencoded","X-Unity-Version":"2018.4.12f1",
                           "X-Forwarded-For":IP},
                  data=bytes.fromhex(enc(proto(msg).hex())), timeout=15, verify=False)
print(f"[3 MAJORREGISTER] {r.status_code} len={len(r.content)} :: {r.text[:300]!r}")

# ---- 4. MAJOR LOGIN ----
lp = {3:"2026-11-08 00:00:00",4:b"free fire",5:1,7:"2.132.4",8:"Android OS 12 / API-31 (SP1A.210812.016)",9:b"Handheld",
      10:"Telkomsel",11:"WIFI",12:1280,13:720,14:b"240",15:"ARMv8 VFPv4 NEON VMH | 2200 | 8",16:6000,
      17:"Adreno (TM) 618",18:"Adreno (TM) 618|OpenGL ES 3.2",19:"Google|a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      20:IP,21:LANG,22:open_id,23:b"4",24:b"Handheld",25:"SM-A525F",26:LANG,29:at,30:1,
      41:"Telkomsel",42:"WIFI",57:b"1ac4b80ecf0478a44203bf8fac6120f5",60:30000,61:30000,62:2519,63:243,
      64:32357,65:34308,66:32357,67:34308,73:1,
      74:b"/data/app/~~iw-K-GR3srU7dLE-UxJ4bg==/com.dts.freefiremax-kbPhw3SUYautW0I_oayB_A==/lib/arm",76:2,
      77:b"428775ab8c8845bd341b5357ec61d15e|/data/app/~~iw-K-GR3srU7dLE-UxJ4bg==/com.dts.freefiremax-kbPhw3SUYautW0I_oayB_A==/base.apk",78:2,79:1,
      81:b"32",83:b"2019118525",85:3,86:b"OpenGLES3",87:4095,88:4,92:19788,93:b"android_max",
      94:b"KqsHT2gyPt7vUCc9SCjv2ioi3WEZSEL86ErvXB38suVVK/Z4IVt78ESl/r2S15C1pqu/j6ZmgFL7HbwoFiiVconX08ooKiisQffvEAPCo/C+Lahr",
      96:b'{"cur_rate":null,"support_etc2":true}',97:1,98:1,99:b"4",100:b"4",102:b"",104:77149,105:1,
      106:b"https://dl.cdn.freefiremobile.com/live/ABHotUpdates/|https://dl-core.cdn.freefiremobile.com/live/ABHotUpdates/|6b2078db9d22dd98f8e9386a39af8462",
      107:b"c8e41b7a93f02d56e1a94c7b8203f5d1"}
r = requests.post("https://loginbp.ppmainecoonghj.com/MajorLogin",
                  headers={"Host":"loginbp.ppmainecoonghj.com","User-Agent":"UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
                           "Accept":"*/*","Accept-Encoding":"deflate, gzip","Authorization":"Bearer","X-GA":"v1 1",
                           "X-Ga-Sv":"1789534056","ReleaseVersion":"OB55","Content-Type":"application/x-www-form-urlencoded",
                           "X-Unity-Version":"2018.4.12f1","X-Forwarded-For":IP},
                  data=bytes.fromhex(enc(proto(lp).hex())), timeout=15, verify=False)
print(f"[4 MAJORLOGIN] {r.status_code} len={len(r.content)}")
print(f"    jwt_present={'eyJ' in r.text}")
print(f"    head={r.text[:200]!r}")
print(f"\n### RESULTADO uid={uid} pw={pw} name={name} region={REGION}")
