#!/usr/bin/env python3
"""Genera cuentas Free Fire region US. Salida: uid|pass|name|account_id (solo US, verificado por JWT).

Variables: COUNT, NAME_PREFIX, WORKERS, REGION, LOCK_FIELD, OUT_FILE,
           PROXY, HOST_US, TIMEOUT, RETRIES, MAX_ATTEMPTS, PROGRESS, PREFLIGHT, VERBOSE
"""
import os, sys, json, time, random, hmac, hashlib, base64, threading, socket, ssl
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import requests, urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

urllib3.disable_warnings()

def _bool(v):
    return str(v).strip().lower() not in ("", "0", "false", "no", "off", "none")

def log(*a): print(*a, flush=True)

COUNT   = int(os.environ.get("COUNT", "30"))
PREFIX  = os.environ.get("NAME_PREFIX", "PIP")
WORKERS = max(1, int(os.environ.get("WORKERS", "2")))

RETRIES      = max(0, int(os.environ.get("RETRIES", "3")))
TIMEOUT      = float(os.environ.get("TIMEOUT", "20"))
MAX_ATTEMPTS = int(os.environ.get("MAX_ATTEMPTS", str(max(COUNT * 5, 30))))
PROGRESS     = float(os.environ.get("PROGRESS", "30"))
PREFLIGHT    = _bool(os.environ.get("PREFLIGHT", "1"))
VERBOSE      = _bool(os.environ.get("VERBOSE", "0"))

REGION = os.environ.get("REGION", "US").upper()
if REGION not in ("US", "SAC", "BR"):
    log(f"REGION invalida: {REGION}"); sys.exit(2)
LANG = {"US": "en", "SAC": "es", "BR": "pt"}.get(REGION, "en")

OUT = os.environ.get("OUT_FILE", f"accounts_{REGION.lower()}.txt")

HOST_CANDIDATES = [os.environ.get("HOST_US"), "loginbp.ppmainecoonghj.com", "loginbp.ggblueshark.com"]
HOST_CANDIDATES = [h for h in HOST_CANDIDATES if h]
_HI, _HL = 0, threading.Lock()
HOST = HOST_CANDIDATES[0]

def rotate_host():
    global _HI, HOST
    with _HL:
        _HI += 1
        HOST = HOST_CANDIDATES[_HI % len(HOST_CANDIDATES)]
    log(f"[host] rotando a {HOST}")
    return HOST

LOCK_FIELD = int(os.environ.get("LOCK_FIELD", "4"))

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

def fld
